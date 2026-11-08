//! Property tests: every packet survives encode → decode with arbitrary field
//! values.
//!
//! Fixed-layout packets get their generators from `fixed_packet!` and
//! `list_packet!` (every field arbitrary). The rest are generated here, with
//! only the constraints the wire format itself imposes:
//!
//! * NUL-terminated text never contains NUL;
//! * fields whose presence is signalled by the packet length (`Option`s) are
//!   generated both present and absent;
//! * position and weapon packets carry a computed checksum, so the generated
//!   value gets the checksum its encoder writes.
//!
//! Each dispatch enum's generator lists its variants in a macro that also
//! builds an exhaustive `match`, so adding a packet without a generator fails to
//! compile, and a coverage test checks that every variant is produced.

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
// `prop_oneof!` expands to `vec![...]`, which a `no_std` crate must import.
use alloc::vec;

use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

use crate::billing::{BillerLogin, BillerToServer, PlayerScore, ServerToBiller, UserLogin};
use crate::c2s::{self, *};
use crate::common::{DamageData, PlayerData};
use crate::control::{Cluster, CorePacket};
use crate::directory::{DirPing, DirPong, ZoneEntry, ZoneList, ZoneListRequest, ZoneUpdate};
use crate::position::{C2SPosition, ExtraPositionData, PositionTail, S2CPosition, S2CWeapon};
use crate::s2c::{self, *};
use crate::wire::{FixedStr, Packet, arb_wire};
use crate::{C2SPacket, ClientSettings, S2CPacket};

// ---- building blocks ----------------------------------------------------------

fn w<T: crate::wire::Wire + core::fmt::Debug>() -> impl Strategy<Value = T> {
    arb_wire::<T>()
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..max)
}

fn nonempty_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 1..max)
}

/// Text that is sent NUL-terminated.
fn cstr(max: usize) -> impl Strategy<Value = Vec<u8>> {
    vec(1u8..=255, 0..max)
}

fn fixed<const N: usize>() -> impl Strategy<Value = FixedStr<N>> {
    w::<FixedStr<N>>()
}

/// Asserts `decode(encode(p)) == p` for a [`Packet`].
fn check<P: Packet + PartialEq + core::fmt::Debug>(p: &P) -> Result<(), TestCaseError> {
    let b = p.to_bytes();
    prop_assert_eq!(b[0], P::TYPE);
    let back = P::decode(&b);
    prop_assert_eq!(back.as_ref(), Ok(p), "bytes {:02x?}", b);
    Ok(())
}

/// Runs `test` on `cases` values from `strategy`.
fn run<S: Strategy>(cases: u32, strategy: S, test: impl Fn(S::Value) -> Result<(), TestCaseError>)
where
    S::Value: core::fmt::Debug,
{
    let mut runner = TestRunner::new(Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    });
    if let Err(e) = runner.run(&strategy, test) {
        panic!("{e}");
    }
}

/// Builds the generator for a dispatch enum from `Variant => strategy` arms,
/// plus an exhaustive match proving every variant has an arm.
macro_rules! packet_union {
    ($enum:ident; $( $var:ident => $strat:expr ),* $(,)?) => {{
        #[allow(dead_code)]
        fn exhaustive(p: &$enum) {
            match p {
                $( $enum::$var(..) => {} )*
                $enum::Unknown { .. } => {}
            }
        }
        const COUNT: usize = [$( stringify!($var) ),*].len();
        (COUNT, prop_oneof![ $( ($strat).prop_map($enum::$var) ),* ].boxed())
    }};
}

// ---- shared structures ----------------------------------------------------------

fn player_data() -> impl Strategy<Value = PlayerData> {
    (
        (any::<i8>(), any::<u8>(), fixed::<20>(), fixed::<20>()),
        (any::<i32>(), any::<i32>(), any::<i16>(), any::<i16>()),
        (
            any::<i16>(),
            any::<i16>(),
            any::<i16>(),
            any::<i16>(),
            any::<u8>(),
        ),
    )
        .prop_map(
            |(
                (ship, accept_audio, name, squad),
                (kill_points, flag_points, pid, freq),
                (wins, losses, attached_to, flags_carried, misc_bits),
            )| PlayerData {
                ship,
                accept_audio,
                name,
                squad,
                kill_points,
                flag_points,
                pid,
                freq,
                wins,
                losses,
                attached_to,
                flags_carried,
                misc_bits,
            },
        )
}

fn chat_body() -> impl Strategy<Value = ChatBody> {
    (any::<u8>(), any::<u8>(), any::<i16>(), cstr(250)).prop_map(|(kind, sound, pid, text)| {
        ChatBody {
            kind,
            sound,
            pid,
            text,
        }
    })
}

fn position_tail() -> impl Strategy<Value = PositionTail> {
    prop_oneof![
        Just(PositionTail::None),
        any::<u16>().prop_map(PositionTail::Energy),
        w::<ExtraPositionData>().prop_map(PositionTail::Extra),
    ]
}

// ---- server to client -----------------------------------------------------------

fn s2c_position() -> impl Strategy<Value = S2CPosition> {
    (
        (any::<i8>(), any::<u16>(), any::<i16>(), any::<u8>()),
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<i16>()),
        (any::<i16>(), any::<i16>(), position_tail()),
    )
        .prop_map(
            |(
                (rotation, time, x, c2s_latency),
                (bounty, player_id, status, y_speed),
                (y, x_speed, tail),
            )| S2CPosition {
                rotation,
                time,
                x,
                c2s_latency,
                bounty,
                player_id,
                status,
                y_speed,
                y,
                x_speed,
                tail,
            },
        )
}

fn s2c_weapon() -> impl Strategy<Value = S2CWeapon> {
    (
        (any::<i8>(), any::<u16>(), any::<i16>(), any::<i16>()),
        (any::<u16>(), any::<i16>(), any::<u8>(), any::<u8>()),
        (any::<i16>(), any::<u16>(), w(), position_tail()),
    )
        .prop_map(
            |(
                (rotation, time, x, y_speed),
                (player_id, x_speed, status, c2s_latency),
                (y, bounty, weapon, tail),
            )| {
                let mut p = S2CWeapon {
                    rotation,
                    time,
                    x,
                    y_speed,
                    player_id,
                    x_speed,
                    checksum: 0,
                    status,
                    c2s_latency,
                    y,
                    bounty,
                    weapon,
                    tail,
                };
                p.checksum = p.to_bytes()[S2CWeapon::CHECKSUM_OFFSET];
                p
            },
        )
}

fn map_filename() -> impl Strategy<Value = MapFilename> {
    prop_oneof![
        (fixed::<16>(), any::<u32>())
            .prop_map(|(name, checksum)| MapFilename::Single { name, checksum }),
        vec(
            (fixed::<16>(), any::<u32>(), any::<u32>()).prop_map(|(name, checksum, size)| {
                s2c::MapFile {
                    name,
                    checksum,
                    size,
                }
            }),
            1..8
        )
        .prop_map(MapFilename::Files),
    ]
}

fn s2c_union() -> (usize, BoxedStrategy<S2CPacket>) {
    packet_union! { S2CPacket;
        PlayerId => (any::<i16>(), option::of(any::<u8>()))
            .prop_map(|(pid, extra)| PlayerId { pid, extra }),
        EnteringArena => EnteringArena::arb(),
        PlayerEntering => vec(player_data(), 1..5).prop_map(|players| PlayerEntering { players }),
        PlayerLeaving => PlayerLeaving::arb(),
        Weapon => s2c_weapon(),
        Kill => Kill::arb(),
        Chat => chat_body().prop_map(S2CChat),
        Green => Green::arb(),
        ScoreUpdate => ScoreUpdate::arb(),
        LoginResponse => LoginResponse::arb(),
        SoccerGoal => SoccerGoal::arb(),
        Voice => (any::<i16>(), bytes(200)).prop_map(|(pid, data)| S2CVoice { pid, data }),
        FreqChange => FreqChange::arb(),
        Turret => Turret::arb(),
        Settings => vec(any::<u8>(), crate::settings::SETTINGS_LEN - 1).prop_map(|mut b| {
            b.insert(0, s2c::kind::SETTINGS);
            Box::new(ClientSettings::decode(&b).unwrap())
        }),
        IncomingFile => (fixed::<16>(), bytes(300)).prop_map(|(name, data)| IncomingFile { name, data }),
        FlagLocation => FlagLocation::arb(),
        FlagPickup => FlagPickup::arb(),
        FlagVictory => FlagVictory::arb(),
        TurretKickoff => s2c::TurretKickoff::arb(),
        FlagDrop => FlagDrop::arb(),
        Security => Security::arb(),
        RequestFile => RequestFile::arb(),
        ScoreReset => ScoreReset::arb(),
        ShipReset => ShipReset::arb(),
        SpecData => prop_oneof![
            any::<u8>().prop_map(SpecData::ExtraData),
            any::<i16>().prop_map(SpecData::Player),
        ],
        ShipChange => ShipChange::arb(),
        BannerToggle => BannerToggle::arb(),
        Banner => Banner::arb(),
        PrizeReceive => PrizeReceive::arb(),
        Bricks => Bricks::arb(),
        TurfFlags => TurfFlags::arb(),
        PeriodicReward => PeriodicReward::arb(),
        SpeedStats => SpeedStats::arb(),
        Ufo => Ufo::arb(),
        KeepAlive => KeepAlive::arb(),
        Position => s2c_position(),
        MapFilename => map_filename(),
        MapData => (fixed::<16>(), bytes(300)).prop_map(|(name, data)| MapData { name, data }),
        SetKothTimer => SetKothTimer::arb(),
        Koth => Koth::arb(),
        AddKothTime => AddKothTime::arb(),
        Ball => BallPosition::arb(),
        ArenaList => vec(
            (cstr(16), any::<i16>()).prop_map(|(name, population)| ArenaEntry { name, population }),
            0..10
        )
        .prop_map(|arenas| ArenaList { arenas }),
        AdBanner => (any::<u8>(), any::<u16>(), any::<u16>(), any::<u32>(), bytes(200)).prop_map(
            |(mode, width, height, duration, data)| AdBanner {
                mode,
                width,
                height,
                duration,
                data,
            }
        ),
        LoginOk => LoginOk::arb(),
        WarpTo => WarpTo::arb(),
        LoginText => cstr(200).prop_map(|text| LoginText { text }),
        ContVersion => ContVersion::arb(),
        ToggleObjects => ToggleObjects::arb(),
        MoveObjects => MoveObjects::arb(),
        ToggleDamage => ToggleDamage::arb(),
        Damage => (any::<i16>(), any::<u32>(), vec(w::<DamageData>(), 0..10))
            .prop_map(|(pid, time, entries)| S2CDamage { pid, time, entries }),
        BatchedSmallPositions => BatchedSmallPositions::arb(),
        BatchedLargePositions => BatchedLargePositions::arb(),
        Redirect => Redirect::arb(),
        SelectBox => (
            cstr(64),
            vec(
                (any::<i16>(), cstr(127)).prop_map(|(value, text)| SelectItem { value, text }),
                0..8
            )
        )
            .prop_map(|(title, items)| SelectBox { title, items }),
    }
}

// ---- client to server -----------------------------------------------------------

fn c2s_position() -> impl Strategy<Value = C2SPosition> {
    (
        (any::<i8>(), any::<u32>(), any::<i16>(), any::<i16>()),
        (any::<u8>(), any::<i16>(), any::<i16>(), any::<u16>()),
        (any::<i16>(), w(), option::of(w::<ExtraPositionData>())),
    )
        .prop_map(
            |(
                (rotation, time, x_speed, y),
                (status, x, y_speed, bounty),
                (energy, weapon, extra),
            )| {
                let mut p = C2SPosition {
                    rotation,
                    time,
                    x_speed,
                    y,
                    checksum: 0,
                    status,
                    x,
                    y_speed,
                    bounty,
                    energy,
                    weapon,
                    extra,
                };
                p.checksum = p.to_bytes()[C2SPosition::CHECKSUM_OFFSET];
                p
            },
        )
}

fn login(continuum: bool) -> impl Strategy<Value = Login> {
    (
        (any::<u8>(), fixed::<32>(), fixed::<32>(), any::<u32>()),
        (any::<u8>(), any::<i16>(), any::<u16>(), any::<u16>()),
        (any::<i32>(), any::<i32>(), any::<u32>(), w::<[u8; 12]>()),
        w::<[u8; 64]>(),
    )
        .prop_map(
            move |(
                (flags, name, password, machine_id),
                (connect_type, timezone_bias, unknown1, client_version),
                (field444, field555, permission_id, reserved),
                cont,
            )| Login {
                kind: if continuum {
                    c2s::kind::CONT_LOGIN
                } else {
                    c2s::kind::LOGIN
                },
                flags,
                name,
                password,
                machine_id,
                connect_type,
                timezone_bias,
                unknown1,
                client_version,
                field444,
                field555,
                permission_id,
                reserved,
                cont_id: continuum.then_some(cont),
            },
        )
}

fn registration() -> impl Strategy<Value = Box<Registration>> {
    (
        (fixed::<32>(), fixed::<64>(), fixed::<32>(), fixed::<24>()),
        (
            any::<u8>(),
            any::<u8>(),
            any::<u8>(),
            any::<u8>(),
            any::<u8>(),
        ),
        (any::<u32>(), any::<u16>(), any::<u16>()),
        (fixed::<40>(), fixed::<40>(), w::<[FixedStr<40>; 13]>()),
    )
        .prop_map(
            |(
                (real_name, email, city, state),
                (sex, age, from_home, from_work, from_school),
                (processor, unknown1, unknown2),
                (win_owner, win_org, hardware),
            )| {
                Box::new(Registration {
                    real_name,
                    email,
                    city,
                    state,
                    sex,
                    age,
                    from_home,
                    from_work,
                    from_school,
                    processor,
                    unknown1,
                    unknown2,
                    win_owner,
                    win_org,
                    hardware,
                })
            },
        )
}

fn security_response() -> impl Strategy<Value = SecurityResponse> {
    (
        (any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>()),
        (any::<u32>(), any::<u32>(), any::<u16>(), any::<u16>()),
        (any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>()),
        (
            any::<u16>(),
            any::<u8>(),
            option::of((any::<i16>(), any::<u32>())),
        ),
    )
        .prop_map(
            |(
                (weapon_count, settings_checksum, exe_checksum, map_checksum),
                (s2c_slow_total, s2c_fast_total, s2c_slow_current, s2c_fast_current),
                (s2c_reliable_out, ping_last, ping_average, ping_low),
                (ping_high, slow_frame, continuum),
            )| SecurityResponse {
                weapon_count,
                settings_checksum,
                exe_checksum,
                map_checksum,
                s2c_slow_total,
                s2c_fast_total,
                s2c_slow_current,
                s2c_fast_current,
                s2c_reliable_out,
                ping_last,
                ping_average,
                ping_low,
                ping_high,
                slow_frame,
                continuum,
            },
        )
}

fn c2s_union() -> (usize, BoxedStrategy<C2SPacket>) {
    packet_union! { C2SPacket;
        GoArena => (
            (any::<u8>(), any::<i8>(), any::<i8>(), any::<i16>()),
            (any::<i16>(), any::<i16>(), fixed::<16>(), option::of(any::<u8>())),
        )
            .prop_map(
                |((ship, allow_audio, obscenity_filter, x_res), (y_res, arena_type, arena, optional_graphics))| {
                    GoArena {
                        ship,
                        allow_audio,
                        obscenity_filter,
                        x_res,
                        y_res,
                        arena_type,
                        arena,
                        optional_graphics,
                    }
                }
            ),
        LeaveArena => LeaveArena::arb(),
        Position => c2s_position(),
        Death => Death::arb(),
        Chat => chat_body().prop_map(C2SChat),
        TakeGreen => TakeGreen::arb(),
        SpecRequest => SpecRequest::arb(),
        Login => login(false),
        // Any payload, as the test that found the empty-payload asymmetry
        // used; only the constructible ones are packets.
        Rebroadcast => (any::<i16>(), bytes(200))
            .prop_filter_map("empty payload", |(target, packet)| Rebroadcast::new(target, packet)),
        UpdateRequest => UpdateRequest::arb(),
        MapRequest => option::of(any::<u16>()).prop_map(|index| MapRequest { index }),
        NewsRequest => NewsRequest::arb(),
        Voice => (any::<u8>(), any::<i16>(), bytes(200))
            .prop_map(|(slot, target, data)| C2SVoice { slot, target, data }),
        SetFreq => SetFreq::arb(),
        AttachTo => AttachTo::arb(),
        PickupFlag => PickupFlag::arb(),
        TurretKickoff => c2s::TurretKickoff::arb(),
        DropFlags => DropFlags::arb(),
        UploadFile => (fixed::<16>(), bytes(300)).prop_map(|(name, data)| UploadFile { name, data }),
        Registration => registration(),
        SetShip => SetShip::arb(),
        SetBanner => SetBanner::arb(),
        SecurityResponse => security_response(),
        SecurityViolation => (any::<u8>(), bytes(100))
            .prop_map(|(code, text)| SecurityViolation { code, text }),
        DropBrick => DropBrick::arb(),
        SettingChange => vec(vec(1u8..=255, 1..40), 0..8).prop_map(|entries| SettingChange { entries }),
        KothExpired => KothExpired::arb(),
        ShootBall => ShootBall::arb(),
        PickupBall => PickupBall::arb(),
        Goal => Goal::arb(),
        ContLogin => login(true).prop_map(ContLogin),
        Damage => (any::<u32>(), vec(w::<DamageData>(), 0..10))
            .prop_map(|(time, entries)| C2SDamage { time, entries }),
    }
}

// ---- tests ------------------------------------------------------------------------

#[test]
fn every_s2c_packet_round_trips() {
    let (_, s) = s2c_union();
    run(20_000, s, |p| {
        let b = p.to_bytes();
        prop_assert_eq!(S2CPacket::decode(&b), Ok(p), "bytes {:02x?}", b);
        Ok(())
    });
}

#[test]
fn every_c2s_packet_round_trips() {
    let (_, s) = c2s_union();
    run(20_000, s, |p| {
        let b = p.to_bytes();
        prop_assert_eq!(C2SPacket::decode(&b), Ok(p), "bytes {:02x?}", b);
        Ok(())
    });
}

/// The generators really produce every variant.
#[test]
fn generators_cover_every_variant() {
    fn kinds<T: core::fmt::Debug>(
        (count, s): (usize, BoxedStrategy<T>),
        kind: impl Fn(&T) -> u8,
    ) -> (usize, usize) {
        let mut runner = TestRunner::deterministic();
        let mut seen = BTreeSet::new();
        for _ in 0..20 * count {
            let v = s.new_tree(&mut runner).unwrap().current();
            seen.insert(kind(&v));
        }
        (count, seen.len())
    }
    let (want, got) = kinds(s2c_union(), S2CPacket::kind);
    assert_eq!(got, want, "S2C variants generated");
    let (want, got) = kinds(c2s_union(), C2SPacket::kind);
    assert_eq!(got, want, "C2S variants generated");
}

/// Typed packets also round-trip through their own `Packet` impls (not just the
/// dispatch enums), including the boxed ones.
#[test]
fn typed_packets_round_trip() {
    run(2_000, c2s_position(), |p| {
        prop_assert!(p.checksum_ok());
        check(&p)
    });
    run(2_000, s2c_weapon(), |p| {
        prop_assert!(p.checksum_ok());
        check(&p)
    });
    run(500, registration(), |p| check(&p));
    run(2_000, login(false), |p| check(&p));
    run(2_000, login(true).prop_map(ContLogin), |p| check(&p));
}

// ---- core transport packets -----------------------------------------------------

/// An owned description of a [`CorePacket`] (which borrows its payload).
#[derive(Debug, Clone)]
enum Core {
    Connect(u32, u16),
    ConnectResponse(u32, Option<u8>),
    Reliable(u32, Vec<u8>),
    Ack(u32),
    SyncRequest(u32, Option<(u32, u32)>),
    SyncResponse(u32, u32),
    Disconnect,
    ChunkBody(Vec<u8>),
    ChunkTail(Vec<u8>),
    Stream(u32, Vec<u8>),
    StreamCancel,
    StreamCancelAck,
    Cluster(Vec<u8>),
    Other(u8, Vec<u8>),
}

impl Core {
    fn packet(&self) -> CorePacket<'_> {
        match self {
            Self::Connect(key, protocol) => CorePacket::Connect {
                key: *key,
                protocol: *protocol,
            },
            Self::ConnectResponse(key, extra) => CorePacket::ConnectResponse {
                key: *key,
                extra: *extra,
            },
            Self::Reliable(seq, payload) => CorePacket::Reliable { seq: *seq, payload },
            Self::Ack(seq) => CorePacket::Ack { seq: *seq },
            Self::SyncRequest(time, counts) => CorePacket::SyncRequest {
                time: *time,
                counts: *counts,
            },
            Self::SyncResponse(client_time, server_time) => CorePacket::SyncResponse {
                client_time: *client_time,
                server_time: *server_time,
            },
            Self::Disconnect => CorePacket::Disconnect,
            Self::ChunkBody(d) => CorePacket::ChunkBody(d),
            Self::ChunkTail(d) => CorePacket::ChunkTail(d),
            Self::Stream(total, data) => CorePacket::Stream {
                total: *total,
                data,
            },
            Self::StreamCancel => CorePacket::StreamCancel,
            Self::StreamCancelAck => CorePacket::StreamCancelAck,
            Self::Cluster(d) => CorePacket::Cluster(Cluster(d)),
            Self::Other(subtype, body) => CorePacket::Other {
                subtype: *subtype,
                body,
            },
        }
    }
}

fn core() -> impl Strategy<Value = Core> {
    // Subtypes the decoder knows; `Other` uses the rest.
    let known: BTreeSet<u8> = (0x01..=0x0E).collect();
    prop_oneof![
        (any::<u32>(), any::<u16>()).prop_map(|(k, p)| Core::Connect(k, p)),
        (any::<u32>(), option::of(any::<u8>())).prop_map(|(k, e)| Core::ConnectResponse(k, e)),
        (any::<u32>(), nonempty_bytes(500)).prop_map(|(s, p)| Core::Reliable(s, p)),
        any::<u32>().prop_map(Core::Ack),
        (any::<u32>(), option::of((any::<u32>(), any::<u32>())))
            .prop_map(|(t, c)| Core::SyncRequest(t, c)),
        (any::<u32>(), any::<u32>()).prop_map(|(a, b)| Core::SyncResponse(a, b)),
        Just(Core::Disconnect),
        nonempty_bytes(500).prop_map(Core::ChunkBody),
        nonempty_bytes(500).prop_map(Core::ChunkTail),
        (any::<u32>(), nonempty_bytes(500)).prop_map(|(t, d)| Core::Stream(t, d)),
        Just(Core::StreamCancel),
        Just(Core::StreamCancelAck),
        vec(nonempty_bytes(60), 1..8).prop_map(|parts| {
            let mut b = Vec::new();
            for p in parts {
                b.push(p.len() as u8);
                b.extend(p);
            }
            Core::Cluster(b)
        }),
        (
            any::<u8>().prop_filter("unknown subtype", move |s| !known.contains(s)),
            bytes(100)
        )
            .prop_map(|(s, b)| Core::Other(s, b)),
    ]
}

#[test]
fn every_core_packet_round_trips() {
    run(20_000, core(), |c| {
        let p = c.packet();
        let b = p.to_bytes();
        prop_assert_eq!(CorePacket::decode(&b), Ok(p), "bytes {:02x?}", b);
        Ok(())
    });
}

// ---- billing and directory --------------------------------------------------------

fn score() -> impl Strategy<Value = PlayerScore> {
    w::<PlayerScore>()
}

fn user_login() -> impl Strategy<Value = UserLogin> {
    (
        (any::<u8>(), w::<[u8; 4]>(), fixed::<32>(), fixed::<32>()),
        (any::<u32>(), any::<u32>(), any::<i16>(), any::<u16>()),
        (any::<u8>(), any::<u8>(), any::<u16>(), bytes(100)),
    )
        .prop_map(
            |(
                (make_new, ip, name, password),
                (connection_id, machine_id, timezone, timezone_high),
                (unknown, sysop, client_version, extra),
            )| UserLogin {
                make_new,
                ip,
                name,
                password,
                connection_id,
                machine_id,
                timezone,
                timezone_high,
                unknown,
                sysop,
                client_version,
                extra,
            },
        )
}

fn biller_login() -> impl Strategy<Value = BillerLogin> {
    (
        (any::<u8>(), any::<u32>(), fixed::<24>(), fixed::<24>()),
        (w::<crate::wire::Raw<96>>(), any::<u32>(), w::<[u16; 6]>()),
        (
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
            option::of(score()),
        ),
    )
        .prop_map(
            |(
                (result, connection_id, name, squad),
                (banner, seconds_played, first_login),
                (unused0, user_id, unused1, score),
            )| BillerLogin {
                result,
                connection_id,
                name,
                squad,
                banner,
                seconds_played,
                first_login,
                unused0,
                user_id,
                unused1,
                score,
            },
        )
}

fn server_to_biller() -> impl Strategy<Value = ServerToBiller> {
    use ServerToBiller as S;
    let u = any::<u32>;
    prop_oneof![
        Just(S::Ping),
        (u(), u(), u(), fixed::<126>(), any::<u16>(), fixed::<32>()).prop_map(
            |(server_id, group_id, score_id, name, port, password)| S::ServerConnect {
                server_id,
                group_id,
                score_id,
                name,
                port,
                password,
            }
        ),
        Just(S::ServerDisconnect),
        user_login().prop_map(S::UserLogin),
        (
            (u(), any::<u16>(), any::<u16>(), any::<u16>()),
            (any::<u16>(), any::<u16>(), option::of(score()))
        )
            .prop_map(
                |((connection_id, reason, latency, ping), (loss_s2c, loss_c2s, score))| {
                    S::UserLogoff {
                        connection_id,
                        reason,
                        latency,
                        ping,
                        loss_s2c,
                        loss_c2s,
                        score,
                    }
                }
            ),
        (u(), u(), any::<u8>(), any::<u8>(), cstr(200)).prop_map(
            |(connection_id, server_id, kind, sound, text)| S::RemoteZoneMessage {
                connection_id,
                server_id,
                kind,
                sound,
                text,
            }
        ),
        (u(), u(), any::<u8>(), any::<u8>(), cstr(200)).prop_map(
            |(connection_id, group_id, kind, sound, text)| S::UserRemotePrivate {
                connection_id,
                group_id,
                kind,
                sound,
                text,
            }
        ),
        cstr(100).prop_map(|name| S::RequestFile { name }),
        (u(), bytes(300)).prop_map(|(connection_id, data)| S::UserDemographics {
            connection_id,
            data
        }),
        (u(), u(), cstr(200)).prop_map(|(source, destination, text)| S::UserPrivateChat {
            source,
            destination,
            text
        }),
        (u(), cstr(200)).prop_map(|(connection_id, text)| S::SecurityViolation {
            connection_id,
            text
        }),
        (u(), w::<crate::wire::Raw<96>>()).prop_map(|(connection_id, banner)| S::UserBanner {
            connection_id,
            banner
        }),
        (u(), score()).prop_map(|(connection_id, score)| S::UserScore {
            connection_id,
            score
        }),
        (u(), u(), any::<u8>(), any::<u8>(), cstr(200)).prop_map(
            |(connection_id, score_id, kind, sound, text)| S::UserScoreMessage {
                connection_id,
                score_id,
                kind,
                sound,
                text,
            }
        ),
        (u(), cstr(200)).prop_map(|(connection_id, text)| S::UserCommand {
            connection_id,
            text
        }),
        (u(), fixed::<32>(), cstr(200)).prop_map(|(connection_id, channel, text)| {
            S::UserChannelChat {
                connection_id,
                channel,
                text,
            }
        }),
        u().prop_map(|flags| S::ServerCapabilities { flags }),
    ]
}

fn biller_to_server() -> impl Strategy<Value = BillerToServer> {
    use BillerToServer as B;
    let u = any::<u32>;
    prop_oneof![
        biller_login().prop_map(B::UserLogin),
        Just(B::Shutdown),
        (u(), any::<u8>(), any::<u8>(), cstr(200)).prop_map(
            |(source_server, kind, sound, text)| B::ZoneMessage {
                source_server,
                kind,
                sound,
                text,
            }
        ),
        Just(B::Recycle),
        (fixed::<16>(), bytes(300)).prop_map(|(name, data)| B::FileTransfer { name, data }),
        (u(), any::<u16>()).prop_map(|(connection_id, reason)| B::Kick {
            connection_id,
            reason
        }),
        (u(), cstr(200)).prop_map(|(connection_id, text)| B::ArenaMessage {
            connection_id,
            text
        }),
        (u(), any::<u8>(), cstr(200)).prop_map(|(connection_id, channel, text)| {
            B::ChannelMessage {
                connection_id,
                channel,
                text,
            }
        }),
        (u(), u()).prop_map(|(score_id, score_id_neg)| B::ScoreReset {
            score_id,
            score_id_neg
        }),
        (u(), bytes(300)).prop_map(|(connection_id, data)| B::UserPacket {
            connection_id,
            data
        }),
        bytes(300).prop_map(B::Identity),
        (vec((u(), any::<u8>()), 1..10), cstr(200))
            .prop_map(|(recipients, text)| B::MultiChannelChat { recipients, text }),
    ]
}

#[test]
fn billing_packets_round_trip() {
    run(10_000, server_to_biller(), |p| {
        let b = p.to_bytes();
        prop_assert_eq!(ServerToBiller::decode(&b), Ok(p), "bytes {:02x?}", b);
        Ok(())
    });
    run(10_000, biller_to_server(), |p| {
        let b = p.to_bytes();
        prop_assert_eq!(BillerToServer::decode(&b), Ok(p), "bytes {:02x?}", b);
        Ok(())
    });
}

fn encode_with<T>(p: &T, f: impl Fn(&T, &mut Vec<u8>)) -> Vec<u8> {
    let mut v = Vec::new();
    f(p, &mut v);
    v
}

#[test]
fn directory_packets_round_trip() {
    let zone_update = (
        (any::<u32>(), any::<u16>(), any::<u16>(), any::<u16>()),
        (any::<u32>(), fixed::<32>(), fixed::<48>(), cstr(385)),
    )
        .prop_map(
            |((ip, port, players, score_keeping), (version, name, password, description))| {
                ZoneUpdate {
                    ip,
                    port,
                    players,
                    score_keeping,
                    version,
                    name,
                    password,
                    description,
                }
            },
        );
    run(5_000, zone_update, |p| {
        let b = encode_with(&p, ZoneUpdate::encode);
        prop_assert_eq!(ZoneUpdate::decode(&b), Ok(p));
        Ok(())
    });
    run(
        2_000,
        any::<u32>().prop_map(|value| DirPing { value }),
        |p| {
            let b = encode_with(&p, DirPing::encode);
            prop_assert_eq!(DirPing::decode(&b), Ok(p));
            Ok(())
        },
    );
    run(
        2_000,
        (any::<u32>(), any::<u32>()).prop_map(|(info, value)| DirPong { info, value }),
        |p| {
            let b = encode_with(&p, DirPong::encode);
            prop_assert_eq!(DirPong::decode(&b), Ok(p));
            Ok(())
        },
    );
    run(
        2_000,
        any::<u32>().prop_map(|min_players| ZoneListRequest { min_players }),
        |p| {
            let b = encode_with(&p, ZoneListRequest::encode);
            prop_assert_eq!(ZoneListRequest::decode(&b), Ok(p));
            Ok(())
        },
    );
    let entry = (
        (w::<[u8; 4]>(), any::<u16>(), any::<u16>(), any::<u8>()),
        (any::<u8>(), any::<u32>(), fixed::<64>(), cstr(200)),
    )
        .prop_map(
            |((ip, port, players, score_keeping), (hop_count, version, name, description))| {
                ZoneEntry {
                    ip,
                    port,
                    players,
                    score_keeping,
                    hop_count,
                    version,
                    name,
                    description,
                }
            },
        );
    run(
        2_000,
        vec(entry, 0..6).prop_map(|zones| ZoneList { zones }),
        |p| {
            let b = encode_with(&p, ZoneList::encode);
            prop_assert_eq!(ZoneList::decode(&b), Ok(p));
            Ok(())
        },
    );
}

/// An empty rebroadcast used to encode to 3 bytes that do not decode; now it
/// cannot be built, and the encoder and decoder agree on every value.
#[test]
fn rebroadcast_encoder_and_decoder_agree() {
    assert_eq!(Rebroadcast::new(-1, Vec::new()), None);
    assert!(C2SPacket::decode(&[c2s::kind::REBROADCAST, 0xFF, 0xFF]).is_err());
    run(5_000, (any::<i16>(), bytes(200)), |(target, packet)| {
        let raw = {
            let mut b = alloc::vec![c2s::kind::REBROADCAST];
            b.extend_from_slice(&target.to_le_bytes());
            b.extend_from_slice(&packet);
            b
        };
        match Rebroadcast::new(target, packet.clone()) {
            Some(p) => {
                prop_assert_eq!(p.to_bytes(), raw.clone());
                prop_assert_eq!(Rebroadcast::decode(&raw), Ok(p));
            }
            None => {
                prop_assert!(packet.is_empty());
                prop_assert!(Rebroadcast::decode(&raw).is_err());
            }
        }
        Ok(())
    });
}
