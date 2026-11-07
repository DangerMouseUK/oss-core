//! Round-trip every game packet through its dispatch enum, and check that no
//! decoder panics on arbitrary input.

use oss_proto::c2s::{self, C2SPacket};
use oss_proto::common::{
    Brick, DamageData, LargeBatchedPosition, ObjectChange, ObjectToggle, PackedMotion, PlayerData,
    SmallBatchedPosition,
};
use oss_proto::s2c::{self, S2CPacket};
use oss_proto::wire::Raw;
use oss_proto::{
    C2SPosition, ClientSettings, CorePacket, ExtraPositionData, FixedStr, ObjectData, PositionTail,
    S2CPosition, S2CWeapon, WeaponInfo,
};

fn player(pid: i16) -> PlayerData {
    PlayerData {
        ship: 3,
        accept_audio: 1,
        name: "Pilot".into(),
        squad: "Squad".into(),
        kill_points: 1000,
        flag_points: -5,
        pid,
        freq: 1,
        wins: 2,
        losses: 3,
        attached_to: -1,
        flags_carried: 0,
        misc_bits: 1,
    }
}

fn damage() -> DamageData {
    DamageData {
        attacker: 4,
        weapon: WeaponInfo(0x1234),
        energy: 900,
        damage: 300,
        time_offset: 7,
    }
}

fn chat(kind: u8) -> s2c::ChatBody {
    s2c::ChatBody {
        kind,
        sound: 0,
        pid: 12,
        text: b"hello world".to_vec(),
    }
}

fn s2c_samples() -> Vec<S2CPacket> {
    let mut settings = ClientSettings::default();
    settings.ships[1].set_maximum_speed(4000);
    vec![
        s2c::PlayerId {
            pid: 5,
            extra: None,
        }
        .into(),
        s2c::PlayerId {
            pid: 5,
            extra: Some(1),
        }
        .into(),
        s2c::EnteringArena {}.into(),
        s2c::PlayerEntering {
            players: vec![player(1)],
        }
        .into(),
        s2c::PlayerEntering {
            players: vec![player(1), player(2), player(3)],
        }
        .into(),
        s2c::PlayerLeaving { pid: 9 }.into(),
        S2CWeapon {
            player_id: 3,
            weapon: WeaponInfo(5),
            tail: PositionTail::Energy(1),
            ..Default::default()
        }
        .into(),
        s2c::Kill {
            green: 2,
            killer: 1,
            killed: 2,
            bounty: 30,
            flags: 0,
        }
        .into(),
        S2CPacket::Chat(s2c::S2CChat(chat(2))),
        s2c::Green {
            time: 1,
            x: 2,
            y: 3,
            prize: 4,
            pid: 5,
        }
        .into(),
        s2c::ScoreUpdate {
            pid: 1,
            kill_points: 2,
            flag_points: 3,
            kills: 4,
            deaths: 5,
        }
        .into(),
        s2c::LoginResponse {
            code: 0,
            server_version: 134,
            exe_checksum: 0xF142_9CE8,
            news_checksum: 7,
            ..Default::default()
        }
        .into(),
        s2c::SoccerGoal {
            freq: 1,
            points: 1000,
        }
        .into(),
        s2c::S2CVoice {
            pid: 1,
            data: vec![1, 2, 3],
        }
        .into(),
        s2c::FreqChange {
            pid: 1,
            freq: 2,
            ship: 0xFF,
        }
        .into(),
        s2c::Turret { pid: 1, host: -1 }.into(),
        settings.into(),
        s2c::IncomingFile {
            name: FixedStr::default(),
            data: vec![0x78, 0x9C],
        }
        .into(),
        s2c::FlagLocation {
            flag_id: 1,
            x: 512,
            y: 512,
            freq: 0xFFFF,
        }
        .into(),
        s2c::FlagPickup { flag_id: 1, pid: 2 }.into(),
        s2c::FlagVictory {
            freq: 1,
            points: 5000,
        }
        .into(),
        s2c::TurretKickoff { pid: 3 }.into(),
        s2c::FlagDrop { pid: 3 }.into(),
        s2c::Security {
            green_seed: 1,
            door_seed: 2,
            timestamp: 3,
            key: 4,
        }
        .into(),
        s2c::RequestFile {
            local_path: "C:\\x".into(),
            name: "f.txt".into(),
        }
        .into(),
        s2c::ScoreReset { pid: -1 }.into(),
        s2c::ShipReset {}.into(),
        s2c::SpecData::ExtraData(1).into(),
        s2c::SpecData::Player(77).into(),
        s2c::ShipChange {
            ship: 8,
            pid: 1,
            freq: 9999,
        }
        .into(),
        s2c::BannerToggle { toggle: 1 }.into(),
        s2c::Banner {
            pid: 1,
            banner: Raw([7; 96]),
        }
        .into(),
        s2c::PrizeReceive {
            count: 1,
            prize: 13,
        }
        .into(),
        s2c::Bricks { bricks: vec![] }.into(),
        s2c::Bricks {
            bricks: vec![
                Brick {
                    x1: 1,
                    y1: 2,
                    x2: 3,
                    y2: 4,
                    freq: 5,
                    brick_id: 6,
                    start_time: 7
                };
                2
            ],
        }
        .into(),
        s2c::TurfFlags {
            owners: vec![-1, 0, 1],
        }
        .into(),
        s2c::PeriodicReward {
            rewards: vec![s2c::Reward {
                freq: 1,
                points: 100,
            }],
        }
        .into(),
        s2c::SpeedStats {
            personal_best: 1,
            rank: 2,
            score: 3,
            top_scores: [1, 2, 3, 4, 5],
            top_pids: [1, 2, -1, -1, -1],
        }
        .into(),
        s2c::Ufo { allowed: 1 }.into(),
        s2c::KeepAlive {}.into(),
        S2CPosition {
            player_id: 9,
            tail: PositionTail::Extra(ExtraPositionData::default()),
            ..Default::default()
        }
        .into(),
        s2c::MapFilename::Single {
            name: "map.lvl".into(),
            checksum: 0x1234,
        }
        .into(),
        s2c::MapFilename::Files(vec![
            s2c::MapFile {
                name: "map.lvl".into(),
                checksum: 1,
                size: 100,
            },
            s2c::MapFile {
                name: "gfx.lvz".into(),
                checksum: 2,
                size: 200,
            },
        ])
        .into(),
        s2c::MapData {
            name: "map.lvl".into(),
            data: vec![1; 50],
        }
        .into(),
        s2c::SetKothTimer { time: 6000 }.into(),
        s2c::Koth {
            action: 1,
            time: 6000,
            pid: -1,
        }
        .into(),
        s2c::AddKothTime { time: 100 }.into(),
        s2c::BallPosition {
            ball_id: 0,
            x: 1,
            y: 2,
            x_speed: 3,
            y_speed: 4,
            pid: -1,
            time: 5,
        }
        .into(),
        s2c::ArenaList {
            arenas: vec![
                s2c::ArenaEntry {
                    name: b"0".to_vec(),
                    population: -5,
                },
                s2c::ArenaEntry {
                    name: b"duel".to_vec(),
                    population: 2,
                },
            ],
        }
        .into(),
        s2c::AdBanner {
            mode: 1,
            width: 2,
            height: 3,
            duration: 4,
            data: vec![5],
        }
        .into(),
        s2c::LoginOk {}.into(),
        s2c::WarpTo { x: 512, y: 600 }.into(),
        s2c::LoginText {
            text: b"Go away".to_vec(),
        }
        .into(),
        s2c::ContVersion {
            version: 40,
            checksum: 0xC9B6_1486,
        }
        .into(),
        s2c::ToggleObjects {
            toggles: vec![ObjectToggle::new(1, true), ObjectToggle::new(2, false)],
        }
        .into(),
        s2c::MoveObjects {
            changes: vec![ObjectChange {
                mask: 0x1F,
                data: ObjectData::map(5, 100, 200),
            }],
        }
        .into(),
        s2c::ToggleDamage { on: 1 }.into(),
        s2c::S2CDamage {
            pid: 1,
            time: 2,
            entries: vec![damage(), damage()],
        }
        .into(),
        s2c::BatchedSmallPositions {
            entries: vec![SmallBatchedPosition {
                pid: 1,
                motion: PackedMotion {
                    rotation: 10,
                    time: 1000,
                    x: 8000,
                    y: 9000,
                    x_speed: -500,
                    y_speed: 700,
                },
            }],
        }
        .into(),
        s2c::BatchedLargePositions {
            entries: vec![LargeBatchedPosition {
                pid: 700,
                status: 0x21,
                motion: PackedMotion {
                    rotation: 10,
                    time: 1000,
                    x: 8000,
                    y: 9000,
                    x_speed: 500,
                    y_speed: -700,
                },
            }],
        }
        .into(),
        s2c::Redirect {
            ip: [127, 0, 0, 1],
            port: 5000,
            arena_type: -3,
            arena: "duel".into(),
            login_id: 0,
        }
        .into(),
        s2c::SelectBox {
            title: b"Pick".to_vec(),
            items: vec![s2c::SelectItem {
                value: 1,
                text: b"One".to_vec(),
            }],
        }
        .into(),
        S2CPacket::Unknown {
            kind: 0x11,
            data: vec![0x11, 1, 2],
        },
    ]
}

fn c2s_samples() -> Vec<C2SPacket> {
    let login = c2s::Login {
        name: "Pilot".into(),
        password: "pw".into(),
        machine_id: 42,
        ..Default::default()
    };
    vec![
        c2s::GoArena {
            ship: 8,
            allow_audio: 1,
            x_res: 1024,
            y_res: 768,
            arena_type: -3,
            arena: "duel".into(),
            ..Default::default()
        }
        .into(),
        c2s::GoArena {
            arena_type: -1,
            optional_graphics: Some(1),
            ..Default::default()
        }
        .into(),
        c2s::LeaveArena {}.into(),
        C2SPosition {
            x: 1,
            y: 2,
            energy: 3,
            ..Default::default()
        }
        .into(),
        C2SPosition {
            extra: Some(ExtraPositionData {
                energy: 5,
                ..Default::default()
            }),
            ..Default::default()
        }
        .into(),
        c2s::Death {
            killer: 4,
            bounty: 10,
        }
        .into(),
        C2SPacket::Chat(c2s::C2SChat(chat(5))),
        c2s::TakeGreen {
            time: 1,
            x: 2,
            y: 3,
            prize: 4,
        }
        .into(),
        c2s::SpecRequest { pid: -1 }.into(),
        login.clone().into(),
        c2s::ContLogin(c2s::Login {
            kind: c2s::kind::CONT_LOGIN,
            client_version: 40,
            cont_id: Some([9; 64]),
            ..login
        })
        .into(),
        c2s::Rebroadcast {
            target: -1,
            packet: vec![0x35, 1, 0],
        }
        .into(),
        c2s::UpdateRequest {}.into(),
        c2s::MapRequest { index: None }.into(),
        c2s::MapRequest { index: Some(3) }.into(),
        c2s::NewsRequest {}.into(),
        c2s::C2SVoice {
            slot: 1,
            target: 2,
            data: vec![3],
        }
        .into(),
        c2s::SetFreq { freq: 5 }.into(),
        c2s::AttachTo { pid: -1 }.into(),
        c2s::PickupFlag { flag_id: 2 }.into(),
        c2s::TurretKickoff {}.into(),
        c2s::DropFlags {}.into(),
        c2s::UploadFile {
            name: "x".into(),
            data: vec![1, 2],
        }
        .into(),
        c2s::Registration {
            real_name: "A".into(),
            email: "a@b".into(),
            age: 30,
            processor: 586,
            ..Default::default()
        }
        .into(),
        c2s::SetShip { ship: 2 }.into(),
        c2s::SetBanner {
            banner: Raw([1; 96]),
        }
        .into(),
        c2s::SecurityResponse {
            weapon_count: 1,
            settings_checksum: 2,
            exe_checksum: 3,
            map_checksum: 4,
            ping_high: 9,
            ..Default::default()
        }
        .into(),
        c2s::SecurityResponse {
            continuum: Some((-2, 0xDEAD_BEEF)),
            ..Default::default()
        }
        .into(),
        c2s::SecurityViolation {
            code: 0x3D,
            text: b"custom".to_vec(),
        }
        .into(),
        c2s::DropBrick { x: 1, y: 2 }.into(),
        c2s::SettingChange {
            entries: vec![b"Misc:Foo:1".to_vec(), b"__pragma:flush:1".to_vec()],
        }
        .into(),
        c2s::KothExpired {}.into(),
        c2s::ShootBall {
            ball_id: 1,
            x: 2,
            y: 3,
            x_speed: 4,
            y_speed: 5,
            pid: 6,
            time: 7,
        }
        .into(),
        c2s::PickupBall {
            ball_id: 1,
            time: 2,
        }
        .into(),
        c2s::Goal {
            ball_id: 1,
            x: 2,
            y: 3,
        }
        .into(),
        c2s::C2SDamage {
            time: 1,
            entries: vec![damage()],
        }
        .into(),
        C2SPacket::Unknown {
            kind: 0x22,
            data: vec![0x22],
        },
    ]
}

#[test]
fn every_s2c_packet_round_trips() {
    let samples = s2c_samples();
    // One sample (or more) for every variant: count distinct type bytes.
    let mut kinds: Vec<u8> = samples.iter().map(S2CPacket::kind).collect();
    kinds.sort();
    kinds.dedup();
    assert_eq!(kinds.len(), 58, "{kinds:02x?}");
    for p in samples {
        // Position packets carry a computed checksum: take it from the encoding.
        let p = match p {
            S2CPacket::Weapon(_) => S2CPacket::decode(&p.to_bytes()).unwrap(),
            p => p,
        };
        let b = p.to_bytes();
        let back = S2CPacket::decode(&b).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        assert_eq!(back, p, "{b:02x?}");
        assert_eq!(back.to_bytes(), b);
    }
}

#[test]
fn every_c2s_packet_round_trips() {
    let samples = c2s_samples();
    let mut kinds: Vec<u8> = samples.iter().map(C2SPacket::kind).collect();
    kinds.sort();
    kinds.dedup();
    assert_eq!(kinds.len(), 33, "{kinds:02x?}");
    for p in samples {
        let p = match p {
            C2SPacket::Position(_) => C2SPacket::decode(&p.to_bytes()).unwrap(),
            p => p,
        };
        let b = p.to_bytes();
        let back = C2SPacket::decode(&b).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        assert_eq!(back, p, "{b:02x?}");
        assert_eq!(back.to_bytes(), b);
    }
}

#[test]
fn documented_lengths() {
    use oss_proto::Packet;
    let len = |p: &S2CPacket| p.to_bytes().len();
    assert_eq!(len(&s2c::LoginResponse::default().into()), 36);
    assert_eq!(len(&s2c::Security::default().into()), 17);
    assert_eq!(len(&s2c::RequestFile::default().into()), 273);
    assert_eq!(len(&s2c::SpeedStats::default().into()), 38);
    assert_eq!(len(&s2c::Redirect::default().into()), 29);
    assert_eq!(len(&s2c::Banner::default().into()), 99);
    assert_eq!(len(&s2c::Koth::default().into()), 8);
    assert_eq!(
        len(&s2c::PlayerEntering {
            players: vec![player(1)]
        }
        .into()),
        64
    );
    assert_eq!(c2s::Login::default().to_bytes().len(), 101);
    assert_eq!(
        c2s::ContLogin(c2s::Login {
            cont_id: Some([0; 64]),
            ..Default::default()
        })
        .to_bytes()
        .len(),
        165
    );
    assert_eq!(c2s::Registration::default().to_bytes().len(), 766);
    assert_eq!(c2s::SecurityResponse::default().to_bytes().len(), 40);
    assert_eq!(c2s::GoArena::default().to_bytes().len(), 26);
    assert_eq!(c2s::ShootBall::default().to_bytes().len(), 16);
}

#[test]
fn length_dependent_forms() {
    // 0x29: 21 bytes is the single form; other lengths must be 1 + 24n.
    assert!(S2CPacket::decode(&[0x29; 22]).is_err());
    assert!(
        matches!(S2CPacket::decode(&[0x29; 25]).unwrap(), S2CPacket::MapFilename(s2c::MapFilename::Files(f)) if f.len() == 1)
    );
    // List packets reject partial entries.
    assert!(S2CPacket::decode(&[0x22, 1]).is_err());
    assert!(S2CPacket::decode(&[0x35]).is_err());
    // Concatenated player records must all be 0x03.
    let mut b = Vec::new();
    player(1).write(&mut b);
    player(2).write(&mut b);
    b[64] = 0x04;
    assert!(S2CPacket::decode(&b).is_err());
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn decoders_never_panic() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let mut buf = Vec::new();
    for i in 0..200_000u32 {
        let len = (rng.next() % 80) as usize + if i % 50 == 0 { 1400 } else { 0 };
        buf.clear();
        buf.extend((0..len).map(|_| rng.next() as u8));
        if !buf.is_empty() {
            buf[0] = (i % 0x40) as u8;
        }
        let _ = S2CPacket::decode(&buf);
        let _ = C2SPacket::decode(&buf);
        let _ = CorePacket::decode(&buf).map(|c| {
            if let CorePacket::Cluster(c) = c {
                c.iter().count()
            } else {
                0
            }
        });
        let _ = ClientSettings::decode(&buf);
    }
}
