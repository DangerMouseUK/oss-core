//! Server-to-client game packets.
//!
//! Each packet type is a struct implementing [`Packet`]; [`S2CPacket`] decodes any
//! of them by type byte (and length where a type has several forms). Fixed-size
//! packets ignore trailing bytes when decoding.

use alloc::vec::Vec;

use crate::DecodeError;
use crate::common::{
    Brick, DamageData, LargeBatchedPosition, ObjectChange, ObjectToggle, PlayerData,
    SmallBatchedPosition, read_entries,
};
use crate::fixed_packet;
use crate::position::{S2CPosition, S2CWeapon};
use crate::settings::ClientSettings;
use crate::wire::{FixedStr, Packet, Raw, Reader, Wire, Writer, expect_type};

/// S2C type bytes.
pub mod kind {
    /// Your player id.
    pub const PLAYER_ID: u8 = 0x01;
    /// Arena entry complete.
    pub const ENTERING_ARENA: u8 = 0x02;
    /// Player(s) entering.
    pub const PLAYER_ENTERING: u8 = 0x03;
    /// Player leaving.
    pub const PLAYER_LEAVING: u8 = 0x04;
    /// Weapon / large position.
    pub const WEAPON: u8 = 0x05;
    /// Kill.
    pub const KILL: u8 = 0x06;
    /// Chat.
    pub const CHAT: u8 = 0x07;
    /// Prize picked up by someone.
    pub const GREEN: u8 = 0x08;
    /// Score update.
    pub const SCORE_UPDATE: u8 = 0x09;
    /// Login response.
    pub const LOGIN_RESPONSE: u8 = 0x0A;
    /// Soccer goal.
    pub const SOCCER_GOAL: u8 = 0x0B;
    /// Voice.
    pub const VOICE: u8 = 0x0C;
    /// Frequency change.
    pub const FREQ_CHANGE: u8 = 0x0D;
    /// Turret attach/detach.
    pub const TURRET: u8 = 0x0E;
    /// Arena settings.
    pub const SETTINGS: u8 = 0x0F;
    /// Incoming file.
    pub const INCOMING_FILE: u8 = 0x10;
    /// Flag location.
    pub const FLAG_LOCATION: u8 = 0x12;
    /// Flag pickup.
    pub const FLAG_PICKUP: u8 = 0x13;
    /// Flag game victory.
    pub const FLAG_VICTORY: u8 = 0x14;
    /// Turret kickoff.
    pub const TURRET_KICKOFF: u8 = 0x15;
    /// Flag drop.
    pub const FLAG_DROP: u8 = 0x16;
    /// Security seeds / checksum request.
    pub const SECURITY: u8 = 0x18;
    /// Request for a file upload.
    pub const REQUEST_FILE: u8 = 0x19;
    /// Score reset.
    pub const SCORE_RESET: u8 = 0x1A;
    /// Ship reset.
    pub const SHIP_RESET: u8 = 0x1B;
    /// Spectator data.
    pub const SPEC_DATA: u8 = 0x1C;
    /// Ship and frequency change.
    pub const SHIP_CHANGE: u8 = 0x1D;
    /// Banner toggle.
    pub const BANNER_TOGGLE: u8 = 0x1E;
    /// Player banner.
    pub const BANNER: u8 = 0x1F;
    /// Prize received.
    pub const PRIZE_RECEIVE: u8 = 0x20;
    /// Bricks.
    pub const BRICK: u8 = 0x21;
    /// Turf flag owners.
    pub const TURF_FLAGS: u8 = 0x22;
    /// Periodic reward.
    pub const PERIODIC_REWARD: u8 = 0x23;
    /// Speed game results.
    pub const SPEED_STATS: u8 = 0x24;
    /// UFO permission.
    pub const UFO: u8 = 0x25;
    /// Keep-alive.
    pub const KEEP_ALIVE: u8 = 0x27;
    /// Small position.
    pub const POSITION: u8 = 0x28;
    /// Map and LVZ file names.
    pub const MAP_FILENAME: u8 = 0x29;
    /// Map or LVZ file data.
    pub const MAP_DATA: u8 = 0x2A;
    /// Personal crown timer.
    pub const SET_KOTH_TIMER: u8 = 0x2B;
    /// Crown on/off.
    pub const KOTH: u8 = 0x2C;
    /// Add to crown timer.
    pub const ADD_KOTH_TIME: u8 = 0x2D;
    /// Ball position.
    pub const BALL: u8 = 0x2E;
    /// Arena list.
    pub const ARENA_LIST: u8 = 0x2F;
    /// Advertisement banner (obsolete).
    pub const AD_BANNER: u8 = 0x30;
    /// Login complete (obsolete).
    pub const LOGIN_OK: u8 = 0x31;
    /// Warp to a tile.
    pub const WARP_TO: u8 = 0x32;
    /// Custom login failure text.
    pub const LOGIN_TEXT: u8 = 0x33;
    /// Continuum version.
    pub const CONT_VERSION: u8 = 0x34;
    /// Toggle LVZ objects.
    pub const TOGGLE_OBJECTS: u8 = 0x35;
    /// Change LVZ objects.
    pub const MOVE_OBJECTS: u8 = 0x36;
    /// Toggle damage reports.
    pub const TOGGLE_DAMAGE: u8 = 0x37;
    /// Damage reports.
    pub const DAMAGE: u8 = 0x38;
    /// Batched small positions.
    pub const BATCHED_SMALL_POSITION: u8 = 0x39;
    /// Batched large positions.
    pub const BATCHED_LARGE_POSITION: u8 = 0x3A;
    /// Redirect to another zone/arena.
    pub const REDIRECT: u8 = 0x3B;
    /// Selection box.
    pub const SELECT_BOX: u8 = 0x3C;
}

fixed_packet! {
    /// S2C `0x02`: arena entry is complete.
    pub struct EnteringArena = kind::ENTERING_ARENA; {}
}
fixed_packet! {
    /// S2C `0x04`: a player left the arena.
    pub struct PlayerLeaving = kind::PLAYER_LEAVING; {
        /// Player id.
        pub pid: i16,
    }
}
fixed_packet! {
    /// S2C `0x06`: a kill.
    pub struct Kill = kind::KILL; {
        /// Prize left at the death spot (0 = none).
        pub green: u8,
        /// Killer.
        pub killer: i16,
        /// Player killed.
        pub killed: i16,
        /// Bounty of the killed player.
        pub bounty: i16,
        /// Flags transferred.
        pub flags: i16,
    }
}
fixed_packet! {
    /// S2C `0x08`: a player picked up a prize.
    pub struct Green = kind::GREEN; {
        /// Server time (ticks).
        pub time: u32,
        /// X tile.
        pub x: i16,
        /// Y tile.
        pub y: i16,
        /// Prize ([`crate::common::prize`]).
        pub prize: i16,
        /// Player.
        pub pid: i16,
    }
}
fixed_packet! {
    /// S2C `0x09`: a player's score.
    pub struct ScoreUpdate = kind::SCORE_UPDATE; {
        /// Player.
        pub pid: i16,
        /// Kill points.
        pub kill_points: i32,
        /// Flag points.
        pub flag_points: i32,
        /// Kills.
        pub kills: i16,
        /// Deaths.
        pub deaths: i16,
    }
}
fixed_packet! {
    /// S2C `0x0A`: login (password) response, 36 bytes for every client type.
    pub struct LoginResponse = kind::LOGIN_RESPONSE; {
        /// Result code ([`login_code`]).
        pub code: u8,
        /// Server version (134).
        pub server_version: u32,
        /// VIP: Continuum skips its checksum checks.
        pub is_vip: u8,
        /// Unused.
        pub unused1: [u8; 3],
        /// Expected exe checksum (`0xFFFFFFFF` with the code checksum also
        /// `0xFFFFFFFF` marks the user as staff).
        pub exe_checksum: u32,
        /// Unused.
        pub unused2: [u8; 5],
        /// Non-zero asks the client for registration data (C2S `0x17`).
        pub demo_data: u8,
        /// Code checksum.
        pub code_checksum: u32,
        /// CRC-32 of the news file (0 = none).
        pub news_checksum: u32,
        /// Unused.
        pub unused3: [u8; 8],
    }
}

/// Login response codes.
pub mod login_code {
    /// Success.
    pub const OK: u8 = 0x00;
    /// Unknown name; the client may resend with the new-user flag.
    pub const NEW_USER: u8 = 0x01;
    /// Wrong password.
    pub const BAD_PASSWORD: u8 = 0x02;
    /// Arena full.
    pub const FULL: u8 = 0x03;
    /// Locked out.
    pub const LOCKED: u8 = 0x04;
    /// No permission.
    pub const NO_PERMISSION: u8 = 0x05;
    /// Success, spectator only.
    pub const SPEC_ONLY: u8 = 0x06;
    /// Too many points.
    pub const TOO_MANY_POINTS: u8 = 0x07;
    /// Connection too slow.
    pub const TOO_SLOW: u8 = 0x08;
    /// No permission (2).
    pub const NO_PERMISSION2: u8 = 0x09;
    /// Not accepting new connections.
    pub const NO_NEW_CONNECTIONS: u8 = 0x0A;
    /// Bad name.
    pub const BAD_NAME: u8 = 0x0B;
    /// Offensive name.
    pub const OFFENSIVE_NAME: u8 = 0x0C;
    /// Success, but no scores are kept (biller down).
    pub const NO_SCORES: u8 = 0x0D;
    /// Server busy.
    pub const SERVER_BUSY: u8 = 0x0E;
    /// Not enough usage.
    pub const TOO_LOW_USAGE: u8 = 0x0F;
    /// No name.
    pub const NO_NAME: u8 = 0x10;
    /// Too many demo users.
    pub const TOO_MANY_DEMO: u8 = 0x11;
    /// No demo users.
    pub const NO_DEMO: u8 = 0x12;
    /// Custom text (Continuum only; preceded by S2C `0x33`).
    pub const CUSTOM_TEXT: u8 = 0x13;
}

fixed_packet! {
    /// S2C `0x0B`: a soccer goal was scored.
    pub struct SoccerGoal = kind::SOCCER_GOAL; {
        /// Scoring frequency.
        pub freq: i16,
        /// Points awarded.
        pub points: i32,
    }
}
fixed_packet! {
    /// S2C `0x0D`: a player changed frequency.
    pub struct FreqChange = kind::FREQ_CHANGE; {
        /// Player.
        pub pid: i16,
        /// New frequency.
        pub freq: i16,
        /// Servers send `0xFF`; with the high bit clear some clients read a ship.
        pub ship: u8,
    }
}
fixed_packet! {
    /// S2C `0x0E`: a player attached to (or detached from) another.
    pub struct Turret = kind::TURRET; {
        /// The attaching player.
        pub pid: i16,
        /// Host, or -1 to detach.
        pub host: i16,
    }
}
fixed_packet! {
    /// S2C `0x12`: flag location.
    pub struct FlagLocation = kind::FLAG_LOCATION; {
        /// Flag id.
        pub flag_id: u16,
        /// X tile.
        pub x: u16,
        /// Y tile.
        pub y: u16,
        /// Owning frequency (`0xFFFF` = neutral).
        pub freq: u16,
    }
}
fixed_packet! {
    /// S2C `0x13`: a player picked up a flag.
    pub struct FlagPickup = kind::FLAG_PICKUP; {
        /// Flag id.
        pub flag_id: i16,
        /// Player.
        pub pid: i16,
    }
}
fixed_packet! {
    /// S2C `0x14`: the flag game was won (and flags reset).
    pub struct FlagVictory = kind::FLAG_VICTORY; {
        /// Winning frequency.
        pub freq: i16,
        /// Points awarded.
        pub points: i32,
    }
}
fixed_packet! {
    /// S2C `0x15`: everyone attached to `pid` is detached.
    pub struct TurretKickoff = kind::TURRET_KICKOFF; {
        /// Host player.
        pub pid: i16,
    }
}
fixed_packet! {
    /// S2C `0x16`: a player dropped flags.
    pub struct FlagDrop = kind::FLAG_DROP; {
        /// Player.
        pub pid: i16,
    }
}
fixed_packet! {
    /// S2C `0x18`: random seeds and, optionally, a security checksum request.
    pub struct Security = kind::SECURITY; {
        /// Prize seed.
        pub green_seed: u32,
        /// Door seed.
        pub door_seed: u32,
        /// Server time the seeds apply from (ticks).
        pub timestamp: u32,
        /// Checksum key: 0 = seeds only; otherwise answer with C2S `0x1A`.
        pub key: u32,
    }
}
fixed_packet! {
    /// S2C `0x19`: the server asks the client to upload a file (C2S `0x16`).
    pub struct RequestFile = kind::REQUEST_FILE; {
        /// Path on the client's machine.
        pub local_path: FixedStr<256>,
        /// File name.
        pub name: FixedStr<16>,
    }
}
fixed_packet! {
    /// S2C `0x1A`: reset scores of `pid`, or of everyone when -1.
    pub struct ScoreReset = kind::SCORE_RESET; {
        /// Player, or -1.
        pub pid: i16,
    }
}
fixed_packet! {
    /// S2C `0x1B`: the client must reset its ship.
    pub struct ShipReset = kind::SHIP_RESET; {}
}
fixed_packet! {
    /// S2C `0x1D`: a player changed ship (and frequency).
    pub struct ShipChange = kind::SHIP_CHANGE; {
        /// Ship (8 = spectator).
        pub ship: i8,
        /// Player.
        pub pid: i16,
        /// Frequency.
        pub freq: i16,
    }
}
fixed_packet! {
    /// S2C `0x1E`: banner toggle (meaning unclear).
    pub struct BannerToggle = kind::BANNER_TOGGLE; {
        /// Toggle value.
        pub toggle: u8,
    }
}
fixed_packet! {
    /// S2C `0x1F`: a player's banner.
    pub struct Banner = kind::BANNER; {
        /// Player.
        pub pid: i16,
        /// 12x8 pixels, palette indices, no header.
        pub banner: Raw<96>,
    }
}
fixed_packet! {
    /// S2C `0x20`: you received prizes.
    pub struct PrizeReceive = kind::PRIZE_RECEIVE; {
        /// How many.
        pub count: i16,
        /// Prize ([`crate::common::prize`]).
        pub prize: i16,
    }
}
fixed_packet! {
    /// S2C `0x24`: speed game results.
    pub struct SpeedStats = kind::SPEED_STATS; {
        /// Whether this is your personal best.
        pub personal_best: u8,
        /// Your rank.
        pub rank: u16,
        /// Your score.
        pub score: i32,
        /// Top five scores.
        pub top_scores: [i32; 5],
        /// Top five players (-1 = empty).
        pub top_pids: [i16; 5],
    }
}
fixed_packet! {
    /// S2C `0x25`: whether the client may use UFO.
    pub struct Ufo = kind::UFO; {
        /// 1 = allowed.
        pub allowed: u8,
    }
}
fixed_packet! {
    /// S2C `0x27`: keep-alive.
    pub struct KeepAlive = kind::KEEP_ALIVE; {}
}
fixed_packet! {
    /// S2C `0x2B`: set your crown timer.
    pub struct SetKothTimer = kind::SET_KOTH_TIMER; {
        /// Ticks.
        pub time: u32,
    }
}
fixed_packet! {
    /// S2C `0x2C`: crown given or removed.
    pub struct Koth = kind::KOTH; {
        /// 1 = give / start, 0 = remove.
        pub action: u8,
        /// Duration in ticks (0 when removing).
        pub time: u32,
        /// Player, or -1 for everyone.
        pub pid: i16,
    }
}
fixed_packet! {
    /// S2C `0x2D`: add time to your crown timer.
    pub struct AddKothTime = kind::ADD_KOTH_TIME; {
        /// Ticks to add.
        pub time: u32,
    }
}
fixed_packet! {
    /// S2C `0x2E`: ball position.
    pub struct BallPosition = kind::BALL; {
        /// Ball id.
        pub ball_id: u8,
        /// X pixel.
        pub x: i16,
        /// Y pixel.
        pub y: i16,
        /// X velocity.
        pub x_speed: i16,
        /// Y velocity.
        pub y_speed: i16,
        /// Carrier or last shooter (-1 = none).
        pub pid: i16,
        /// Server time (ticks; 0 while carried).
        pub time: u32,
    }
}
fixed_packet! {
    /// S2C `0x31`: login complete (obsolete billing-era packet).
    pub struct LoginOk = kind::LOGIN_OK; {}
}
fixed_packet! {
    /// S2C `0x32`: warp to a tile.
    pub struct WarpTo = kind::WARP_TO; {
        /// X tile.
        pub x: i16,
        /// Y tile.
        pub y: i16,
    }
}
fixed_packet! {
    /// S2C `0x34`: Continuum version and expected exe checksum.
    pub struct ContVersion = kind::CONT_VERSION; {
        /// Version (40 for Continuum 0.40).
        pub version: u16,
        /// Expected exe checksum.
        pub checksum: u32,
    }
}
fixed_packet! {
    /// S2C `0x37`: start (1) or stop (0) sending damage reports.
    pub struct ToggleDamage = kind::TOGGLE_DAMAGE; {
        /// 1 = send reports.
        pub on: u8,
    }
}
fixed_packet! {
    /// S2C `0x3B`: redirect to another server/arena.
    pub struct Redirect = kind::REDIRECT; {
        /// IPv4 address bytes as on the wire (sources disagree on order; ASSS
        /// sends network order a.b.c.d).
        pub ip: [u8; 4],
        /// Port.
        pub port: u16,
        /// Arena type, as in C2S `0x01`.
        pub arena_type: i16,
        /// Arena name.
        pub arena: FixedStr<16>,
        /// Login id echoed by the client in its login packet.
        pub login_id: u32,
    }
}

/// S2C `0x01`: your player id (3 bytes; some servers add a byte).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlayerId {
    /// Your player id.
    pub pid: i16,
    /// Optional trailing byte of unknown meaning.
    pub extra: Option<u8>,
}

impl Packet for PlayerId {
    const TYPE: u8 = kind::PLAYER_ID;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        let pid = r.i16()?;
        let extra = if r.remaining() > 0 {
            Some(r.u8()?)
        } else {
            None
        };
        Ok(Self { pid, extra })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_i16(self.pid);
        if let Some(e) = self.extra {
            out.put_u8(e);
        }
    }
}

/// S2C `0x03`: one or more players entering (records are concatenated, each with
/// its own `0x03` byte).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlayerEntering {
    /// The players.
    pub players: Vec<PlayerData>,
}

impl Packet for PlayerEntering {
    const TYPE: u8 = kind::PLAYER_ENTERING;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        expect_type(data, Self::TYPE)?;
        Ok(Self {
            players: PlayerData::decode_all(data)?,
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        self.players.iter().for_each(|p| p.write(out));
    }
}

/// A chat packet body; [`S2CChat`] and [`crate::c2s::C2SChat`] share it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChatBody {
    /// [`crate::common::chat_type`].
    pub kind: u8,
    /// Sound number (0 = none).
    pub sound: u8,
    /// S2C: sender (-1 = none). C2S: target for private/enemy-freq types.
    pub pid: i16,
    /// Text without the terminating NUL.
    pub text: Vec<u8>,
}

impl ChatBody {
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            kind: r.u8()?,
            sound: r.u8()?,
            pid: r.i16()?,
            text: r.cstr(),
        })
    }
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.put_u8(self.kind);
        out.put_u8(self.sound);
        out.put_i16(self.pid);
        out.put_cstr(&self.text);
    }
}

/// S2C `0x07`: chat message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct S2CChat(pub ChatBody);

impl Packet for S2CChat {
    const TYPE: u8 = kind::CHAT;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        ChatBody::read(&mut expect_type(data, Self::TYPE)?).map(Self)
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        self.0.write(out);
    }
}

/// S2C `0x0C`: voice message from a player.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct S2CVoice {
    /// Sender.
    pub pid: i16,
    /// Compressed WAV data.
    pub data: Vec<u8>,
}

impl Packet for S2CVoice {
    const TYPE: u8 = kind::VOICE;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        Ok(Self {
            pid: r.i16()?,
            data: r.rest().to_vec(),
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_i16(self.pid);
        out.put_bytes(&self.data);
    }
}

/// S2C `0x10`: an incoming file (an all-zero name means the news file, which is
/// zlib-compressed).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IncomingFile {
    /// File name.
    pub name: FixedStr<16>,
    /// Contents.
    pub data: Vec<u8>,
}

impl Packet for IncomingFile {
    const TYPE: u8 = kind::INCOMING_FILE;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        Ok(Self {
            name: r.fixed()?,
            data: r.rest().to_vec(),
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        self.name.write(out);
        out.put_bytes(&self.data);
    }
}

/// S2C `0x1C`: spectator data; the two forms differ in length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecData {
    /// 2 bytes: 1 = append extra data to your position packets, 0 = stop.
    ExtraData(u8),
    /// 3 bytes: the player went into spectator mode.
    Player(i16),
}

impl Default for SpecData {
    fn default() -> Self {
        Self::ExtraData(0)
    }
}

impl Packet for SpecData {
    const TYPE: u8 = kind::SPEC_DATA;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        if r.remaining() >= 2 {
            Ok(Self::Player(r.i16()?))
        } else {
            Ok(Self::ExtraData(r.u8()?))
        }
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        match self {
            Self::ExtraData(v) => out.put_u8(*v),
            Self::Player(p) => out.put_i16(*p),
        }
    }
}

macro_rules! list_packet {
    ($(#[$m:meta])* $name:ident = $ty:expr, $field:ident: $t:ty, $min:expr) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            /// Entries.
            pub $field: Vec<$t>,
        }

        impl Packet for $name {
            const TYPE: u8 = $ty;
            #[allow(unused_comparisons)]
            fn decode(data: &[u8]) -> Result<Self, DecodeError> {
                let mut r = expect_type(data, Self::TYPE)?;
                let $field: Vec<$t> = read_entries(&mut r, Self::TYPE)?;
                if $field.len() < $min {
                    return Err(DecodeError::Truncated {
                        kind: Self::TYPE,
                        need: 1 + $min * <$t as Wire>::SIZE,
                        have: data.len(),
                    });
                }
                Ok(Self { $field })
            }
            fn encode(&self, out: &mut Vec<u8>) {
                out.put_u8(Self::TYPE);
                self.$field.iter().for_each(|e| e.write(out));
            }
        }

        #[cfg(test)]
        impl $name {
            /// Property tests: a list of arbitrary entries.
            pub(crate) fn arb() -> impl proptest::strategy::Strategy<Value = Self> {
                use proptest::strategy::Strategy;
                proptest::collection::vec($crate::wire::arb_wire::<$t>(), $min..$min + 40)
                    .prop_map(|$field| Self { $field })
            }
        }
    };
}

list_packet! {
    /// S2C `0x21`: bricks placed. An empty list (1-byte packet) clears all bricks.
    Bricks = kind::BRICK, bricks: Brick, 0
}
list_packet! {
    /// S2C `0x22`: owner frequency of every static flag, indexed by flag id (-1 =
    /// unowned).
    TurfFlags = kind::TURF_FLAGS, owners: i16, 0
}
list_packet! {
    /// S2C `0x35`: show/hide LVZ objects.
    ToggleObjects = kind::TOGGLE_OBJECTS, toggles: ObjectToggle, 1
}
list_packet! {
    /// S2C `0x36`: change LVZ object properties.
    MoveObjects = kind::MOVE_OBJECTS, changes: ObjectChange, 1
}
list_packet! {
    /// S2C `0x39`: several small positions (needs the batch-positions client feature).
    BatchedSmallPositions = kind::BATCHED_SMALL_POSITION, entries: SmallBatchedPosition, 0
}
list_packet! {
    /// S2C `0x3A`: several large positions (needs the batch-positions client feature).
    BatchedLargePositions = kind::BATCHED_LARGE_POSITION, entries: LargeBatchedPosition, 0
}

/// One periodic reward entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reward {
    /// Frequency.
    pub freq: i16,
    /// Points for each player on it (in a ship, outside safe zones).
    pub points: i16,
}

impl Wire for Reward {
    const SIZE: usize = 4;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            freq: r.i16()?,
            points: r.i16()?,
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.put_i16(self.freq);
        out.put_i16(self.points);
    }
}

list_packet! {
    /// S2C `0x23`: periodic flag reward.
    PeriodicReward = kind::PERIODIC_REWARD, rewards: Reward, 0
}

/// One entry of the map file list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MapFile {
    /// File name (may use all 16 bytes without a NUL).
    pub name: FixedStr<16>,
    /// CRC-32 of the file as stored on the server.
    pub checksum: u32,
    /// Total length of the S2C `0x2A` packet that carries it.
    pub size: u32,
}

/// S2C `0x29`: map (and LVZ) file names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapFilename {
    /// 21-byte form for clients without LVZ support.
    Single {
        /// Map file name.
        name: FixedStr<16>,
        /// CRC-32 of the uncompressed map file.
        checksum: u32,
    },
    /// `1 + 24 * n` form: entry 0 is the map, the rest are LVZ files.
    Files(Vec<MapFile>),
}

impl Default for MapFilename {
    fn default() -> Self {
        Self::Single {
            name: FixedStr::default(),
            checksum: 0,
        }
    }
}

impl Packet for MapFilename {
    const TYPE: u8 = kind::MAP_FILENAME;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        if data.len() == 21 {
            return Ok(Self::Single {
                name: r.fixed()?,
                checksum: r.u32()?,
            });
        }
        if data.len() < 25 || !(data.len() - 1).is_multiple_of(24) {
            return Err(DecodeError::Invalid {
                kind: Self::TYPE,
                field: "length",
            });
        }
        let mut files = Vec::new();
        while r.remaining() > 0 {
            files.push(MapFile {
                name: r.fixed()?,
                checksum: r.u32()?,
                size: r.u32()?,
            });
        }
        Ok(Self::Files(files))
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        match self {
            Self::Single { name, checksum } => {
                name.write(out);
                out.put_u32(*checksum);
            }
            Self::Files(files) => {
                for f in files {
                    f.name.write(out);
                    out.put_u32(f.checksum);
                    out.put_u32(f.size);
                }
            }
        }
    }
}

/// S2C `0x2A`: map or LVZ file contents (maps are zlib-compressed, LVZ files are
/// sent as stored).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MapData {
    /// File name.
    pub name: FixedStr<16>,
    /// Contents.
    pub data: Vec<u8>,
}

impl Packet for MapData {
    const TYPE: u8 = kind::MAP_DATA;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        Ok(Self {
            name: r.fixed()?,
            data: r.rest().to_vec(),
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        self.name.write(out);
        out.put_bytes(&self.data);
    }
}

/// One arena list entry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArenaEntry {
    /// Arena name.
    pub name: Vec<u8>,
    /// Population; negative for the arena the recipient is in.
    pub population: i16,
}

/// S2C `0x2F`: arena list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArenaList {
    /// Arenas.
    pub arenas: Vec<ArenaEntry>,
}

impl Packet for ArenaList {
    const TYPE: u8 = kind::ARENA_LIST;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        let mut arenas = Vec::new();
        while r.remaining() > 0 {
            let name = r.cstr();
            arenas.push(ArenaEntry {
                name,
                population: r.i16()?,
            });
        }
        Ok(Self { arenas })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        for a in &self.arenas {
            out.put_cstr(&a.name);
            out.put_i16(a.population);
        }
    }
}

/// S2C `0x30`: advertisement banner (obsolete; data encoding unknown).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdBanner {
    /// Display mode.
    pub mode: u8,
    /// Width.
    pub width: u16,
    /// Height.
    pub height: u16,
    /// Duration.
    pub duration: u32,
    /// Banner data.
    pub data: Vec<u8>,
}

impl Packet for AdBanner {
    const TYPE: u8 = kind::AD_BANNER;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        Ok(Self {
            mode: r.u8()?,
            width: r.u16()?,
            height: r.u16()?,
            duration: r.u32()?,
            data: r.rest().to_vec(),
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_u8(self.mode);
        out.put_u16(self.width);
        out.put_u16(self.height);
        out.put_u32(self.duration);
        out.put_bytes(&self.data);
    }
}

/// S2C `0x33`: custom login text (Continuum).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoginText {
    /// Text without the NUL.
    pub text: Vec<u8>,
}

impl Packet for LoginText {
    const TYPE: u8 = kind::LOGIN_TEXT;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            text: expect_type(data, Self::TYPE)?.cstr(),
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_cstr(&self.text);
    }
}

/// S2C `0x38`: damage reports for a player.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct S2CDamage {
    /// Player who took the damage.
    pub pid: i16,
    /// Server time (ticks).
    pub time: u32,
    /// Hits.
    pub entries: Vec<DamageData>,
}

impl Packet for S2CDamage {
    const TYPE: u8 = kind::DAMAGE;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        let pid = r.i16()?;
        let time = r.u32()?;
        Ok(Self {
            pid,
            time,
            entries: read_entries(&mut r, Self::TYPE)?,
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_i16(self.pid);
        out.put_u32(self.time);
        self.entries.iter().for_each(|e| e.write(out));
    }
}

/// One select box item.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectItem {
    /// Value returned in `?select <value> <text>`.
    pub value: i16,
    /// Text (at most 127 bytes).
    pub text: Vec<u8>,
}

/// S2C `0x3C`: show a selection box.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectBox {
    /// Title (at most 63 bytes).
    pub title: Vec<u8>,
    /// Items.
    pub items: Vec<SelectItem>,
}

impl Packet for SelectBox {
    const TYPE: u8 = kind::SELECT_BOX;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        let title = r.cstr();
        let mut items = Vec::new();
        while r.remaining() > 0 {
            let value = r.i16()?;
            items.push(SelectItem {
                value,
                text: r.cstr(),
            });
        }
        Ok(Self { title, items })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_cstr(&self.title);
        for i in &self.items {
            out.put_i16(i.value);
            out.put_cstr(&i.text);
        }
    }
}

impl Packet for ClientSettings {
    const TYPE: u8 = kind::SETTINGS;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        ClientSettings::decode(data)
    }
    fn encode(&self, out: &mut Vec<u8>) {
        ClientSettings::encode(self, out)
    }
}

macro_rules! packet_enum {
    ($(#[$m:meta])* $name:ident { $( $(#[$vm:meta])* $var:ident($t:ty), )* }) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum $name {
            $( $(#[$vm])* $var($t), )*
            /// A type this crate does not decode (or a core `0x00` packet).
            Unknown {
                /// Type byte.
                kind: u8,
                /// The whole packet, type byte included.
                data: Vec<u8>,
            },
        }

        impl $name {
            /// Decodes a packet by its type byte.
            pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
                let kind = *data.first().ok_or(DecodeError::Empty)?;
                $( if kind == <$t as Packet>::TYPE {
                    return <$t as Packet>::decode(data).map(Self::$var);
                } )*
                Ok(Self::Unknown { kind, data: data.to_vec() })
            }

            /// Appends the encoded packet.
            pub fn encode(&self, out: &mut Vec<u8>) {
                match self {
                    $( Self::$var(p) => p.encode(out), )*
                    Self::Unknown { data, .. } => out.extend_from_slice(data),
                }
            }

            /// The encoded packet.
            pub fn to_bytes(&self) -> Vec<u8> {
                let mut v = Vec::new();
                self.encode(&mut v);
                v
            }

            /// The packet's type byte.
            pub fn kind(&self) -> u8 {
                match self {
                    $( Self::$var(_) => <$t as Packet>::TYPE, )*
                    Self::Unknown { kind, .. } => *kind,
                }
            }
        }

        $(
            impl From<$t> for $name {
                fn from(p: $t) -> Self {
                    Self::$var(p)
                }
            }
        )*
    };
}

pub(crate) use packet_enum;

packet_enum! {
    /// Any server-to-client game packet.
    S2CPacket {
        /// `0x01`.
        PlayerId(PlayerId),
        /// `0x02`.
        EnteringArena(EnteringArena),
        /// `0x03`.
        PlayerEntering(PlayerEntering),
        /// `0x04`.
        PlayerLeaving(PlayerLeaving),
        /// `0x05`.
        Weapon(S2CWeapon),
        /// `0x06`.
        Kill(Kill),
        /// `0x07`.
        Chat(S2CChat),
        /// `0x08`.
        Green(Green),
        /// `0x09`.
        ScoreUpdate(ScoreUpdate),
        /// `0x0A`.
        LoginResponse(LoginResponse),
        /// `0x0B`.
        SoccerGoal(SoccerGoal),
        /// `0x0C`.
        Voice(S2CVoice),
        /// `0x0D`.
        FreqChange(FreqChange),
        /// `0x0E`.
        Turret(Turret),
        /// `0x0F`.
        Settings(alloc::boxed::Box<ClientSettings>),
        /// `0x10`.
        IncomingFile(IncomingFile),
        /// `0x12`.
        FlagLocation(FlagLocation),
        /// `0x13`.
        FlagPickup(FlagPickup),
        /// `0x14`.
        FlagVictory(FlagVictory),
        /// `0x15`.
        TurretKickoff(TurretKickoff),
        /// `0x16`.
        FlagDrop(FlagDrop),
        /// `0x18`.
        Security(Security),
        /// `0x19`.
        RequestFile(RequestFile),
        /// `0x1A`.
        ScoreReset(ScoreReset),
        /// `0x1B`.
        ShipReset(ShipReset),
        /// `0x1C`.
        SpecData(SpecData),
        /// `0x1D`.
        ShipChange(ShipChange),
        /// `0x1E`.
        BannerToggle(BannerToggle),
        /// `0x1F`.
        Banner(Banner),
        /// `0x20`.
        PrizeReceive(PrizeReceive),
        /// `0x21`.
        Bricks(Bricks),
        /// `0x22`.
        TurfFlags(TurfFlags),
        /// `0x23`.
        PeriodicReward(PeriodicReward),
        /// `0x24`.
        SpeedStats(SpeedStats),
        /// `0x25`.
        Ufo(Ufo),
        /// `0x27`.
        KeepAlive(KeepAlive),
        /// `0x28`.
        Position(S2CPosition),
        /// `0x29`.
        MapFilename(MapFilename),
        /// `0x2A`.
        MapData(MapData),
        /// `0x2B`.
        SetKothTimer(SetKothTimer),
        /// `0x2C`.
        Koth(Koth),
        /// `0x2D`.
        AddKothTime(AddKothTime),
        /// `0x2E`.
        Ball(BallPosition),
        /// `0x2F`.
        ArenaList(ArenaList),
        /// `0x30`.
        AdBanner(AdBanner),
        /// `0x31`.
        LoginOk(LoginOk),
        /// `0x32`.
        WarpTo(WarpTo),
        /// `0x33`.
        LoginText(LoginText),
        /// `0x34`.
        ContVersion(ContVersion),
        /// `0x35`.
        ToggleObjects(ToggleObjects),
        /// `0x36`.
        MoveObjects(MoveObjects),
        /// `0x37`.
        ToggleDamage(ToggleDamage),
        /// `0x38`.
        Damage(S2CDamage),
        /// `0x39`.
        BatchedSmallPositions(BatchedSmallPositions),
        /// `0x3A`.
        BatchedLargePositions(BatchedLargePositions),
        /// `0x3B`.
        Redirect(Redirect),
        /// `0x3C`.
        SelectBox(SelectBox),
    }
}

impl From<ClientSettings> for S2CPacket {
    fn from(p: ClientSettings) -> Self {
        Self::Settings(alloc::boxed::Box::new(p))
    }
}
