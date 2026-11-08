//! Client-to-server game packets.
//!
//! Each packet type is a struct implementing [`Packet`]; [`C2SPacket`] decodes any
//! of them by type byte (and length where a type has several forms). Fixed-size
//! packets ignore trailing bytes when decoding.

use alloc::vec::Vec;

use crate::DecodeError;
use crate::common::{DamageData, read_entries};
use crate::fixed_packet;
use crate::position::C2SPosition;
use crate::s2c::{ChatBody, packet_enum};
use crate::wire::{FixedStr, Packet, Raw, Reader, Wire, Writer, expect_type};

/// C2S type bytes.
pub mod kind {
    /// Enter an arena.
    pub const GO_ARENA: u8 = 0x01;
    /// Leave the arena.
    pub const LEAVE_ARENA: u8 = 0x02;
    /// Position.
    pub const POSITION: u8 = 0x03;
    /// Death.
    pub const DEATH: u8 = 0x05;
    /// Chat.
    pub const CHAT: u8 = 0x06;
    /// Take a prize.
    pub const TAKE_GREEN: u8 = 0x07;
    /// Spectate a player.
    pub const SPEC_REQUEST: u8 = 0x08;
    /// Login (SubSpace/VIE form).
    pub const LOGIN: u8 = 0x09;
    /// Relay LVZ object changes.
    pub const REBROADCAST: u8 = 0x0A;
    /// Client update request.
    pub const UPDATE_REQUEST: u8 = 0x0B;
    /// Map/LVZ request.
    pub const MAP_REQUEST: u8 = 0x0C;
    /// News request.
    pub const NEWS_REQUEST: u8 = 0x0D;
    /// Voice message.
    pub const VOICE: u8 = 0x0E;
    /// Frequency change request.
    pub const SET_FREQ: u8 = 0x0F;
    /// Attach request.
    pub const ATTACH_TO: u8 = 0x10;
    /// Flag pickup.
    pub const PICKUP_FLAG: u8 = 0x13;
    /// Detach all turrets.
    pub const TURRET_KICKOFF: u8 = 0x14;
    /// Drop flags.
    pub const DROP_FLAGS: u8 = 0x15;
    /// File upload.
    pub const UPLOAD_FILE: u8 = 0x16;
    /// Registration data.
    pub const REGISTRATION: u8 = 0x17;
    /// Ship change request.
    pub const SET_SHIP: u8 = 0x18;
    /// Banner.
    pub const BANNER: u8 = 0x19;
    /// Security response.
    pub const SECURITY_RESPONSE: u8 = 0x1A;
    /// Security violation.
    pub const SECURITY_VIOLATION: u8 = 0x1B;
    /// Drop a brick.
    pub const DROP_BRICK: u8 = 0x1C;
    /// Settings change.
    pub const SETTING_CHANGE: u8 = 0x1D;
    /// Crown timer expired.
    pub const KOTH_EXPIRED: u8 = 0x1E;
    /// Shoot the ball.
    pub const SHOOT_BALL: u8 = 0x1F;
    /// Pick up the ball.
    pub const PICKUP_BALL: u8 = 0x20;
    /// Goal.
    pub const GOAL: u8 = 0x21;
    /// Login (Continuum form).
    pub const CONT_LOGIN: u8 = 0x24;
    /// Damage reports.
    pub const DAMAGE: u8 = 0x32;
}

/// Arena types for [`GoArena::arena_type`].
pub mod arena_type {
    /// Any public arena; the server chooses.
    pub const ANY_PUBLIC: i16 = -1;
    /// Treated like [`ANY_PUBLIC`] by servers.
    pub const RANDOM: i16 = -2;
    /// The named arena in [`super::GoArena::arena`].
    pub const NAMED: i16 = -3;
}

/// C2S `0x01`: enter an arena. 26 bytes from SubSpace clients, 27 from Continuum.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GoArena {
    /// Requested ship (8 = spectator).
    pub ship: u8,
    /// Whether the client accepts voice messages (most sources; one server
    /// reads this byte as the obscenity filter).
    pub allow_audio: i8,
    /// Obscenity filter (most sources).
    pub obscenity_filter: i8,
    /// Screen width.
    pub x_res: i16,
    /// Screen height.
    pub y_res: i16,
    /// [`arena_type`], or a public arena number (>= 0).
    pub arena_type: i16,
    /// Arena name (for [`arena_type::NAMED`]).
    pub arena: FixedStr<16>,
    /// Continuum only: 1 = download optional LVZ files.
    pub optional_graphics: Option<u8>,
}

impl Packet for GoArena {
    const TYPE: u8 = kind::GO_ARENA;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        Ok(Self {
            ship: r.u8()?,
            allow_audio: r.i8()?,
            obscenity_filter: r.i8()?,
            x_res: r.i16()?,
            y_res: r.i16()?,
            arena_type: r.i16()?,
            arena: r.fixed()?,
            optional_graphics: if r.remaining() > 0 {
                Some(r.u8()?)
            } else {
                None
            },
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_u8(self.ship);
        out.put_i8(self.allow_audio);
        out.put_i8(self.obscenity_filter);
        out.put_i16(self.x_res);
        out.put_i16(self.y_res);
        out.put_i16(self.arena_type);
        self.arena.write(out);
        if let Some(g) = self.optional_graphics {
            out.put_u8(g);
        }
    }
}

fixed_packet! {
    /// C2S `0x02`: leave the arena.
    pub struct LeaveArena = kind::LEAVE_ARENA; {}
}
fixed_packet! {
    /// C2S `0x05`: the client died.
    pub struct Death = kind::DEATH; {
        /// Killer.
        pub killer: i16,
        /// Bounty of the dead player.
        pub bounty: i16,
    }
}
fixed_packet! {
    /// C2S `0x07`: the client picked up a prize.
    pub struct TakeGreen = kind::TAKE_GREEN; {
        /// Time (ticks).
        pub time: u32,
        /// X tile.
        pub x: i16,
        /// Y tile.
        pub y: i16,
        /// Prize.
        pub prize: i16,
    }
}
fixed_packet! {
    /// C2S `0x08`: spectate a player (-1 = none).
    pub struct SpecRequest = kind::SPEC_REQUEST; {
        /// Player.
        pub pid: i16,
    }
}
fixed_packet! {
    /// C2S `0x0B`: client update request.
    pub struct UpdateRequest = kind::UPDATE_REQUEST; {}
}
fixed_packet! {
    /// C2S `0x0D`: news file request.
    pub struct NewsRequest = kind::NEWS_REQUEST; {}
}
fixed_packet! {
    /// C2S `0x0F`: frequency change request.
    pub struct SetFreq = kind::SET_FREQ; {
        /// Frequency.
        pub freq: i16,
    }
}
fixed_packet! {
    /// C2S `0x10`: attach to a player as a turret (-1 = detach).
    pub struct AttachTo = kind::ATTACH_TO; {
        /// Player.
        pub pid: i16,
    }
}
fixed_packet! {
    /// C2S `0x13`: pick up (touch) a flag.
    pub struct PickupFlag = kind::PICKUP_FLAG; {
        /// Flag id.
        pub flag_id: i16,
    }
}
fixed_packet! {
    /// C2S `0x14`: detach everyone attached to the client.
    pub struct TurretKickoff = kind::TURRET_KICKOFF; {}
}
fixed_packet! {
    /// C2S `0x15`: drop carried flags.
    pub struct DropFlags = kind::DROP_FLAGS; {}
}
fixed_packet! {
    /// C2S `0x18`: ship change request (8 = spectator).
    pub struct SetShip = kind::SET_SHIP; {
        /// Ship.
        pub ship: u8,
    }
}
fixed_packet! {
    /// C2S `0x19`: set the client's banner.
    pub struct SetBanner = kind::BANNER; {
        /// 12x8 pixels, palette indices.
        pub banner: Raw<96>,
    }
}
fixed_packet! {
    /// C2S `0x1C`: drop a brick at a tile.
    pub struct DropBrick = kind::DROP_BRICK; {
        /// X tile.
        pub x: i16,
        /// Y tile.
        pub y: i16,
    }
}
fixed_packet! {
    /// C2S `0x1E`: the client's crown timer ran out.
    pub struct KothExpired = kind::KOTH_EXPIRED; {}
}
fixed_packet! {
    /// C2S `0x1F`: shoot the ball (same layout as S2C `0x2E`).
    pub struct ShootBall = kind::SHOOT_BALL; {
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
        /// Shooter.
        pub pid: i16,
        /// Time (ticks).
        pub time: u32,
    }
}
fixed_packet! {
    /// C2S `0x20`: pick up the ball.
    pub struct PickupBall = kind::PICKUP_BALL; {
        /// Ball id.
        pub ball_id: u8,
        /// Time (ticks).
        pub time: u32,
    }
}
fixed_packet! {
    /// C2S `0x21`: a goal (most sources read x/y tiles; one reads a timestamp).
    pub struct Goal = kind::GOAL; {
        /// Ball id.
        pub ball_id: u8,
        /// X tile.
        pub x: i16,
        /// Y tile.
        pub y: i16,
    }
}

/// C2S `0x06`: chat message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct C2SChat(pub ChatBody);

impl Packet for C2SChat {
    const TYPE: u8 = kind::CHAT;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        ChatBody::read(&mut expect_type(data, Self::TYPE)?).map(Self)
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        self.0.write(out);
    }
}

/// C2S `0x09` (101 bytes, SubSpace) and `0x24` (165 bytes, Continuum): login.
///
/// Servers decide which length to expect from the encryption the connection
/// negotiated, not from the type byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    /// `0x09` or `0x24`, kept so the packet re-encodes as received.
    pub kind: u8,
    /// 1 = new user.
    pub flags: u8,
    /// Name.
    pub name: FixedStr<32>,
    /// Password.
    pub password: FixedStr<32>,
    /// Machine id.
    pub machine_id: u32,
    /// Connection type (4 is typical).
    pub connect_type: u8,
    /// Minutes from UTC.
    pub timezone_bias: i16,
    /// Unknown, 0.
    pub unknown1: u16,
    /// Client version (134 for SubSpace, 40 for Continuum 0.40).
    pub client_version: u16,
    /// Normally 444. Some servers read its upper half (bytes 79-80) as client
    /// feature flags ([`client_features`]).
    pub field444: i32,
    /// Normally 555.
    pub field555: i32,
    /// Permission id.
    pub permission_id: u32,
    /// Reserved; some servers read the connected-to address, port and a login id
    /// from [`super::s2c::Redirect`] here.
    pub reserved: [u8; 12],
    /// Continuum only: opaque client id passed to the billing server.
    pub cont_id: Option<[u8; 64]>,
}

/// Feature flags a client may advertise in the upper half of
/// [`Login::field444`] (offset 79).
pub mod client_features {
    /// Understands damage watching (S2C `0x38`, C2S `0x32`).
    pub const WATCH_DAMAGE: u16 = 0x01;
    /// Understands batched positions (S2C `0x39`/`0x3A`).
    pub const BATCH_POSITIONS: u16 = 0x02;
    /// Understands warp-to (S2C `0x32`).
    pub const WARP_TO: u16 = 0x04;
    /// Understands LVZ (S2C `0x35`/`0x36`, long `0x29`).
    pub const LVZ: u16 = 0x08;
    /// Understands redirect (S2C `0x3B`).
    pub const REDIRECT: u16 = 0x10;
    /// Understands select boxes (S2C `0x3C`).
    pub const SELECT_BOX: u16 = 0x20;
}

impl Login {
    /// Length of the SubSpace form.
    pub const VIE_LEN: usize = 101;
    /// Length of the Continuum form.
    pub const CONT_LEN: usize = 165;

    /// The feature flags in bytes 79-80.
    pub fn client_features(&self) -> u16 {
        (self.field444 as u32 >> 16) as u16
    }

    /// Decodes either form (type `0x09` or `0x24`; the Continuum id is read when
    /// the packet is long enough).
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let kind = *data.first().ok_or(DecodeError::Empty)?;
        if kind != kind::LOGIN && kind != kind::CONT_LOGIN {
            return Err(DecodeError::WrongType {
                expected: kind::LOGIN,
                found: kind,
            });
        }
        let mut r = Reader::new(data, kind);
        r.u8()?;
        Ok(Self {
            kind,
            flags: r.u8()?,
            name: r.fixed()?,
            password: r.fixed()?,
            machine_id: r.u32()?,
            connect_type: r.u8()?,
            timezone_bias: r.i16()?,
            unknown1: r.u16()?,
            client_version: r.u16()?,
            field444: r.i32()?,
            field555: r.i32()?,
            permission_id: r.u32()?,
            reserved: r.array()?,
            cont_id: if r.remaining() >= 64 {
                Some(r.array()?)
            } else {
                None
            },
        })
    }

    /// Appends the packet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(self.kind);
        out.put_u8(self.flags);
        self.name.write(out);
        self.password.write(out);
        out.put_u32(self.machine_id);
        out.put_u8(self.connect_type);
        out.put_i16(self.timezone_bias);
        out.put_u16(self.unknown1);
        out.put_u16(self.client_version);
        out.put_i32(self.field444);
        out.put_i32(self.field555);
        out.put_u32(self.permission_id);
        out.put_bytes(&self.reserved);
        if let Some(c) = &self.cont_id {
            out.put_bytes(c);
        }
    }
}

impl Default for Login {
    fn default() -> Self {
        Self {
            kind: kind::LOGIN,
            flags: 0,
            name: FixedStr::default(),
            password: FixedStr::default(),
            machine_id: 0,
            connect_type: 4,
            timezone_bias: 0,
            unknown1: 0,
            client_version: 134,
            field444: 444,
            field555: 555,
            permission_id: 0,
            reserved: [0; 12],
            cont_id: None,
        }
    }
}

/// C2S `0x0A`: relay an LVZ object packet (S2C `0x35` or `0x36`) to a player or
/// the arena.
///
/// The embedded packet is never empty: [`Rebroadcast::new`] refuses an empty
/// one, just as decoding refuses a 3-byte packet, so every value encodes to
/// something that decodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rebroadcast {
    /// Target player, or -1 for the whole arena.
    pub target: i16,
    packet: Vec<u8>,
}

impl Rebroadcast {
    /// A rebroadcast of `packet` (an S2C packet, type byte first). `None` if
    /// `packet` is empty.
    pub fn new(target: i16, packet: Vec<u8>) -> Option<Self> {
        (!packet.is_empty()).then_some(Self { target, packet })
    }

    /// The embedded S2C packet, type byte first (never empty).
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// The embedded packet, by value.
    pub fn into_packet(self) -> Vec<u8> {
        self.packet
    }
}

impl Packet for Rebroadcast {
    const TYPE: u8 = kind::REBROADCAST;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        let target = r.i16()?;
        Self::new(target, r.rest().to_vec()).ok_or(DecodeError::Truncated {
            kind: Self::TYPE,
            need: 4,
            have: data.len(),
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_i16(self.target);
        out.put_bytes(&self.packet);
    }
}

/// C2S `0x0C`: request the map (no index) or a file from the S2C `0x29` list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MapRequest {
    /// File index (absent = 0, the map).
    pub index: Option<u16>,
}

impl Packet for MapRequest {
    const TYPE: u8 = kind::MAP_REQUEST;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        Ok(Self {
            index: if r.remaining() >= 2 {
                Some(r.u16()?)
            } else {
                None
            },
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        if let Some(i) = self.index {
            out.put_u16(i);
        }
    }
}

/// C2S `0x0E`: store/send a voice message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct C2SVoice {
    /// Voice slot.
    pub slot: u8,
    /// Target player (negative = store only).
    pub target: i16,
    /// Compressed WAV data (empty = resend the stored slot).
    pub data: Vec<u8>,
}

impl Packet for C2SVoice {
    const TYPE: u8 = kind::VOICE;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        Ok(Self {
            slot: r.u8()?,
            target: r.i16()?,
            data: r.rest().to_vec(),
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_u8(self.slot);
        out.put_i16(self.target);
        out.put_bytes(&self.data);
    }
}

/// C2S `0x16`: upload a file (answer to S2C `0x19`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UploadFile {
    /// File name (servers ignore it).
    pub name: FixedStr<16>,
    /// Contents.
    pub data: Vec<u8>,
}

impl Packet for UploadFile {
    const TYPE: u8 = kind::UPLOAD_FILE;
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

/// C2S `0x17`: registration (demographics) form, 766 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// Real name.
    pub real_name: FixedStr<32>,
    /// E-mail.
    pub email: FixedStr<64>,
    /// City.
    pub city: FixedStr<32>,
    /// State.
    pub state: FixedStr<24>,
    /// `M` or `F`.
    pub sex: u8,
    /// Age.
    pub age: u8,
    /// Connecting from home.
    pub from_home: u8,
    /// From work.
    pub from_work: u8,
    /// From school.
    pub from_school: u8,
    /// Processor type (e.g. 586).
    pub processor: u32,
    /// Unknown.
    pub unknown1: u16,
    /// Unknown.
    pub unknown2: u16,
    /// Windows registered owner.
    pub win_owner: FixedStr<40>,
    /// Windows registered organisation.
    pub win_org: FixedStr<40>,
    /// Hardware description strings.
    pub hardware: [FixedStr<40>; 13],
}

impl Default for Registration {
    fn default() -> Self {
        Self {
            real_name: FixedStr::default(),
            email: FixedStr::default(),
            city: FixedStr::default(),
            state: FixedStr::default(),
            sex: b'M',
            age: 0,
            from_home: 0,
            from_work: 0,
            from_school: 0,
            processor: 0,
            unknown1: 0,
            unknown2: 0,
            win_owner: FixedStr::default(),
            win_org: FixedStr::default(),
            hardware: [FixedStr::default(); 13],
        }
    }
}

impl Registration {
    /// Encoded length, type byte included.
    pub const LEN: usize = 766;
}

impl Packet for Registration {
    const TYPE: u8 = kind::REGISTRATION;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        let mut s = Self {
            real_name: r.fixed()?,
            email: r.fixed()?,
            city: r.fixed()?,
            state: r.fixed()?,
            sex: r.u8()?,
            age: r.u8()?,
            from_home: r.u8()?,
            from_work: r.u8()?,
            from_school: r.u8()?,
            processor: r.u32()?,
            unknown1: r.u16()?,
            unknown2: r.u16()?,
            win_owner: r.fixed()?,
            win_org: r.fixed()?,
            hardware: [FixedStr::default(); 13],
        };
        for h in &mut s.hardware {
            *h = r.fixed()?;
        }
        Ok(s)
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        self.real_name.write(out);
        self.email.write(out);
        self.city.write(out);
        self.state.write(out);
        for b in [
            self.sex,
            self.age,
            self.from_home,
            self.from_work,
            self.from_school,
        ] {
            out.put_u8(b);
        }
        out.put_u32(self.processor);
        out.put_u16(self.unknown1);
        out.put_u16(self.unknown2);
        self.win_owner.write(out);
        self.win_org.write(out);
        self.hardware.iter().for_each(|h| h.write(out));
    }
}

/// C2S `0x1A`: answer to a security request. 40 bytes from SubSpace clients, 46
/// from Continuum (which adds timer drift and a map CRC).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityResponse {
    /// Weapon packets received.
    pub weapon_count: u32,
    /// [`crate::checksum::settings_checksum`].
    pub settings_checksum: u32,
    /// Exe checksum.
    pub exe_checksum: u32,
    /// [`crate::checksum::map_checksum`].
    pub map_checksum: u32,
    /// Slow S2C packets, total.
    pub s2c_slow_total: u32,
    /// Fast S2C packets, total.
    pub s2c_fast_total: u32,
    /// Slow S2C packets, current period.
    pub s2c_slow_current: u16,
    /// Fast S2C packets, current period.
    pub s2c_fast_current: u16,
    /// Reliable packets outstanding (one source calls it an average).
    pub s2c_reliable_out: u16,
    /// Last ping (10 ms units).
    pub ping_last: u16,
    /// Average ping.
    pub ping_average: u16,
    /// Lowest ping.
    pub ping_low: u16,
    /// Highest ping.
    pub ping_high: u16,
    /// Slow frame detected.
    pub slow_frame: u8,
    /// Continuum only: timer drift and [`crate::checksum::map_crc32`].
    pub continuum: Option<(i16, u32)>,
}

impl SecurityResponse {
    /// SubSpace length.
    pub const VIE_LEN: usize = 40;
    /// Continuum length.
    pub const CONT_LEN: usize = 46;
}

impl Packet for SecurityResponse {
    const TYPE: u8 = kind::SECURITY_RESPONSE;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        Ok(Self {
            weapon_count: r.u32()?,
            settings_checksum: r.u32()?,
            exe_checksum: r.u32()?,
            map_checksum: r.u32()?,
            s2c_slow_total: r.u32()?,
            s2c_fast_total: r.u32()?,
            s2c_slow_current: r.u16()?,
            s2c_fast_current: r.u16()?,
            s2c_reliable_out: r.u16()?,
            ping_last: r.u16()?,
            ping_average: r.u16()?,
            ping_low: r.u16()?,
            ping_high: r.u16()?,
            slow_frame: r.u8()?,
            continuum: if r.remaining() >= 6 {
                Some((r.i16()?, r.u32()?))
            } else {
                None
            },
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        for v in [
            self.weapon_count,
            self.settings_checksum,
            self.exe_checksum,
            self.map_checksum,
            self.s2c_slow_total,
            self.s2c_fast_total,
        ] {
            out.put_u32(v);
        }
        for v in [
            self.s2c_slow_current,
            self.s2c_fast_current,
            self.s2c_reliable_out,
            self.ping_last,
            self.ping_average,
            self.ping_low,
            self.ping_high,
        ] {
            out.put_u16(v);
        }
        out.put_u8(self.slow_frame);
        if let Some((drift, crc)) = self.continuum {
            out.put_i16(drift);
            out.put_u32(crc);
        }
    }
}

/// C2S `0x1B`: the client reports a security violation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityViolation {
    /// Violation code.
    pub code: u8,
    /// Optional message bytes after the code.
    pub text: Vec<u8>,
}

impl Packet for SecurityViolation {
    const TYPE: u8 = kind::SECURITY_VIOLATION;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        Ok(Self {
            code: r.u8()?,
            text: r.rest().to_vec(),
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_u8(self.code);
        out.put_bytes(&self.text);
    }
}

/// C2S `0x1D`: change settings: NUL-terminated `Section:Key:Value` strings,
/// ended by an empty string.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SettingChange {
    /// The strings, without NULs.
    pub entries: Vec<Vec<u8>>,
}

impl Packet for SettingChange {
    const TYPE: u8 = kind::SETTING_CHANGE;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        let mut entries = Vec::new();
        while r.remaining() > 0 {
            let s = r.cstr();
            if s.is_empty() {
                break;
            }
            entries.push(s);
        }
        Ok(Self { entries })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        self.entries.iter().for_each(|e| out.put_cstr(e));
        out.put_u8(0);
    }
}

/// C2S `0x32`: damage reports (sent while S2C `0x37` is on).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct C2SDamage {
    /// Time (ticks).
    pub time: u32,
    /// Hits.
    pub entries: Vec<DamageData>,
}

impl Packet for C2SDamage {
    const TYPE: u8 = kind::DAMAGE;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        let time = r.u32()?;
        Ok(Self {
            time,
            entries: read_entries(&mut r, Self::TYPE)?,
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_u32(self.time);
        self.entries.iter().for_each(|e| e.write(out));
    }
}

/// [`Login`] under its Continuum type byte, so [`C2SPacket`] can dispatch both.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContLogin(pub Login);

impl Packet for Login {
    const TYPE: u8 = kind::LOGIN;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        Login::decode(data)
    }
    fn encode(&self, out: &mut Vec<u8>) {
        Login::encode(self, out)
    }
}

impl Packet for ContLogin {
    const TYPE: u8 = kind::CONT_LOGIN;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        Login::decode(data).map(Self)
    }
    fn encode(&self, out: &mut Vec<u8>) {
        Login {
            kind: kind::CONT_LOGIN,
            ..self.0.clone()
        }
        .encode(out)
    }
}

packet_enum! {
    /// Any client-to-server game packet.
    C2SPacket {
        /// `0x01`.
        GoArena(GoArena),
        /// `0x02`.
        LeaveArena(LeaveArena),
        /// `0x03`.
        Position(C2SPosition),
        /// `0x05`.
        Death(Death),
        /// `0x06`.
        Chat(C2SChat),
        /// `0x07`.
        TakeGreen(TakeGreen),
        /// `0x08`.
        SpecRequest(SpecRequest),
        /// `0x09`.
        Login(Login),
        /// `0x0A`.
        Rebroadcast(Rebroadcast),
        /// `0x0B`.
        UpdateRequest(UpdateRequest),
        /// `0x0C`.
        MapRequest(MapRequest),
        /// `0x0D`.
        NewsRequest(NewsRequest),
        /// `0x0E`.
        Voice(C2SVoice),
        /// `0x0F`.
        SetFreq(SetFreq),
        /// `0x10`.
        AttachTo(AttachTo),
        /// `0x13`.
        PickupFlag(PickupFlag),
        /// `0x14`.
        TurretKickoff(TurretKickoff),
        /// `0x15`.
        DropFlags(DropFlags),
        /// `0x16`.
        UploadFile(UploadFile),
        /// `0x17`.
        Registration(alloc::boxed::Box<Registration>),
        /// `0x18`.
        SetShip(SetShip),
        /// `0x19`.
        SetBanner(SetBanner),
        /// `0x1A`.
        SecurityResponse(SecurityResponse),
        /// `0x1B`.
        SecurityViolation(SecurityViolation),
        /// `0x1C`.
        DropBrick(DropBrick),
        /// `0x1D`.
        SettingChange(SettingChange),
        /// `0x1E`.
        KothExpired(KothExpired),
        /// `0x1F`.
        ShootBall(ShootBall),
        /// `0x20`.
        PickupBall(PickupBall),
        /// `0x21`.
        Goal(Goal),
        /// `0x24`.
        ContLogin(ContLogin),
        /// `0x32`.
        Damage(C2SDamage),
    }
}

impl From<Registration> for C2SPacket {
    fn from(p: Registration) -> Self {
        Self::Registration(alloc::boxed::Box::new(p))
    }
}
