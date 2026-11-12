//! Generates `docs/protocol/packets/`: one page per implemented packet, with
//! its layout, notes and the evidence behind it (see `verification.md`).
//!
//! Fixed-layout packets are rendered from the codec's own field metadata
//! (`FIELDS`), so their pages cannot drift from the code; the others carry
//! hand-written layouts. The test fails if a page is stale, or if a packet that
//! appears in the conformance vectors has no page. Regenerate with
//! `OSS_REGEN_DOCS=1 cargo test -p oss-proto --test protocol_pages`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use oss_proto::wire::Field;
use oss_proto::{c2s, s2c};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Dir {
    S2C,
    C2S,
    Core,
    S2B,
    B2S,
    Directory,
}

impl Dir {
    fn slug(self) -> &'static str {
        match self {
            Dir::S2C => "s2c",
            Dir::C2S => "c2s",
            Dir::Core => "core",
            Dir::S2B => "s2b",
            Dir::B2S => "b2s",
            Dir::Directory => "dir",
        }
    }
    fn title(self) -> &'static str {
        match self {
            Dir::S2C => "S2C",
            Dir::C2S => "C2S",
            Dir::Core => "Core",
            Dir::S2B => "Zone → biller",
            Dir::B2S => "Biller → zone",
            Dir::Directory => "Directory",
        }
    }
    fn direction(self) -> &'static str {
        match self {
            Dir::S2C => "server → client",
            Dir::C2S => "client → server",
            Dir::Core => "both directions (transport layer)",
            Dir::S2B => "zone → billing server",
            Dir::B2S => "billing server → zone",
            Dir::Directory => "see below",
        }
    }
    fn overview(self) -> &'static str {
        match self {
            Dir::S2C | Dir::C2S => "[game-packets.md](../game-packets.md)",
            Dir::Core => "[transport.md](../transport.md)",
            Dir::S2B | Dir::B2S => "[billing.md](../billing.md)",
            Dir::Directory => "[directory.md](../directory.md)",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Level {
    Vectors,
    Sources,
    Partly,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Vectors => "Vectors",
            Level::Sources => "Sources",
            Level::Partly => "Partly inferred",
        }
    }
}

/// One packet page.
struct Page {
    dir: Dir,
    /// Type byte (core: the subtype after `00`; directory: a page index).
    ty: u8,
    name: &'static str,
    rust: &'static str,
    /// Lengths; `None` for fixed packets (computed).
    lengths: Option<&'static str>,
    /// Field metadata of a fixed-layout packet.
    fixed: Option<&'static [Field]>,
    /// Hand-written layout: `offset|size|type|field|meaning` per line, type
    /// byte included.
    rows: &'static str,
    notes: &'static str,
    level: Level,
    evidence: &'static str,
}

const S2C_SOURCES: &str = "Defined by the reference server and listed in the SubSpace 1.35 client's packet handler table; round-trip and property tests in oss-core.";
const S2C_CONT: &str = "Continuum-era packet, beyond the 1.35 client's handler table: the reference server and Subspace Server .NET; round-trip and property tests in oss-core.";
const C2S_SOURCES: &str = "Defined by the reference server and handled by Subspace Server .NET; round-trip and property tests in oss-core.";
const CORE_SOURCES: &str = "The reference server's transport and the 1.35 control-packet table; exercised live by the conformance suite's transport checks.";
const BILL_SOURCES: &str = "The reference server's billing client, Subspace Server .NET and the billing protocol write-up; not among the reference vectors.";
const BILL_VECTORS: &str = "Struct size and every field offset checked against the reference server's `packets/billing.h` (vectors in `billing-ssc.txt`).";

macro_rules! fixed {
    ($dir:expr, $ty:path, $rust:literal, $name:literal, $level:expr, $evidence:expr, $notes:literal) => {
        Page {
            dir: $dir,
            ty: <$ty as oss_proto::Packet>::TYPE,
            name: $name,
            rust: $rust,
            lengths: None,
            fixed: Some(<$ty>::FIELDS),
            rows: "",
            notes: $notes,
            level: $level,
            evidence: $evidence,
        }
    };
}

#[allow(clippy::too_many_arguments)]
const fn manual(
    dir: Dir,
    ty: u8,
    name: &'static str,
    rust: &'static str,
    lengths: &'static str,
    rows: &'static str,
    notes: &'static str,
    level: Level,
    evidence: &'static str,
) -> Page {
    Page {
        dir,
        ty,
        name,
        rust,
        lengths: Some(lengths),
        fixed: None,
        rows,
        notes,
        level,
        evidence,
    }
}

use Dir::*;
use Level::*;

fn pages() -> Vec<Page> {
    vec![
        // ---- server to client -----------------------------------------------------
        manual(
            S2C,
            0x01,
            "your player id",
            "s2c::PlayerId",
            "3, or 4 to 19",
            "0|1|u8|type|`0x01`\n1|2|i16|pid|Your player id.\n3|n|char[]|arena|Optional: the arena's name and its NUL",
            "First packet of the arena entry sequence; the client treats it as a reset of arena state. The reference server sends the 3-byte form. Anything after the id is the arena's name: Continuum treats the packet's last byte as the terminator whatever it holds, so 4 bytes is an empty name, and it drops a packet longer than 19 bytes, so names are at most 15 bytes. Continuum looks for files in a folder named after the arena before the zone's own folder, and saves and restores ships (`AllowSavedShips`) only while the name is empty, i.e. in a public arena. The 3-byte form leaves it with the name it asked for in C2S `0x01`, which is wrong when the server placed the player somewhere else. oss-server sends the 3-byte form, as the reference server does.",
            Partly,
            "The 3-byte form from the reference server and Subspace Server .NET. The name form and Continuum's handling of it are from the QS protocol reference (poid.be/subspace/protocols) and are not yet checked here. Round-trip and property tests in oss-core.",
        ),
        fixed!(
            S2C,
            s2c::EnteringArena,
            "s2c::EnteringArena",
            "arena entered",
            Sources,
            S2C_SOURCES,
            "Last packet of the arena entry sequence: the client may start playing. The conformance suite's live checks expect it after the player id, settings and player list."
        ),
        manual(
            S2C,
            0x03,
            "player entering",
            "s2c::PlayerEntering",
            "64 × n",
            "0|1|u8|type|`0x03`, repeated at the start of every record\n1|1|i8|ship|0–7, 8 = spectator\n2|1|u8|accept_audio|Accepts voice messages.\n3|20|char[20]|name|NUL-padded; may lack a NUL\n23|20|char[20]|squad|NUL-padded; may lack a NUL\n43|4|i32|kill_points|\n47|4|i32|flag_points|\n51|2|i16|pid|\n53|2|i16|freq|\n55|2|i16|wins|\n57|2|i16|losses|\n59|2|i16|attached_to|Turret host, −1 none\n61|2|i16|flags_carried|\n63|1|u8|misc|Bit 0 has a crown, bit 1 send damage reports for this player",
            "Several 64-byte records may be concatenated; each starts with its own `0x03`. Offsets are within one record.",
            Sources,
            S2C_SOURCES,
        ),
        fixed!(
            S2C,
            s2c::PlayerLeaving,
            "s2c::PlayerLeaving",
            "player leaving",
            Sources,
            S2C_SOURCES,
            ""
        ),
        manual(
            S2C,
            0x05,
            "weapon / large position",
            "position::S2CWeapon",
            "21, 23 or 31",
            "0|1|u8|type|`0x05`\n1|1|i8|rotation|0–39\n2|2|u16|time|Low 16 bits of the server time (ticks)\n4|2|i16|x|Pixels\n6|2|i16|y_speed|\n8|2|u16|player_id|\n10|2|i16|x_speed|\n12|1|u8|checksum|XOR of bytes 0–20 with this byte taken as 0\n13|1|u8|status|Status bits\n14|1|u8|c2s_latency|Ticks\n15|2|i16|y|Pixels\n17|2|u16|bounty|\n19|2|u16|weapon|Weapon word\n21|0, 2 or 10|tail|tail|Nothing, energy (`u16`), or extra position data",
            "Servers use this form when a weapon was fired or the pid or bounty does not fit in a byte; otherwise `0x28`. The tail is chosen per recipient.",
            Vectors,
            "Checksum byte checked against 40 packets from the reference server (`position-checksum.txt`); layout from sources.",
        ),
        fixed!(
            S2C,
            s2c::Kill,
            "s2c::Kill",
            "kill",
            Sources,
            S2C_SOURCES,
            ""
        ),
        manual(
            S2C,
            0x07,
            "chat",
            "s2c::S2CChat",
            "6 or more",
            "0|1|u8|type|`0x07`\n1|1|u8|kind|Chat type (0 arena … 9 channel)\n2|1|u8|sound|0 = none\n3|2|i16|pid|Sender, −1 none\n5|n|char[]|text|NUL-terminated",
            "Remote private messages arrive as `(name)>text` with pid −1; channel messages as `n;text`. Chat types are listed in [game-packets.md](../game-packets.md#chat-types).",
            Sources,
            S2C_SOURCES,
        ),
        fixed!(
            S2C,
            s2c::Green,
            "s2c::Green",
            "prize taken",
            Sources,
            S2C_SOURCES,
            ""
        ),
        fixed!(
            S2C,
            s2c::ScoreUpdate,
            "s2c::ScoreUpdate",
            "score",
            Sources,
            S2C_SOURCES,
            ""
        ),
        fixed!(
            S2C,
            s2c::LoginResponse,
            "s2c::LoginResponse",
            "login response",
            Sources,
            S2C_SOURCES,
            "Result codes are listed in [game-packets.md](../game-packets.md#login-response-0x0a-36-bytes). An exe checksum and code checksum both `0xFFFFFFFF` mark the user as staff."
        ),
        fixed!(
            S2C,
            s2c::SoccerGoal,
            "s2c::SoccerGoal",
            "soccer goal",
            Sources,
            S2C_SOURCES,
            ""
        ),
        manual(
            S2C,
            0x0C,
            "voice",
            "s2c::S2CVoice",
            "3 or more",
            "0|1|u8|type|`0x0C`\n1|2|i16|pid|Sender\n3|n|bytes|data|Compressed WAV",
            "",
            Partly,
            "Layout from sources; the voice payload is opaque here.",
        ),
        fixed!(
            S2C,
            s2c::FreqChange,
            "s2c::FreqChange",
            "frequency change",
            Partly,
            "Layout from sources; servers send `0xFF` in the last byte and some clients read a ship there.",
            ""
        ),
        fixed!(
            S2C,
            s2c::Turret,
            "s2c::Turret",
            "turret",
            Sources,
            S2C_SOURCES,
            ""
        ),
        manual(
            S2C,
            0x0F,
            "arena settings",
            "ClientSettings",
            "1428",
            "0|1|u8|type|`0x0F`\n1|1427|settings|settings|See [settings.md](../settings.md)",
            "",
            Vectors,
            "Two complete packets built by the reference server re-encode byte for byte, and the bit position of every named key (846 per configuration) matches (`clientset-*.txt`).",
        ),
        manual(
            S2C,
            0x10,
            "incoming file",
            "s2c::IncomingFile",
            "17 or more",
            "0|1|u8|type|`0x10`\n1|16|char[16]|name|All zero = the news file (zlib)\n17|n|bytes|data|",
            "",
            Sources,
            S2C_SOURCES,
        ),
        fixed!(
            S2C,
            s2c::FlagLocation,
            "s2c::FlagLocation",
            "flag location",
            Sources,
            S2C_SOURCES,
            "Coordinates are in tiles."
        ),
        fixed!(
            S2C,
            s2c::FlagPickup,
            "s2c::FlagPickup",
            "flag pickup",
            Sources,
            S2C_SOURCES,
            ""
        ),
        fixed!(
            S2C,
            s2c::FlagVictory,
            "s2c::FlagVictory",
            "flag victory",
            Sources,
            S2C_SOURCES,
            ""
        ),
        fixed!(
            S2C,
            s2c::TurretKickoff,
            "s2c::TurretKickoff",
            "turret kickoff",
            Sources,
            S2C_SOURCES,
            ""
        ),
        fixed!(
            S2C,
            s2c::FlagDrop,
            "s2c::FlagDrop",
            "flag drop",
            Sources,
            S2C_SOURCES,
            ""
        ),
        fixed!(
            S2C,
            s2c::Security,
            "s2c::Security",
            "security / seeds",
            Sources,
            S2C_SOURCES,
            "A key of 0 delivers seeds only; any other key asks for a C2S `0x1A` security response. The conformance suite's live client checks verify the response."
        ),
        fixed!(
            S2C,
            s2c::RequestFile,
            "s2c::RequestFile",
            "request file",
            Sources,
            S2C_SOURCES,
            ""
        ),
        fixed!(
            S2C,
            s2c::ScoreReset,
            "s2c::ScoreReset",
            "score reset",
            Sources,
            "The SubSpace 1.35 client's handler table and Subspace Server .NET call it a score reset; the reference server names the constant `TIMEDGAME` but does not use it.",
            ""
        ),
        fixed!(
            S2C,
            s2c::ShipReset,
            "s2c::ShipReset",
            "ship reset",
            Sources,
            S2C_SOURCES,
            ""
        ),
        manual(
            S2C,
            0x1C,
            "spectator data",
            "s2c::SpecData",
            "2 or 3",
            "0|1|u8|type|`0x1C`\n1|1|u8|extra_data|2-byte form: 1 = append extra position data to your positions\n1|2|i16|pid|3-byte form: this player became a spectator of you",
            "The length selects the form. Continuum accepts only the 2-byte form, and no known server sends the 3-byte one (per the QS protocol reference (poid.be/subspace/protocols)); oss-core decodes it, but nothing should send it.",
            Sources,
            S2C_SOURCES,
        ),
        fixed!(
            S2C,
            s2c::ShipChange,
            "s2c::ShipChange",
            "ship change",
            Sources,
            S2C_SOURCES,
            ""
        ),
        fixed!(
            S2C,
            s2c::BannerToggle,
            "s2c::BannerToggle",
            "banner toggle",
            Partly,
            "Defined by sources, but its meaning is unclear in all of them.",
            ""
        ),
        fixed!(
            S2C,
            s2c::Banner,
            "s2c::Banner",
            "banner",
            Sources,
            S2C_SOURCES,
            "The banner is 12 × 8 palette indices."
        ),
        fixed!(
            S2C,
            s2c::PrizeReceive,
            "s2c::PrizeReceive",
            "prize received",
            Sources,
            S2C_SOURCES,
            ""
        ),
        manual(
            S2C,
            0x21,
            "bricks",
            "s2c::Bricks",
            "1 + 16 × n",
            "0|1|u8|type|`0x21`\n1 + 16i|2|i16|x1|Tiles\n3 + 16i|2|i16|y1|\n5 + 16i|2|i16|x2|\n7 + 16i|2|i16|y2|\n9 + 16i|2|i16|freq|\n11 + 16i|2|u16|id|\n13 + 16i|4|u32|time|Ticks",
            "A 1-byte packet (no bricks) clears all bricks; servers send it during arena entry.",
            Sources,
            S2C_SOURCES,
        ),
        manual(
            S2C,
            0x22,
            "turf flag owners",
            "s2c::TurfFlags",
            "1 + 2 × n",
            "0|1|u8|type|`0x22`\n1 + 2i|2|i16|owner|Frequency owning flag *i*, −1 unowned",
            "",
            Sources,
            S2C_SOURCES,
        ),
        manual(
            S2C,
            0x23,
            "periodic reward",
            "s2c::PeriodicReward",
            "1 + 4 × n",
            "0|1|u8|type|`0x23`\n1 + 4i|2|i16|freq|\n3 + 4i|2|i16|points|",
            "",
            Sources,
            S2C_SOURCES,
        ),
        fixed!(
            S2C,
            s2c::SpeedStats,
            "s2c::SpeedStats",
            "speed game result",
            Partly,
            "Defined by sources but rarely used; field meanings come from a single source.",
            ""
        ),
        fixed!(
            S2C,
            s2c::Ufo,
            "s2c::Ufo",
            "UFO allowed",
            Sources,
            S2C_SOURCES,
            ""
        ),
        fixed!(
            S2C,
            s2c::KeepAlive,
            "s2c::KeepAlive",
            "keep-alive",
            Sources,
            S2C_SOURCES,
            ""
        ),
        manual(
            S2C,
            0x28,
            "small position",
            "position::S2CPosition",
            "16, 18 or 26",
            "0|1|u8|type|`0x28`\n1|1|i8|rotation|0–39\n2|2|u16|time|Low 16 bits of the server time (ticks)\n4|2|i16|x|Pixels\n6|1|u8|c2s_latency|Ticks\n7|1|u8|bounty|Low byte\n8|1|u8|player_id|Low byte\n9|1|u8|status|Status bits\n10|2|i16|y_speed|\n12|2|i16|y|Pixels\n14|2|i16|x_speed|\n16|0, 2 or 10|tail|tail|Nothing, energy (`u16`), or extra position data",
            "Used when no weapon was fired and the pid and bounty fit in a byte; otherwise S2C `0x05`. Has no checksum.",
            Sources,
            S2C_SOURCES,
        ),
        manual(
            S2C,
            0x29,
            "map file names",
            "s2c::MapFilename",
            "21, or 1 + 24 × n",
            "0|1|u8|type|`0x29`\n1|16|char[16]|name|21-byte form: the map\n17|4|u32|checksum|21-byte form: CRC-32 of the uncompressed map\n1 + 24i|16|char[16]|name|Long form: entry 0 is the map, the rest LVZ files\n17 + 24i|4|u32|checksum|Long form: CRC-32 of the file as stored\n21 + 24i|4|u32|size|Long form: total length of the `0x2A` packet that carries it",
            "The client requests entry *i* with C2S `0x0C`. Clients without LVZ support get the 21-byte form.",
            Sources,
            S2C_SOURCES,
        ),
        manual(
            S2C,
            0x2A,
            "map / LVZ data",
            "s2c::MapData",
            "17 or more",
            "0|1|u8|type|`0x2A`\n1|16|char[16]|name|\n17|n|bytes|data|Maps zlib-compressed; LVZ files as stored",
            "Larger than a datagram, so it travels as big or sized data. The conformance suite downloads and checks the map in its live server checks.",
            Sources,
            S2C_SOURCES,
        ),
        fixed!(
            S2C,
            s2c::SetKothTimer,
            "s2c::SetKothTimer",
            "set crown timer",
            Sources,
            S2C_SOURCES,
            ""
        ),
        fixed!(
            S2C,
            s2c::Koth,
            "s2c::Koth",
            "crown",
            Sources,
            S2C_SOURCES,
            ""
        ),
        fixed!(
            S2C,
            s2c::AddKothTime,
            "s2c::AddKothTime",
            "add crown time",
            Sources,
            S2C_SOURCES,
            ""
        ),
        fixed!(
            S2C,
            s2c::BallPosition,
            "s2c::BallPosition",
            "ball",
            Sources,
            S2C_SOURCES,
            ""
        ),
        manual(
            S2C,
            0x2F,
            "arena list",
            "s2c::ArenaList",
            "variable",
            "0|1|u8|type|`0x2F`\n1|n|char[]|name|NUL-terminated; repeated with the population\n…|2|i16|population|Negative for the arena you are in",
            "",
            Sources,
            S2C_SOURCES,
        ),
        manual(
            S2C,
            0x30,
            "ad banner",
            "s2c::AdBanner",
            "10 or more",
            "0|1|u8|type|`0x30`\n1|1|u8|mode|\n2|2|u16|width|\n4|2|u16|height|\n6|4|u32|duration|\n10|n|bytes|data|",
            "Obsolete.",
            Partly,
            "Defined by sources but obsolete; field meanings come from a single source.",
        ),
        fixed!(
            S2C,
            s2c::LoginOk,
            "s2c::LoginOk",
            "login OK",
            Partly,
            "Obsolete; defined by sources.",
            ""
        ),
        fixed!(
            S2C,
            s2c::WarpTo,
            "s2c::WarpTo",
            "warp to",
            Sources,
            S2C_CONT,
            "Coordinates are in tiles."
        ),
        manual(
            S2C,
            0x33,
            "login text",
            "s2c::LoginText",
            "2 or more",
            "0|1|u8|type|`0x33`\n1|n|char[]|text|NUL-terminated",
            "Continuum shows it with login result code 19.",
            Sources,
            S2C_CONT,
        ),
        fixed!(
            S2C,
            s2c::ContVersion,
            "s2c::ContVersion",
            "Continuum version",
            Sources,
            S2C_CONT,
            "Sent to Continuum before the login response."
        ),
        manual(
            S2C,
            0x35,
            "toggle LVZ objects",
            "s2c::ToggleObjects",
            "1 + 2 × n",
            "0|1|u8|type|`0x35`\n1 + 2i|2|u16|toggle|Bits 0–14 object id; bit 15 set = hide",
            "",
            Sources,
            S2C_CONT,
        ),
        manual(
            S2C,
            0x36,
            "change LVZ objects",
            "s2c::MoveObjects",
            "1 + 11 × n",
            "0|1|u8|type|`0x36`\n1 + 11i|1|u8|mask|Bit 0 position, 1 image, 2 layer, 3 time, 4 mode\n2 + 11i|10|object|object|The object record from [lvz](../../formats/lvz.md)",
            "",
            Sources,
            S2C_CONT,
        ),
        fixed!(
            S2C,
            s2c::ToggleDamage,
            "s2c::ToggleDamage",
            "damage reporting",
            Sources,
            S2C_CONT,
            "While on, the client sends C2S `0x32` damage reports."
        ),
        manual(
            S2C,
            0x38,
            "damage",
            "s2c::S2CDamage",
            "7 + 9 × n",
            "0|1|u8|type|`0x38`\n1|2|i16|pid|Player damaged\n3|4|u32|time|Ticks\n7 + 9i|2|i16|attacker|\n9 + 9i|2|u16|weapon|Weapon word\n11 + 9i|2|i16|energy|Before the hit\n13 + 9i|2|i16|damage|\n15 + 9i|1|u8|time_offset|Ticks",
            "",
            Sources,
            S2C_CONT,
        ),
        manual(
            S2C,
            0x39,
            "batched small positions",
            "s2c::BatchedSmallPositions",
            "1 + 10 × n",
            "0|1|u8|type|`0x39`\n1 + 10i|1|u8|pid|\n2 + 10i|2|u16|rotation, time|Rotation in bits 10–15, low 10 bits of the time in 0–9\n4 + 10i|4|u32|x, y, x speed|x in bits 0–13, y in 14–27, x-speed bits 0–3 in 28–31\n8 + 10i|2|u16|y speed, x speed|Signed 14-bit y speed in bits 0–13, x-speed bits 4–5 in 14–15\n10 + 10i|1|i8|x speed|x-speed bits 6–13 (carries the sign)",
            "Only for clients that advertise batched positions.",
            Sources,
            "Continuum-only: Subspace Server .NET and nullspace; not in the reference server. Round-trip and property tests in oss-core.",
        ),
        manual(
            S2C,
            0x3A,
            "batched large positions",
            "s2c::BatchedLargePositions",
            "1 + 11 × n",
            "0|1|u8|type|`0x3A`\n1 + 11i|2|u16|pid, status|pid in bits 0–9, status bits 0–5 in 10–15\n3 + 11i|2|u16|rotation, time|As in `0x39`\n5 + 11i|4|u32|x, y, x speed|As in `0x39`\n9 + 11i|2|u16|y speed, x speed|As in `0x39`\n11 + 11i|1|i8|x speed|As in `0x39`",
            "Only for clients that advertise batched positions.",
            Sources,
            "Continuum-only: Subspace Server .NET and nullspace; not in the reference server. Round-trip and property tests in oss-core.",
        ),
        fixed!(
            S2C,
            s2c::Redirect,
            "s2c::Redirect",
            "redirect",
            Sources,
            S2C_CONT,
            ""
        ),
        manual(
            S2C,
            0x3C,
            "select box",
            "s2c::SelectBox",
            "variable",
            "0|1|u8|type|`0x3C`\n1|n|char[]|title|NUL-terminated\n…|2|i16|value|Repeated with the text\n…|n|char[]|text|NUL-terminated, at most 127 bytes",
            "",
            Sources,
            S2C_CONT,
        ),
        // ---- client to server -----------------------------------------------------
        manual(
            C2S,
            0x01,
            "enter arena",
            "c2s::GoArena",
            "26 or 27",
            "0|1|u8|type|`0x01`\n1|1|u8|ship|8 = spectator\n2|1|i8|allow_audio|Nonzero: accept voice messages. Sources disagree; see notes\n3|1|i8|obscenity_filter|Nonzero: filter chat sent to this player\n4|2|i16|x_res|Screen width\n6|2|i16|y_res|Screen height\n8|2|i16|arena_type|−3 named, −1/−2 any public, ≥ 0 public arena *n*\n10|16|char[16]|arena|For the named type\n26|1|u8|optional_graphics|Continuum only: 1 = download optional LVZ",
            "Sources disagree on offsets 2 and 3. The reference server's `goarena.h` puts the obscenity filter at 2 and allow-audio at 3 in both forms. Subspace Server .NET reads allow-audio at 2 in the 26-byte form and at 3 in the 27-byte Continuum form. The QS protocol reference (poid.be/subspace/protocols) puts allow-audio at 2 in both, citing Continuum's sender and subgame echoing offset 2 as the allow-audio byte of S2C `0x03`. oss-core and oss-server read allow-audio at 2.",
            Sources,
            C2S_SOURCES,
        ),
        fixed!(
            C2S,
            c2s::LeaveArena,
            "c2s::LeaveArena",
            "leave arena",
            Sources,
            C2S_SOURCES,
            ""
        ),
        manual(
            C2S,
            0x03,
            "position",
            "position::C2SPosition",
            "22 or 32",
            "0|1|u8|type|`0x03`\n1|1|i8|rotation|0–39\n2|4|u32|time|Client's estimate of server time (ticks)\n6|2|i16|x_speed|\n8|2|i16|y|Pixels\n10|1|u8|checksum|Makes the XOR of bytes 0–21 zero\n11|1|u8|status|Status bits\n12|2|i16|x|Pixels\n14|2|i16|y_speed|\n16|2|u16|bounty|\n18|2|i16|energy|\n20|2|u16|weapon|Weapon word\n22|10|extra|extra|Extra position data, 32-byte form only (not covered by the checksum)",
            "x = y = −1 means dead, waiting to respawn. Clients add the extra data while S2C `0x1C` (2-byte form) is on.",
            Vectors,
            "Checksum checked against 48 packets from the reference server, 8 of them corrupted (`position-checksum.txt`); the live client checks verify a client's checksums.",
        ),
        fixed!(
            C2S,
            c2s::Death,
            "c2s::Death",
            "death",
            Sources,
            C2S_SOURCES,
            ""
        ),
        manual(
            C2S,
            0x06,
            "chat",
            "c2s::C2SChat",
            "6 or more",
            "0|1|u8|type|`0x06`\n1|1|u8|kind|Chat type\n2|1|u8|sound|\n3|2|i16|target|Player for private and enemy-team messages\n5|n|char[]|text|NUL-terminated",
            "Remote private messages are written `:name:text`.",
            Sources,
            C2S_SOURCES,
        ),
        fixed!(
            C2S,
            c2s::TakeGreen,
            "c2s::TakeGreen",
            "take prize",
            Sources,
            C2S_SOURCES,
            "Coordinates are in tiles."
        ),
        fixed!(
            C2S,
            c2s::SpecRequest,
            "c2s::SpecRequest",
            "spectate",
            Sources,
            C2S_SOURCES,
            ""
        ),
        manual(
            C2S,
            0x09,
            "login (SubSpace)",
            "c2s::Login",
            "101",
            "0|1|u8|type|`0x09`\n1|1|u8|flags|1 = new user\n2|32|char[32]|name|\n34|32|char[32]|password|\n66|4|u32|machine_id|\n70|1|u8|connect_type|4 typical\n71|2|i16|timezone_bias|Minutes\n73|2|u16|unknown1|Unknown\n75|2|u16|client_version|134 for SubSpace\n77|4|i32|field444|Normally 444; one server reads bytes 79–80 as feature flags\n81|4|u32|bound_ip|Client's bound address, host-order dword; 0 for INADDR_ANY\n85|4|u32|permission_id|\n89|4|u32|server_ip|Zone address being dialled, same encoding\n93|2|u16|bound_port|Client's local UDP port\n95|4|u32|redirect_id|From a previous S2C `0x3B`, else 0\n99|1|u8|using_proxy|Non-zero if behind a SOCKS proxy\n100|1|u8|unused|",
            "Servers check the length against the client type negotiated by the encryption handshake.",
            Partly,
            "Layout from sources and a capture of a real client; `unknown1` and the upper half of field 444 are kept raw.",
        ),
        manual(
            C2S,
            0x0A,
            "relay LVZ packet",
            "c2s::Rebroadcast",
            "4 or more",
            "0|1|u8|type|`0x0A`\n1|2|i16|target|−1 = the arena\n3|n|bytes|packet|An S2C `0x35` or `0x36` packet, at least one byte",
            "A 3-byte packet (no inner packet) is invalid; `Rebroadcast::new` refuses it.",
            Sources,
            C2S_SOURCES,
        ),
        fixed!(
            C2S,
            c2s::UpdateRequest,
            "c2s::UpdateRequest",
            "update request",
            Sources,
            C2S_SOURCES,
            ""
        ),
        manual(
            C2S,
            0x0C,
            "file request",
            "c2s::MapRequest",
            "1 or 3",
            "0|1|u8|type|`0x0C`\n1|2|u16|index|Optional index into the S2C `0x29` list (absent = the map)",
            "",
            Sources,
            C2S_SOURCES,
        ),
        fixed!(
            C2S,
            c2s::NewsRequest,
            "c2s::NewsRequest",
            "news request",
            Sources,
            C2S_SOURCES,
            ""
        ),
        manual(
            C2S,
            0x0E,
            "voice",
            "c2s::C2SVoice",
            "4 or more",
            "0|1|u8|type|`0x0E`\n1|1|u8|slot|\n2|2|i16|target|\n4|n|bytes|data|Compressed WAV",
            "",
            Partly,
            "Layout from sources; the voice payload is opaque here.",
        ),
        fixed!(
            C2S,
            c2s::SetFreq,
            "c2s::SetFreq",
            "set frequency",
            Sources,
            C2S_SOURCES,
            ""
        ),
        fixed!(
            C2S,
            c2s::AttachTo,
            "c2s::AttachTo",
            "attach",
            Sources,
            C2S_SOURCES,
            ""
        ),
        fixed!(
            C2S,
            c2s::PickupFlag,
            "c2s::PickupFlag",
            "flag pickup",
            Sources,
            C2S_SOURCES,
            ""
        ),
        fixed!(
            C2S,
            c2s::TurretKickoff,
            "c2s::TurretKickoff",
            "detach turrets",
            Sources,
            C2S_SOURCES,
            ""
        ),
        fixed!(
            C2S,
            c2s::DropFlags,
            "c2s::DropFlags",
            "drop flags",
            Sources,
            C2S_SOURCES,
            ""
        ),
        manual(
            C2S,
            0x16,
            "upload file",
            "c2s::UploadFile",
            "17 or more",
            "0|1|u8|type|`0x16`\n1|16|char[16]|name|\n17|n|bytes|data|",
            "Answers S2C `0x19`.",
            Sources,
            C2S_SOURCES,
        ),
        manual(
            C2S,
            0x17,
            "registration",
            "c2s::Registration",
            "766",
            "0|1|u8|type|`0x17`\n1|32|char[32]|real_name|\n33|64|char[64]|email|\n97|32|char[32]|city|\n129|24|char[24]|state|\n153|1|u8|sex|`M` or `F`\n154|1|u8|age|\n155|1|u8|from_home|\n156|1|u8|from_work|\n157|1|u8|from_school|\n158|4|u32|processor|\n162|2|u16|unknown1|\n164|2|u16|unknown2|\n166|40|char[40]|win_owner|\n206|40|char[40]|win_org|\n246|520|char[40] × 13|hardware|Free-text hardware descriptions",
            "Sent when the login response asks for it.",
            Partly,
            "Layout from sources; the hardware strings are free text whose content varies between clients.",
        ),
        fixed!(
            C2S,
            c2s::SetShip,
            "c2s::SetShip",
            "set ship",
            Sources,
            C2S_SOURCES,
            ""
        ),
        fixed!(
            C2S,
            c2s::SetBanner,
            "c2s::SetBanner",
            "set banner",
            Sources,
            C2S_SOURCES,
            ""
        ),
        manual(
            C2S,
            0x1A,
            "security response",
            "c2s::SecurityResponse",
            "40, 42 or 46",
            "0|1|u8|type|`0x1A`\n1|4|u32|weapon_count|Weapon packets received\n5|4|u32|settings_checksum|\n9|4|u32|exe_checksum|\n13|4|u32|map_checksum|\n17|4|u32|s2c_slow_total|\n21|4|u32|s2c_fast_total|\n25|2|u16|s2c_slow_current|\n27|2|u16|s2c_fast_current|\n29|2|u16|s2c_reliable_out|\n31|2|u16|ping_last|10 ms units\n33|2|u16|ping_average|\n35|2|u16|ping_low|\n37|2|u16|ping_high|\n39|1|u8|slow_frame|\n40|2|i16|timer_drift|Continuum only\n42|4|u32|map_crc32|Continuum, later builds only",
            "The checksum algorithms are in [checksums.md](../checksums.md).\n\nContinuum always sends the timer drift. Build 0.40 stops there, for 42 bytes; later builds append the map CRC-32, for 46. A server must accept both lengths, and must not read an absent CRC as a zero one.",
            Vectors,
            "The settings, map and exe checksums it carries are vector-verified (`clientset-*.txt`, `map-checksum-*.txt`, `vie-exe-checksum.txt`) and checked live by the conformance suite; the Continuum fields come from a single source. The 42-byte form is read from build 0.40's own response builder, which ends by sending 42 bytes out of a buffer it cleared as ten dwords and a word.",
        ),
        manual(
            C2S,
            0x1B,
            "security violation",
            "c2s::SecurityViolation",
            "2 or more",
            "0|1|u8|type|`0x1B`\n1|1|u8|code|\n2|n|bytes|text|Optional",
            "",
            Partly,
            "The trailing message is optional and its contents are not specified.",
        ),
        fixed!(
            C2S,
            c2s::DropBrick,
            "c2s::DropBrick",
            "drop brick",
            Sources,
            C2S_SOURCES,
            "Coordinates are in tiles."
        ),
        manual(
            C2S,
            0x1D,
            "change settings",
            "c2s::SettingChange",
            "variable",
            "0|1|u8|type|`0x1D`\n1|n|char[]|entries|`Section:Key:Value` strings, each NUL-terminated, ended by an empty string",
            "",
            Sources,
            C2S_SOURCES,
        ),
        fixed!(
            C2S,
            c2s::KothExpired,
            "c2s::KothExpired",
            "crown expired",
            Sources,
            C2S_SOURCES,
            ""
        ),
        fixed!(
            C2S,
            c2s::ShootBall,
            "c2s::ShootBall",
            "shoot ball",
            Sources,
            C2S_SOURCES,
            ""
        ),
        fixed!(
            C2S,
            c2s::PickupBall,
            "c2s::PickupBall",
            "pick up ball",
            Sources,
            C2S_SOURCES,
            ""
        ),
        fixed!(
            C2S,
            c2s::Goal,
            "c2s::Goal",
            "goal",
            Sources,
            C2S_SOURCES,
            "Coordinates are in tiles."
        ),
        manual(
            C2S,
            0x24,
            "login (Continuum)",
            "c2s::ContLogin",
            "165",
            "0|1|u8|type|`0x24`\n1|100|login|login|As C2S `0x09` from offset 1\n101|64|bytes|cont_id|Opaque Continuum client id, passed to the billing server",
            "Continuum sends client version 40.",
            Partly,
            "Layout from sources; the Continuum id is opaque.",
        ),
        manual(
            C2S,
            0x32,
            "damage",
            "c2s::C2SDamage",
            "5 + 9 × n",
            "0|1|u8|type|`0x32`\n1|4|u32|time|Ticks\n5 + 9i|9|damage|entries|As in S2C `0x38`",
            "Sent while S2C `0x37` is on.",
            Sources,
            C2S_SOURCES,
        ),
        // ---- core ---------------------------------------------------------------------
        manual(
            Core,
            0x01,
            "connect",
            "CorePacket::Connect",
            "8",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x01`\n2|4|u32|key|Client key\n6|2|u16|protocol|1 SubSpace (VIE), 0x11 Continuum",
            "Never encrypted. Servers create connections only from this packet.",
            Vectors,
            "16 key exchanges from the reference server's VIE module (`vie.txt`); checked live by the conformance suite.",
        ),
        manual(
            Core,
            0x02,
            "connect response",
            "CorePacket::ConnectResponse",
            "6 or 7; 7 or 139 for Continuum",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x02`\n2|4|u32|key|Server key: the negated client key for VIE, the client key itself for no encryption; 0 in the Continuum form\n6|1|u8|extra|VIE: optional, ignored. Continuum: a flag byte\n7|128|bytes|identity|Continuum, 139-byte form only: the biller's SSC id (B2S `0x33`)\n135|4|u32|identity_value|Continuum, 139-byte form only: the biller's rotating identity value",
            "On a VIE link this packet ends the handshake and is never encrypted. The Continuum handshake also ends with it, after `00 10` and `00 11`, but encrypted: 7 bytes from a zone with no biller identity, 139 when the zone passes on the identity its biller sent in B2S `0x33`, which the client checks and to which Continuum password hashes are keyed. oss-core's codec reads the key and the byte after it; the identity is opaque here and not decoded.",
            Vectors,
            "16 key exchanges from the reference server's VIE module, including the edge-case keys (`vie.txt`). The 139-byte Continuum form is from the QS protocol reference (poid.be/subspace/protocols); the 7-byte one has been seen from a real server.",
        ),
        manual(
            Core,
            0x03,
            "reliable",
            "CorePacket::Reliable",
            "7 or more",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x03`\n2|4|i32|seq|Per-direction sequence number from 0\n6|n|packet|payload|One complete packet (game or core)",
            "Acknowledged one by one with `00 04`, delivered in order; a duplicate is acknowledged again but not delivered. See [transport.md](../transport.md#reliable-delivery).",
            Sources,
            CORE_SOURCES,
        ),
        manual(
            Core,
            0x04,
            "ack",
            "CorePacket::Ack",
            "6",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x04`\n2|4|i32|seq|The reliable acknowledged",
            "",
            Sources,
            CORE_SOURCES,
        ),
        manual(
            Core,
            0x05,
            "sync request",
            "CorePacket::SyncRequest",
            "6 or 14",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x05`\n2|4|u32|time|Sender's clock (ticks); before `00 02`, an id to echo back\n6|4|u32|sent|14-byte form: datagrams sent\n10|4|u32|received|14-byte form: datagrams received",
            "The 6-byte form has two roles. In an established session it is an ordinary \
             sync, answered with `00 06` carrying the echoed value and the responder's \
             own clock; clients send the 14-byte form and servers use the counts for \
             loss statistics.\n\nBefore the connection is established it can also be a \
             challenge that gates the connect response: subgame 1.34.14 answers `00 01` \
             with a 6-byte `00 05` and sends nothing further until the client replies \
             `00 06` with that `u32` echoed back, after which `00 02` arrives. Measured \
             against that server: only the first `u32` of the reply is read, so the \
             trailing clock is optional in this role. Why it requires the exchange is \
             not known, and ASSS does not. See \
             [encryption.md](../encryption.md).",
            Sources,
            CORE_SOURCES,
        ),
        manual(
            Core,
            0x06,
            "sync response",
            "CorePacket::SyncResponse",
            "10",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x06`\n2|4|u32|client_time|Echoed from the request\n6|4|u32|server_time|Responder's clock (ticks)",
            "",
            Sources,
            CORE_SOURCES,
        ),
        manual(
            Core,
            0x07,
            "disconnect",
            "CorePacket::Disconnect",
            "2",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x07`",
            "Sent raw instead of `00 02` when a server has no free slot.",
            Sources,
            CORE_SOURCES,
        ),
        manual(
            Core,
            0x08,
            "big data, more follows",
            "CorePacket::ChunkBody",
            "3 or more",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x08`\n2|n|bytes|slice|",
            "Always inside a reliable; the slices up to the `00 09` form one packet.",
            Sources,
            CORE_SOURCES,
        ),
        manual(
            Core,
            0x09,
            "big data, last slice",
            "CorePacket::ChunkTail",
            "3 or more",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x09`\n2|n|bytes|slice|",
            "",
            Sources,
            CORE_SOURCES,
        ),
        manual(
            Core,
            0x0A,
            "sized data",
            "CorePacket::Stream",
            "7 or more",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x0A`\n2|4|i32|total|Size of the whole transfer\n6|n|bytes|slice|",
            "Always inside a reliable. Used for map and LVZ downloads.",
            Sources,
            CORE_SOURCES,
        ),
        manual(
            Core,
            0x0B,
            "sized cancel",
            "CorePacket::StreamCancel",
            "2",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x0B`",
            "",
            Sources,
            CORE_SOURCES,
        ),
        manual(
            Core,
            0x0C,
            "sized cancel ack",
            "CorePacket::StreamCancelAck",
            "2",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x0C`",
            "",
            Sources,
            CORE_SOURCES,
        ),
        manual(
            Core,
            0x0E,
            "cluster",
            "CorePacket::Cluster",
            "4 or more",
            "0|1|u8|core|`0x00`\n1|1|u8|subtype|`0x0E`\n2|1|u8|len|Repeated: length of the next item\n3|len|packet|item|A complete packet",
            "Packs several small packets into one datagram. Checked live by the conformance suite.",
            Sources,
            CORE_SOURCES,
        ),
        // ---- zone to biller -----------------------------------------------------------
        manual(
            S2B,
            0x01,
            "ping",
            "ServerToBiller::Ping",
            "1",
            "0|1|u8|type|`0x01`",
            "",
            Sources,
            BILL_SOURCES,
        ),
        manual(
            S2B,
            0x02,
            "server connect",
            "ServerToBiller::ServerConnect",
            "173",
            "0|1|u8|type|`0x02`\n1|4|u32|server_id|\n5|4|u32|group_id|\n9|4|u32|score_id|\n13|126|char[126]|name|\n139|2|u16|port|\n141|32|char[32]|password|",
            "The first packet on the zone's connection to the biller; the biller never acknowledges it.",
            Vectors,
            BILL_VECTORS,
        ),
        manual(
            S2B,
            0x03,
            "server disconnect",
            "ServerToBiller::ServerDisconnect",
            "1",
            "0|1|u8|type|`0x03`",
            "",
            Sources,
            BILL_SOURCES,
        ),
        manual(
            S2B,
            0x04,
            "user login",
            "ServerToBiller::UserLogin",
            "86 to 342",
            "0|1|u8|type|`0x04`\n1|1|u8|make_new|\n2|4|u8[4]|ip|\n6|32|char[32]|name|\n38|32|char[32]|password|\n70|4|u32|connection_id|\n74|4|u32|machine_id|\n78|2|i16|timezone|\n80|2|u16|timezone_high|\n82|1|u8|unknown|\n83|1|u8|sysop|\n84|2|u16|client_version|\n86|n|bytes|extra|Client data (the 64-byte Continuum id), up to 256 bytes",
            "SubSpace clients send nothing after offset 86. The password is NUL-padded text, except from a Continuum client logging in to a zone on an SSC biller: then it is a 32-byte hash keyed to the biller identity (B2S `0x33`), so keep it as bytes. A client redirected into a non-SSC zone sends 32 zero bytes.",
            Vectors,
            "Every field offset checked against `packets/billing.h`; packets with and without client data as the reference server sends them (`billing-ssc.txt`).",
        ),
        manual(
            S2B,
            0x05,
            "user logoff",
            "ServerToBiller::UserLogoff",
            "15 or 29",
            "0|1|u8|type|`0x05`\n1|4|u32|connection_id|\n5|2|u16|reason|\n7|2|u16|latency|\n9|2|u16|ping|\n11|2|u16|loss_s2c|\n13|2|u16|loss_c2s|\n15|14|score|score|Only if the zone has a saved score: `u16 kills, u16 deaths, u16 flags, u32 points, u32 flag points`",
            "",
            Vectors,
            "Both forms as the reference server sends them, and every field offset (`billing-ssc.txt`). The vectors found that oss-core rejected the 15-byte form; fixed.",
        ),
        manual(
            S2B,
            0x06,
            "remote zone message or permit",
            "ServerToBiller::RemoteZoneMessage, ServerToBiller::RemotePermit",
            "12 or more; 11 or more for a permit",
            "0|1|u8|type|`0x06`\n1|4|u32|connection_id|\n5|4|u32|server_id|The zone that should receive it, by the server id in its ServerConnect\n9|1|u8|kind|`0x01` permit; anything else a message\n10|1|u8|sound|Message only\n11|n|char[]|text|Message only; NUL-terminated\n10|n|char[]|name|Permit only: the player to permit; NUL-terminated",
            "Kind `0x01` asks the biller to send a permit entry (B2S `0x03` kind `0x01`) to the zone with that server id. It has no sound byte, and the biller sends no reply. The billing protocol write-up documents only the message form.",
            Sources,
            "The billing protocol write-up (message form) and the QS protocol reference (poid.be/subspace/protocols) (permit form); round-trip and property tests in oss-core.",
        ),
        manual(
            S2B,
            0x07,
            "remote private",
            "ServerToBiller::UserRemotePrivate",
            "12 or more",
            "0|1|u8|type|`0x07`\n1|4|u32|connection_id|Often `0xFFFFFFFF`\n5|4|u32|group_id|\n9|1|u8|kind|\n10|1|u8|sound|\n11|n|char[]|text|`:name:(from)>msg` or `:#squad:(from)>msg`, NUL-terminated",
            "",
            Vectors,
            BILL_VECTORS,
        ),
        manual(
            S2B,
            0x08,
            "request file",
            "ServerToBiller::RequestFile",
            "2 or more",
            "0|1|u8|type|`0x08`\n1|n|char[]|name|NUL-terminated",
            "",
            Sources,
            BILL_SOURCES,
        ),
        manual(
            S2B,
            0x0D,
            "demographics",
            "ServerToBiller::UserDemographics",
            "5 to 770",
            "0|1|u8|type|`0x0D`\n1|4|u32|connection_id|\n5|n|bytes|data|The C2S `0x17` registration without its type byte, up to 765 bytes",
            "",
            Vectors,
            BILL_VECTORS,
        ),
        manual(
            S2B,
            0x0E,
            "private chat",
            "ServerToBiller::UserPrivateChat",
            "10 or more",
            "0|1|u8|type|`0x0E`\n1|4|u32|source|\n5|4|u32|destination|`0xFFFFFFFF` = a `*` command aimed at nobody\n9|n|char[]|text|NUL-terminated",
            "Already delivered unless it starts with `*`.",
            Sources,
            BILL_SOURCES,
        ),
        manual(
            S2B,
            0x0F,
            "security violation",
            "ServerToBiller::SecurityViolation",
            "6 or more",
            "0|1|u8|type|`0x0F`\n1|4|u32|connection_id|\n5|n|char[]|text|NUL-terminated",
            "",
            Sources,
            BILL_SOURCES,
        ),
        manual(
            S2B,
            0x10,
            "banner",
            "ServerToBiller::UserBanner",
            "101",
            "0|1|u8|type|`0x10`\n1|4|u32|connection_id|\n5|96|bytes|banner|12 × 8 palette indices",
            "",
            Vectors,
            BILL_VECTORS,
        ),
        manual(
            S2B,
            0x11,
            "score",
            "ServerToBiller::UserScore",
            "19",
            "0|1|u8|type|`0x11`\n1|4|u32|connection_id|\n5|14|score|score|`u16 kills, u16 deaths, u16 flags, u32 points, u32 flag points`",
            "",
            Vectors,
            BILL_VECTORS,
        ),
        manual(
            S2B,
            0x12,
            "score-group message",
            "ServerToBiller::UserScoreMessage",
            "12 or more",
            "0|1|u8|type|`0x12`\n1|4|u32|connection_id|\n5|4|u32|score_id|\n9|1|u8|kind|\n10|1|u8|sound|\n11|n|char[]|text|NUL-terminated",
            "",
            Sources,
            BILL_SOURCES,
        ),
        manual(
            S2B,
            0x13,
            "command",
            "ServerToBiller::UserCommand",
            "6 or more",
            "0|1|u8|type|`0x13`\n1|4|u32|connection_id|\n5|n|char[]|text|`?command` text, NUL-terminated",
            "",
            Vectors,
            "Field offsets and a command as the reference server sends it (`billing-ssc.txt`).",
        ),
        manual(
            S2B,
            0x14,
            "channel chat",
            "ServerToBiller::UserChannelChat",
            "38 or more",
            "0|1|u8|type|`0x14`\n1|4|u32|connection_id|\n5|32|char[32]|channel|\n37|n|char[]|text|NUL-terminated",
            "",
            Vectors,
            "Field offsets and a packet as the reference server sends it (`billing-ssc.txt`).",
        ),
        manual(
            S2B,
            0x15,
            "capabilities",
            "ServerToBiller::ServerCapabilities",
            "5",
            "0|1|u8|type|`0x15`\n1|4|u32|flags|Bit 0: multicast channel chat",
            "",
            Vectors,
            "Struct size and a packet as the reference server sends it (`billing-ssc.txt`).",
        ),
        // ---- biller to zone -----------------------------------------------------------
        manual(
            B2S,
            0x01,
            "login response",
            "BillerToServer::UserLogin",
            "178 or 192",
            "0|1|u8|type|`0x01`\n1|1|u8|result|\n2|4|u32|connection_id|\n6|24|char[24]|name|\n30|24|char[24]|squad|\n54|96|bytes|banner|\n150|4|u32|seconds_played|\n154|12|u16[6]|first_login|Year, month, day, hour, minute, second of account creation\n166|4|u32|unused0|\n170|4|u32|user_id|\n174|4|u32|unused1|\n178|14|score|score|Only when the login succeeded",
            "",
            Vectors,
            "Every field offset, and both lengths as the reference server receives them (`billing-ssc.txt`).",
        ),
        manual(
            B2S,
            0x02,
            "shut down the zone",
            "BillerToServer::Shutdown",
            "1",
            "0|1|u8|type|`0x02`",
            "",
            Sources,
            BILL_SOURCES,
        ),
        manual(
            B2S,
            0x03,
            "zone message or permit",
            "BillerToServer::ZoneMessage, BillerToServer::Permit",
            "8 or more; 7 or more for a permit",
            "0|1|u8|type|`0x03`\n1|4|u32|source_server|\n5|1|u8|kind|`0x02` message; `0x01` permit entry\n6|1|u8|sound|Message only\n7|n|char[]|text|Message only: `:target:(from)>msg` is a remote private message; NUL-terminated\n6|n|char[]|name|Permit only: a name to add to this zone's permit list; NUL-terminated",
            "Kind `0x01` is a permit entry, which the biller routes here from another zone's S2B `0x06`. It has no sound byte, so check the kind before reading offset 6. The zone conventionally appends the name to `permit.txt`; there is no reply and no way to revoke it. The reference server acts only on kind `0x02`.",
            Vectors,
            "Struct size and every field offset of the message form checked against the reference server's `packets/billing.h` (vectors in `billing-ssc.txt`). The permit form is from the QS protocol reference (poid.be/subspace/protocols).",
        ),
        manual(
            B2S,
            0x04,
            "recycle the zone",
            "BillerToServer::Recycle",
            "1",
            "0|1|u8|type|`0x04`",
            "",
            Sources,
            BILL_SOURCES,
        ),
        manual(
            B2S,
            0x05,
            "file",
            "BillerToServer::FileTransfer",
            "17 or more",
            "0|1|u8|type|`0x05`\n1|16|char[16]|name|\n17|n|bytes|data|",
            "",
            Sources,
            BILL_SOURCES,
        ),
        manual(
            B2S,
            0x08,
            "kick",
            "BillerToServer::Kick",
            "7",
            "0|1|u8|type|`0x08`\n1|4|u32|connection_id|\n5|2|u16|reason|",
            "",
            Vectors,
            "Struct size, field offsets and a packet (`billing-ssc.txt`).",
        ),
        manual(
            B2S,
            0x09,
            "arena message to one player",
            "BillerToServer::ArenaMessage",
            "6 or more",
            "0|1|u8|type|`0x09`\n1|4|u32|connection_id|\n5|n|char[]|text|NUL-terminated",
            "",
            Vectors,
            BILL_VECTORS,
        ),
        manual(
            B2S,
            0x0A,
            "channel message to one player",
            "BillerToServer::ChannelMessage",
            "7 or more",
            "0|1|u8|type|`0x0A`\n1|4|u32|connection_id|\n5|1|u8|channel|\n6|n|char[]|text|NUL-terminated",
            "",
            Vectors,
            BILL_VECTORS,
        ),
        manual(
            B2S,
            0x31,
            "score reset",
            "BillerToServer::ScoreReset",
            "9",
            "0|1|u8|type|`0x31`\n1|4|u32|score_id|\n5|4|u32|score_id_neg|Must equal `-score_id` (as `i32`)",
            "The reference server ignores the packet unless the two ids agree.",
            Sources,
            "The reference server's `B2S_Scorereset` struct and handler and the billing protocol write-up; not among the compiled vectors.",
        ),
        manual(
            B2S,
            0x32,
            "user packet",
            "BillerToServer::UserPacket",
            "5 or more",
            "0|1|u8|type|`0x32`\n1|4|u32|connection_id|`0xFFFFFFFF` = every player (the reference server refuses that)\n5|n|packet|data|A game packet to forward to the player: 1 to 1024 bytes",
            "The reference server ignores a user packet with no data.",
            Sources,
            "The reference server's `B2S_UserPacket` struct and handler, Subspace Server .NET and the billing protocol write-up; not among the compiled vectors.",
        ),
        manual(
            B2S,
            0x33,
            "biller identity",
            "BillerToServer::Identity",
            "1 or more; 133 in full",
            "0|1|u8|type|`0x33`\n1|128|bytes|ssc_id|Opaque; present when the packet is at least 129 bytes\n129|4|u32|identity_value|Rotating value; present when the packet is at least 133 bytes",
            "`BillingIdentity::parse` splits the payload; the variant keeps it raw. An SSC biller sends the full form after ServerConnect and whenever the value rotates, and keeps the previous value valid for a while so logins in flight still verify. Continuum clients key their password hash (S2B `0x04`) to it, and the zone hands it to them in the Continuum form of core `00 02`. Billers also send it to every zone on a timer (60 s in one implementation) as a keepalive, because the zone's ping (S2B `0x01`) has no reply; those forms may be 1 or 129 bytes. Bytes past 133 are ignored. The reference server keeps up to 256 bytes raw.",
            Sources,
            "The reference server's `B2S_BillingIdentity` struct and handler and the billing protocol write-up; the field split and its uses are from the QS protocol reference (poid.be/subspace/protocols). Not among the compiled vectors.",
        ),
        manual(
            B2S,
            0x34,
            "multicast channel chat",
            "BillerToServer::MultiChannelChat",
            "variable",
            "0|1|u8|type|`0x34`\n1|1|u8|count|\n2 + 5i|4|u32|connection_id|Recipient *i*\n6 + 5i|1|u8|channel|\n2 + 5·count|n|char[]|text|NUL-terminated, right after the last recipient",
            "The reference struct reserves 45 recipients, but the reference server reads the text right after the last one actually present.",
            Vectors,
            BILL_VECTORS,
        ),
        // ---- directory ----------------------------------------------------------------
        manual(
            Directory,
            0,
            "zone registration",
            "directory::ZoneUpdate",
            "95 or more",
            "0|4|u32|ip|Always 0: the directory uses the datagram's source address\n4|2|u16|port|Game port\n6|2|u16|players|\n8|2|u16|score_keeping|1 if the zone has a billing server\n10|4|u32|version|134\n14|32|char[32]|name|\n46|48|char[48]|password|Directories use only 15 characters\n94|n|char[]|description|NUL-terminated",
            "Zone → directory, plain UDP to port 4991 about once a minute: no type byte, no transport framing, no reply. Send from any (ephemeral) port; the directory reads the game port from offset 4 and pings that port + 1 at the sender's address, so the zone must answer pings there.",
            Vectors,
            "7 packets built by the reference server's directory module decode and re-encode byte for byte (`directory.txt`).",
        ),
        manual(
            Directory,
            1,
            "ping and pong",
            "directory::DirPing, DirPong",
            "4 / 8",
            "0|4|u32|value|Ping: any value, echoed\n0|4|u32|info|Pong: informational (zone count in one directory)\n4|4|u32|value|Pong: the ping's value",
            "Plain UDP to port 4991; recognised by length.",
            Sources,
            "The dirserver source and the directory protocol write-up.",
        ),
        manual(
            Directory,
            2,
            "zone list request",
            "directory::ZoneListRequest",
            "5",
            "0|1|u8|type|`0x01`\n1|4|u32|min_players|",
            "Client → directory over the normal transport, port 4990.",
            Sources,
            "The dirserver source and the directory protocol write-up.",
        ),
        manual(
            Directory,
            3,
            "zone list",
            "directory::ZoneList",
            "variable",
            "0|1|u8|type|`0x01`\n1 + …|4|u8[4]|ip|IPv4, network byte order; entries repeat to the end\n…|2|u16|port|\n…|2|u16|players|\n…|1|u8|score_keeping|\n…|1|u8|hop_count|\n…|4|u32|version|\n…|64|char[64]|name|\n…|n|char[]|description|NUL-terminated",
            "Directory → client; usually arrives as big or sized data.",
            Sources,
            "The dirserver source and the directory protocol write-up.",
        ),
    ]
}

fn slug(name: &str) -> String {
    let mut s = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c.to_ascii_lowercase());
        } else if !s.ends_with('-') && !s.is_empty() {
            s.push('-');
        }
    }
    s.trim_end_matches('-').to_owned()
}

fn file_name(p: &Page) -> String {
    match p.dir {
        Directory => format!("dir-{}.md", slug(p.name)),
        d => format!("{}-{:02x}-{}.md", d.slug(), p.ty, slug(p.name)),
    }
}

fn type_label(p: &Page) -> String {
    match p.dir {
        Core => format!("`00 {:02X}`", p.ty),
        Directory => "—".into(),
        _ => format!("`0x{:02X}`", p.ty),
    }
}

/// Conformance vectors that exercise each packet, keyed by (dir, type).
fn conformance_counts() -> BTreeMap<(Dir, u8), usize> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../oss-conformance/vectors");
    let mut m = BTreeMap::new();
    let read = |f: &str| std::fs::read_to_string(format!("{root}/{f}")).unwrap_or_default();
    let byte = |h: &str, i: usize| {
        u8::from_str_radix(h.get(2 * i..2 * i + 2).unwrap_or("00"), 16).unwrap_or(0)
    };
    for line in read("packets.txt").lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // `Unknown` samples show that unknown types pass through unchanged; they
        // are not packets with pages.
        if let [dir, name, h] = f.as_slice()
            && *name != "Unknown"
        {
            let key = match *dir {
                "s2c" => (S2C, byte(h, 0)),
                "c2s" => (C2S, byte(h, 0)),
                _ => (Core, byte(h, 1)),
            };
            *m.entry(key).or_default() += 1;
        }
    }
    for line in read("billing-ssc.txt").lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if let [dir @ ("s2b" | "b2s"), _, _, h] = f.as_slice() {
            let d = if *dir == "s2b" { S2B } else { B2S };
            *m.entry((d, byte(h, 0))).or_default() += 1;
        }
    }
    let dir = read("directory.txt")
        .lines()
        .filter(|l| l.starts_with("update"))
        .count();
    m.insert((Directory, 0), dir);
    let vie = read("vie.txt")
        .lines()
        .filter(|l| l.starts_with("keyexchange"))
        .count();
    *m.entry((Core, 1)).or_default() += vie;
    *m.entry((Core, 2)).or_default() += vie;
    m.insert((S2C, 0x0F), 2);
    let pos = read("position-checksum.txt");
    *m.entry((C2S, 0x03)).or_default() += pos.lines().filter(|l| l.starts_with("c2s")).count();
    *m.entry((S2C, 0x05)).or_default() += pos.lines().filter(|l| l.starts_with("s2c")).count();
    m
}

fn render(p: &Page, counts: &BTreeMap<(Dir, u8), usize>) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# {} {}: {}\n", p.dir.title(), type_label(p), p.name);
    let _ = writeln!(
        s,
        "Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Part of the [packet reference](README.md); overview in {}. Generated by `oss-proto/tests/protocol_pages.rs`.\n",
        p.dir.overview()
    );
    let length = match (p.lengths, p.fixed) {
        (Some(l), _) => l.to_owned(),
        (None, Some(f)) => (1 + f.iter().map(|x| x.size).sum::<usize>()).to_string(),
        _ => "?".into(),
    };
    let _ = writeln!(s, "| | |\n|---|---|");
    let _ = writeln!(s, "| Direction | {} |", p.dir.direction());
    let _ = writeln!(s, "| Type | {} |", type_label(p));
    let _ = writeln!(s, "| Length | {length} bytes |");
    let _ = writeln!(s, "| oss-proto | `{}` |", p.rust);
    let _ = writeln!(s, "| Evidence | **{}** |", p.level.label());
    let n = counts.get(&(p.dir, p.ty)).copied().unwrap_or(0);
    let conf = if n == 0 {
        "not in the offline vectors".to_owned()
    } else {
        format!(
            "{n} vector{} in [`oss-conformance`](../../conformance.md)",
            if n == 1 { "" } else { "s" }
        )
    };
    let _ = writeln!(s, "| Conformance | {conf} |\n");
    let _ = writeln!(s, "## Layout\n");
    let _ = writeln!(
        s,
        "| Offset | Size | Type | Field | Meaning |\n|---|---|---|---|---|"
    );
    if let Some(fields) = p.fixed {
        let _ = writeln!(s, "| 0 | 1 | u8 | type | `0x{:02X}` |", p.ty);
        for (off, f) in Field::offsets(fields) {
            let ty: String = f.ty.split_whitespace().collect();
            // Rustdoc intra-doc links (``[`name`]``) become plain code.
            let doc = f.doc.trim().replace("[`", "`").replace("`]", "`");
            let _ = writeln!(s, "| {off} | {} | {ty} | {} | {doc} |", f.size, f.name);
        }
    } else {
        for row in p.rows.lines() {
            let c: Vec<&str> = row.splitn(5, '|').collect();
            assert_eq!(c.len(), 5, "{}: bad row {row}", p.name);
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} | {} |",
                c[0], c[1], c[2], c[3], c[4]
            );
        }
    }
    s.push_str("\nIntegers are little-endian. `n` is a variable length; `i` counts repeated entries from 0.\n");
    if !p.notes.is_empty() {
        let _ = writeln!(s, "\n## Notes\n\n{}", p.notes);
    }
    let _ = writeln!(
        s,
        "\n## Evidence\n\n**{}.** {} See [verification.md](../verification.md) for the levels.",
        p.level.label(),
        p.evidence
    );
    s
}

fn index(pages: &[Page]) -> String {
    let mut s = String::new();
    s.push_str("# Packet reference\n\nLicence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Generated by `oss-proto/tests/protocol_pages.rs`.\n\n");
    s.push_str("One page per packet that oss-core implements, with its byte layout and the evidence behind it. Fixed-layout game packets are rendered from the codec's own field metadata (`FIELDS`). Evidence levels:\n\n");
    s.push_str("- **Vectors**: checked byte for byte against an unmodified reference implementation;\n- **Sources**: agrees with the reference server and at least one other source;\n- **Partly inferred**: some fields' meaning is unknown (named on the page).\n\nSee [verification.md](../verification.md). This project's own protocols have their own specifications: [opensec.md](../opensec.md) and [websocket-relay.md](../websocket-relay.md).\n");
    let mut by_level: BTreeMap<Level, usize> = BTreeMap::new();
    for p in pages {
        *by_level.entry(p.level).or_default() += 1;
    }
    let _ = writeln!(
        s,
        "\n{} pages: {}.",
        pages.len(),
        by_level
            .iter()
            .map(|(l, n)| format!("{n} {}", l.label().to_lowercase()))
            .collect::<Vec<_>>()
            .join(", ")
    );
    for d in [S2C, C2S, Core, S2B, B2S, Directory] {
        let _ = writeln!(
            s,
            "\n## {}\n\n| Type | Packet | Evidence |\n|---|---|---|",
            d.title()
        );
        for p in pages.iter().filter(|p| p.dir == d) {
            let _ = writeln!(
                s,
                "| {} | [{}]({}) | {} |",
                type_label(p),
                p.name,
                file_name(p),
                p.level.label()
            );
        }
    }
    s
}

#[test]
fn protocol_pages_are_current() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/protocol/packets");
    let regen = std::env::var_os("OSS_REGEN_DOCS").is_some();
    if !regen && !std::path::Path::new(dir).exists() {
        eprintln!("skipped: {dir} not present");
        return;
    }
    let pages = pages();
    // No duplicates.
    let mut seen = BTreeSet::new();
    for p in &pages {
        assert!(
            seen.insert((p.dir, p.ty)),
            "two pages for {:?} {:#04x}",
            p.dir,
            p.ty
        );
    }
    // Every packet in the conformance vectors has a page.
    let counts = conformance_counts();
    for key in counts.keys() {
        assert!(seen.contains(key), "no page for {:?} {:#04x}", key.0, key.1);
    }
    let mut files = BTreeMap::new();
    for p in &pages {
        files.insert(file_name(p), render(p, &counts));
    }
    files.insert("README.md".into(), index(&pages));
    if regen {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        for (name, text) in &files {
            std::fs::write(format!("{dir}/{name}"), text).unwrap();
        }
    }
    let on_disk: BTreeSet<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        on_disk,
        files.keys().cloned().collect(),
        "page set changed; regenerate with OSS_REGEN_DOCS=1"
    );
    for (name, text) in &files {
        let committed = std::fs::read_to_string(format!("{dir}/{name}"))
            .unwrap()
            .replace("\r\n", "\n");
        assert_eq!(
            &committed, text,
            "{name} is stale; regenerate with OSS_REGEN_DOCS=1"
        );
    }
}
