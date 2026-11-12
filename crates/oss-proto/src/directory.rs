//! Directory server protocol: zone listings for clients, and zone registration
//! from game servers.
//!
//! * Game servers send [`ZoneUpdate`] datagrams (about once a minute) to the
//!   directory server's update port (4991 by default) as plain UDP, with no type
//!   byte and no reply. A 4-byte datagram to the same port is a [`DirPing`],
//!   answered with an 8-byte [`DirPong`]; the directory tells them apart by
//!   length.
//! * Clients connect to port 4990 with the normal transport (`00 01` handshake,
//!   reliable delivery) and send [`ZoneListRequest`]; the reply [`ZoneList`] is
//!   usually large and arrives as big or sized data.

use alloc::vec::Vec;
use core::fmt;

use crate::DecodeError;
use crate::wire::{FixedStr, Reader, Redacted, Wire, Writer};

/// Default port for client zone-list requests.
pub const CLIENT_PORT: u16 = 4990;
/// Default port for server updates and pings.
pub const UPDATE_PORT: u16 = 4991;

/// A game server's registration datagram (no type byte).
///
/// Layout: `u32` IP (must be 0), `u16` port, `u16` players, `u16` score
/// keeping (0 or 1), `u32` version (134), `name[32]`, `password[48]`, then the
/// NUL-terminated description. Fixed part: 94 bytes.
///
/// Directory servers check that the name and password fields end with a NUL,
/// treat only the first 16 password bytes as the password and require bytes
/// 62-93 (the rest of the password field) to be zero.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct ZoneUpdate {
    /// Always sent as 0; the directory uses the datagram's source address.
    pub ip: u32,
    /// Game port.
    pub port: u16,
    /// Current players.
    pub players: u16,
    /// 1 if the zone keeps scores (has a billing server), else 0.
    pub score_keeping: u16,
    /// Server version; directories expect 134.
    pub version: u32,
    /// Zone name.
    pub name: FixedStr<32>,
    /// Directory password (at most 15 characters are significant).
    pub password: FixedStr<48>,
    /// Zone description (sent NUL-terminated; ASSS caps it at 385 bytes).
    pub description: Vec<u8>,
}

/// Written by hand so the directory password never reaches a log; every other
/// field prints as it would from `derive`. See [`Redacted`].
impl fmt::Debug for ZoneUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneUpdate")
            .field("ip", &self.ip)
            .field("port", &self.port)
            .field("players", &self.players)
            .field("score_keeping", &self.score_keeping)
            .field("version", &self.version)
            .field("name", &self.name)
            .field("password", &Redacted)
            .field("description", &self.description)
            .finish()
    }
}

impl ZoneUpdate {
    /// Length of the fixed fields.
    pub const FIXED_LEN: usize = 94;

    /// Decodes a datagram. Fails if it is shorter than the fixed part.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(data, 0);
        Ok(Self {
            ip: r.u32()?,
            port: r.u16()?,
            players: r.u16()?,
            score_keeping: r.u16()?,
            version: r.u32()?,
            name: r.fixed()?,
            password: r.fixed()?,
            description: r.cstr(),
        })
    }

    /// Appends the datagram.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.ip);
        out.put_u16(self.port);
        out.put_u16(self.players);
        out.put_u16(self.score_keeping);
        out.put_u32(self.version);
        self.name.write(out);
        self.password.write(out);
        out.put_cstr(&self.description);
    }

    /// Checks the rules directory servers apply before accepting an update.
    pub fn is_acceptable(&self) -> bool {
        self.ip == 0
            && self.score_keeping <= 1
            && self.name.0[31] == 0
            && self.password.0[15] == 0
            && self.password.0[16..].iter().all(|&b| b == 0)
            && !self.name.as_bytes().is_empty()
    }
}

/// A 4-byte ping to the update port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirPing {
    /// Opaque value echoed in the pong (often a timestamp; may be 0).
    pub value: u32,
}

impl DirPing {
    /// Decodes a 4-byte ping.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        if data.len() != 4 {
            return Err(DecodeError::Invalid {
                kind: 0,
                field: "directory ping length",
            });
        }
        Ok(Self {
            value: Reader::new(data, 0).u32()?,
        })
    }
    /// Appends the ping.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.value);
    }
}

/// The 8-byte answer to a [`DirPing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirPong {
    /// First word: one directory implementation sends its zone count here;
    /// another document describes it as the constant 1.
    pub info: u32,
    /// The ping's value, echoed.
    pub value: u32,
}

impl DirPong {
    /// Decodes an 8-byte pong.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        if data.len() != 8 {
            return Err(DecodeError::Invalid {
                kind: 0,
                field: "directory pong length",
            });
        }
        let mut r = Reader::new(data, 0);
        Ok(Self {
            info: r.u32()?,
            value: r.u32()?,
        })
    }
    /// Appends the pong.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u32(self.info);
        out.put_u32(self.value);
    }
}

/// Client request for the zone list: type `0x01`, `u32` minimum players.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZoneListRequest {
    /// Only list zones with at least this many players.
    pub min_players: u32,
}

impl ZoneListRequest {
    /// Type byte.
    pub const TYPE: u8 = 0x01;

    /// Decodes the request.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = crate::wire::expect_type(data, Self::TYPE)?;
        Ok(Self {
            min_players: r.u32()?,
        })
    }
    /// Appends the request.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_u32(self.min_players);
    }
}

/// One zone in a [`ZoneList`].
///
/// Layout: `u32` IPv4 address in network byte order (as raw bytes), `u16`
/// port, `u16` players, `u8` score keeping, `u8` hop count, `u32` version,
/// `name[64]`, NUL-terminated description. Fixed part: 78 bytes. (Some servers
/// write score keeping as a `u16`, leaving the hop count 0, and pad a 32-byte
/// name with zeros to 64.)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZoneEntry {
    /// IPv4 address bytes, a.b.c.d.
    pub ip: [u8; 4],
    /// Game port.
    pub port: u16,
    /// Players.
    pub players: u16,
    /// 1 if the zone keeps scores.
    pub score_keeping: u8,
    /// Directory hop count (how many directories relayed the entry).
    pub hop_count: u8,
    /// Server version.
    pub version: u32,
    /// Zone name.
    pub name: FixedStr<64>,
    /// Description.
    pub description: Vec<u8>,
}

/// Zone list reply: type `0x01`, then entries to the end of the packet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZoneList {
    /// The zones.
    pub zones: Vec<ZoneEntry>,
}

impl ZoneList {
    /// Type byte.
    pub const TYPE: u8 = 0x01;
    /// Fixed size of one entry before its description.
    pub const ENTRY_FIXED_LEN: usize = 78;

    /// Decodes the list. Trailing bytes too short for a whole entry end the list.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = crate::wire::expect_type(data, Self::TYPE)?;
        let mut zones = Vec::new();
        while r.remaining() >= Self::ENTRY_FIXED_LEN {
            zones.push(ZoneEntry {
                ip: r.array()?,
                port: r.u16()?,
                players: r.u16()?,
                score_keeping: r.u8()?,
                hop_count: r.u8()?,
                version: r.u32()?,
                name: r.fixed()?,
                description: r.cstr(),
            });
        }
        Ok(Self { zones })
    }

    /// Appends the list.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        for z in &self.zones {
            out.put_bytes(&z.ip);
            out.put_u16(z.port);
            out.put_u16(z.players);
            out.put_u8(z.score_keeping);
            out.put_u8(z.hop_count);
            out.put_u32(z.version);
            z.name.write(out);
            out.put_cstr(&z.description);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_update() {
        let u = ZoneUpdate {
            port: 5000,
            players: 42,
            score_keeping: 1,
            version: 134,
            name: "Test Zone".into(),
            password: "cane".into(),
            description: b"A zone for testing".to_vec(),
            ..Default::default()
        };
        let mut b = Vec::new();
        u.encode(&mut b);
        assert_eq!(b.len(), ZoneUpdate::FIXED_LEN + 19);
        // Name at 14, password at 46, description at 94.
        assert_eq!(&b[14..18], b"Test");
        assert_eq!(&b[46..50], b"cane");
        assert_eq!(&b[94..96], b"A ");
        let back = ZoneUpdate::decode(&b).unwrap();
        assert_eq!(back, u);
        assert!(back.is_acceptable());
        let long_pw = ZoneUpdate {
            password: "0123456789abcdefXYZ".into(),
            ..u
        };
        assert!(!long_pw.is_acceptable());
        assert!(ZoneUpdate::decode(&b[..93]).is_err());
    }

    #[test]
    fn ping_pong() {
        let mut b = Vec::new();
        DirPing { value: 7 }.encode(&mut b);
        assert_eq!(DirPing::decode(&b).unwrap().value, 7);
        let mut b = Vec::new();
        DirPong { info: 3, value: 7 }.encode(&mut b);
        assert_eq!(DirPong::decode(&b).unwrap(), DirPong { info: 3, value: 7 });
        assert!(DirPing::decode(&[0; 5]).is_err());
        assert!(DirPong::decode(&[0; 4]).is_err());
    }

    #[test]
    fn zone_list() {
        let list = ZoneList {
            zones: alloc::vec![
                ZoneEntry {
                    ip: [127, 0, 0, 1],
                    port: 5000,
                    players: 10,
                    score_keeping: 1,
                    hop_count: 0,
                    version: 134,
                    name: "One".into(),
                    description: b"first".to_vec(),
                },
                ZoneEntry {
                    ip: [10, 0, 0, 2],
                    name: "Two".into(),
                    ..Default::default()
                },
            ],
        };
        let mut b = Vec::new();
        list.encode(&mut b);
        assert_eq!(b.len(), 1 + 78 + 6 + 78 + 1);
        assert_eq!(ZoneList::decode(&b).unwrap(), list);
        let mut req = Vec::new();
        ZoneListRequest { min_players: 3 }.encode(&mut req);
        assert_eq!(req, [1, 3, 0, 0, 0]);
        assert_eq!(ZoneListRequest::decode(&req).unwrap().min_players, 3);
    }
}
