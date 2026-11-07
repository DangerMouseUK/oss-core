//! Replay files (`.ossr`): a recording of the game packets a client saw (and
//! optionally sent), with timestamps, metadata and the map/LVZ files needed to
//! play it back.
//!
//! Layout (little-endian):
//!
//! ```text
//! header (12 bytes): "OSSR", u16 version (1), u16 flags, u32 reserved (0)
//! body: records, or a zlib stream of records when flags bit 0 is set
//! record: u8 kind, u32 time (ms since the recording started), u32 length, data
//! ```
//!
//! Record kinds are listed in [`RecordKind`]; readers skip kinds they do not
//! know. Records are appended as the game runs, so a recording cut short (for
//! example by a crash) still parses up to its last complete record, with
//! [`Replay::truncated`] set.
//!
//! Playing back means feeding each [`RecordKind::ServerPacket`] record, at its
//! time, to the same code that handles packets from a live connection.

use alloc::vec::Vec;

use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::decompress_to_vec_zlib_with_limit;

use crate::FormatError;
use crate::error::u32_at;

/// File signature.
pub const REPLAY_MAGIC: [u8; 4] = *b"OSSR";
/// Current format version.
pub const REPLAY_VERSION: u16 = 1;
/// Header flag: the body is zlib-compressed.
pub const FLAG_COMPRESSED: u16 = 0x0001;
/// Header size.
pub const HEADER_LEN: usize = 12;
/// Record header size (kind, time, length).
pub const RECORD_HEADER_LEN: usize = 9;
/// Largest body inflated when reading a compressed replay (1 GiB).
pub const MAX_INFLATED: usize = 1 << 30;

/// What a record holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// `0x01`: metadata, UTF-8 `key=value` (e.g. `zone`, `arena`, `player`,
    /// `client`, `started` as an RFC 3339 timestamp, `map`).
    Meta,
    /// `0x02`: a complete game packet received from the server, as delivered by
    /// the transport (after reliable/cluster/big/sized unwrapping).
    ServerPacket,
    /// `0x03`: a complete game packet the recording client sent.
    ClientPacket,
    /// `0x04`: a file the replay needs (map or LVZ): `u8` name length, name,
    /// then the file contents exactly as stored by the server.
    File,
    /// `0x05`: a bookmark, UTF-8 text.
    Marker,
    /// Any other value; skipped by readers that do not know it.
    Other(u8),
}

impl RecordKind {
    /// The kind byte.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Meta => 0x01,
            Self::ServerPacket => 0x02,
            Self::ClientPacket => 0x03,
            Self::File => 0x04,
            Self::Marker => 0x05,
            Self::Other(k) => k,
        }
    }

    /// Kind from its byte.
    pub fn from_u8(k: u8) -> Self {
        match k {
            0x01 => Self::Meta,
            0x02 => Self::ServerPacket,
            0x03 => Self::ClientPacket,
            0x04 => Self::File,
            0x05 => Self::Marker,
            k => Self::Other(k),
        }
    }
}

/// One record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// What it holds.
    pub kind: RecordKind,
    /// Milliseconds since the recording started.
    pub time_ms: u32,
    /// Payload.
    pub data: Vec<u8>,
}

impl Record {
    /// A metadata record.
    pub fn meta(time_ms: u32, key: &str, value: &str) -> Self {
        let mut data = Vec::with_capacity(key.len() + value.len() + 1);
        data.extend_from_slice(key.as_bytes());
        data.push(b'=');
        data.extend_from_slice(value.as_bytes());
        Self {
            kind: RecordKind::Meta,
            time_ms,
            data,
        }
    }

    /// A file record (`name` is truncated to 255 bytes).
    pub fn file(time_ms: u32, name: &[u8], contents: &[u8]) -> Self {
        let name = &name[..name.len().min(255)];
        let mut data = Vec::with_capacity(1 + name.len() + contents.len());
        data.push(name.len() as u8);
        data.extend_from_slice(name);
        data.extend_from_slice(contents);
        Self {
            kind: RecordKind::File,
            time_ms,
            data,
        }
    }

    /// For a [`RecordKind::Meta`] record, its key and value.
    pub fn as_meta(&self) -> Option<(&str, &str)> {
        if self.kind != RecordKind::Meta {
            return None;
        }
        core::str::from_utf8(&self.data).ok()?.split_once('=')
    }

    /// For a [`RecordKind::File`] record, its name and contents.
    pub fn as_file(&self) -> Option<(&[u8], &[u8])> {
        if self.kind != RecordKind::File {
            return None;
        }
        let (&n, rest) = self.data.split_first()?;
        (rest.len() >= usize::from(n)).then(|| rest.split_at(usize::from(n)))
    }

    /// Appends the encoded record.
    pub fn write(&self, out: &mut Vec<u8>) {
        write_record(out, self.kind, self.time_ms, &self.data);
    }
}

/// Appends one encoded record (for streaming writers that do not build a
/// [`Record`]).
pub fn write_record(out: &mut Vec<u8>, kind: RecordKind, time_ms: u32, data: &[u8]) {
    out.push(kind.to_u8());
    out.extend_from_slice(&time_ms.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

/// The 12-byte file header for an uncompressed replay. A streaming recorder
/// writes this once and then appends records with [`write_record`].
pub fn header(flags: u16) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(&REPLAY_MAGIC);
    h[4..6].copy_from_slice(&REPLAY_VERSION.to_le_bytes());
    h[6..8].copy_from_slice(&flags.to_le_bytes());
    h
}

/// A parsed replay.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Replay {
    /// Records in file order (times are non-decreasing in well-formed files).
    pub records: Vec<Record>,
    /// Set when the file ended in the middle of a record (the partial record is
    /// dropped).
    pub truncated: bool,
}

impl Replay {
    /// Parses a replay file.
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        if data.len() < HEADER_LEN || data[..4] != REPLAY_MAGIC {
            return Err(FormatError::BadMagic {
                what: "replay header",
                offset: 0,
            });
        }
        let version = u16::from_le_bytes([data[4], data[5]]);
        if version != REPLAY_VERSION {
            return Err(FormatError::BadLength {
                what: "replay version",
                offset: 4,
            });
        }
        let flags = u16::from_le_bytes([data[6], data[7]]);
        let body = &data[HEADER_LEN..];
        if flags & FLAG_COMPRESSED != 0 {
            let inflated = decompress_to_vec_zlib_with_limit(body, MAX_INFLATED)
                .map_err(|_| FormatError::Decompress { offset: HEADER_LEN })?;
            Ok(Self::parse_records(&inflated))
        } else {
            Ok(Self::parse_records(body))
        }
    }

    fn parse_records(body: &[u8]) -> Self {
        let mut records = Vec::new();
        let mut pos = 0;
        let mut truncated = false;
        while pos < body.len() {
            let (Ok(time_ms), Ok(len)) = (
                u32_at(body, pos + 1, "replay record"),
                u32_at(body, pos + 5, "replay record"),
            ) else {
                truncated = true;
                break;
            };
            let start = pos + RECORD_HEADER_LEN;
            let Some(data) = start
                .checked_add(len as usize)
                .and_then(|end| body.get(start..end))
            else {
                truncated = true;
                break;
            };
            records.push(Record {
                kind: RecordKind::from_u8(body[pos]),
                time_ms,
                data: data.to_vec(),
            });
            pos = start + len as usize;
        }
        Self { records, truncated }
    }

    /// Serialises the replay, compressing the body if `compress` is set.
    pub fn to_bytes(&self, compress: bool) -> Vec<u8> {
        let mut body = Vec::new();
        for r in &self.records {
            r.write(&mut body);
        }
        let flags = if compress { FLAG_COMPRESSED } else { 0 };
        let mut out = header(flags).to_vec();
        if compress {
            out.extend(compress_to_vec_zlib(&body, 6));
        } else {
            out.extend(body);
        }
        out
    }

    /// Metadata as (key, value) pairs.
    pub fn meta(&self) -> impl Iterator<Item = (&str, &str)> {
        self.records.iter().filter_map(Record::as_meta)
    }

    /// The first value for metadata `key`.
    pub fn meta_value(&self, key: &str) -> Option<&str> {
        self.meta().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// Embedded files as (name, contents).
    pub fn files(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.records.iter().filter_map(Record::as_file)
    }

    /// Length of the recording (time of the last record).
    pub fn duration_ms(&self) -> u32 {
        self.records.iter().map(|r| r.time_ms).max().unwrap_or(0)
    }

    /// Index of the first record at or after `time_ms`, for seeking.
    pub fn seek(&self, time_ms: u32) -> usize {
        self.records.partition_point(|r| r.time_ms < time_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample() -> Replay {
        Replay {
            records: vec![
                Record::meta(0, "zone", "Test Zone"),
                Record::meta(0, "arena", "duel=1"),
                Record::file(0, b"map.lvl", &[1, 2, 3, 4]),
                Record {
                    kind: RecordKind::ServerPacket,
                    time_ms: 10,
                    data: vec![0x01, 5, 0],
                },
                Record {
                    kind: RecordKind::ClientPacket,
                    time_ms: 15,
                    data: vec![0x03; 22],
                },
                Record {
                    kind: RecordKind::Marker,
                    time_ms: 500,
                    data: b"kill".to_vec(),
                },
                Record {
                    kind: RecordKind::Other(0x7F),
                    time_ms: 600,
                    data: vec![],
                },
                Record {
                    kind: RecordKind::ServerPacket,
                    time_ms: 700,
                    data: vec![0x28; 16],
                },
            ],
            truncated: false,
        }
    }

    #[test]
    fn round_trip_plain_and_compressed() {
        let r = sample();
        for compress in [false, true] {
            let b = r.to_bytes(compress);
            assert_eq!(Replay::parse(&b).unwrap(), r);
        }
        assert_eq!(r.meta_value("zone"), Some("Test Zone"));
        assert_eq!(r.meta_value("arena"), Some("duel=1"));
        assert_eq!(r.files().next(), Some((&b"map.lvl"[..], &[1, 2, 3, 4][..])));
        assert_eq!(r.duration_ms(), 700);
        assert_eq!(r.seek(500), 5);
        assert_eq!(r.seek(501), 6);
    }

    #[test]
    fn streaming_writer_matches() {
        let r = sample();
        let mut out = header(0).to_vec();
        for rec in &r.records {
            write_record(&mut out, rec.kind, rec.time_ms, &rec.data);
        }
        assert_eq!(out, r.to_bytes(false));
    }

    #[test]
    fn truncated_recording_keeps_complete_records() {
        let b = sample().to_bytes(false);
        for cut in 1..20 {
            let p = Replay::parse(&b[..b.len() - cut]).unwrap();
            assert!(p.truncated);
            assert_eq!(p.records.len(), 7);
        }
    }

    #[test]
    fn rejects_bad_files() {
        assert!(Replay::parse(b"OSSR").is_err());
        assert!(Replay::parse(b"XXXX\x01\0\0\0\0\0\0\0").is_err());
        assert!(Replay::parse(b"OSSR\x02\0\0\0\0\0\0\0").is_err());
        assert!(Replay::parse(b"OSSR\x01\0\x01\0\0\0\0\0garbage").is_err());
        // A huge declared length is reported as truncation, not a panic.
        let mut b = header(0).to_vec();
        b.extend_from_slice(&[2, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2]);
        assert!(Replay::parse(&b).unwrap().truncated);
    }
}
