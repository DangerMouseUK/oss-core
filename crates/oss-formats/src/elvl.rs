//! eLVL ("extended level") metadata: a chunked section embedded in `.lvl` files.
//!
//! The section starts with a 12-byte header (`"elvl"`, total size including the
//! header, a reserved word) followed by chunks. Each chunk is a four-character
//! type, a little-endian `u32` data length, the data, and zero padding up to the
//! next multiple of four bytes (padding is not counted in the length).
//!
//! Known chunk types are decoded into [`Chunk`] variants; anything else, and any
//! known chunk whose payload does not have the expected shape, is kept verbatim
//! as [`Chunk::Other`] so files can be rewritten without losing data.

use alloc::string::String;
use alloc::vec::Vec;

use crate::FormatError;
use crate::error::u32_at;
use crate::region::RegionBitmap;

/// `"elvl"` read as a little-endian `u32`.
pub const ELVL_MAGIC: u32 = u32::from_le_bytes(*b"elvl");

/// Size of the metadata section header.
pub const ELVL_HEADER_LEN: usize = 12;

/// The eLVL metadata section of a level file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Metadata {
    /// The header's reserved word (normally 0).
    pub reserved: u32,
    /// Chunks in file order.
    pub chunks: Vec<Chunk>,
}

/// One top-level eLVL chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk {
    /// `ATTR`: a `key=value` text attribute (e.g. `NAME`, `VERSION`, `MAPCREATOR`).
    Attribute {
        /// Text before the first `=`.
        key: String,
        /// Text after the first `=`.
        value: String,
    },
    /// `REGN`: a named region and its properties.
    Region(Region),
    /// `TILE`: plain tile data stored as a chunk (same 4-byte entries as the tile
    /// section of the file). Kept raw; [`crate::Level::tile_grid`] applies it.
    TileData(Vec<u8>),
    /// Any other chunk (including `TSET`), or a known chunk with unexpected contents.
    Other {
        /// Four-character chunk type.
        kind: [u8; 4],
        /// Chunk payload, without padding.
        data: Vec<u8>,
    },
}

/// A region: a set of sub-chunks (`rNAM`, `rTIL`, flags, auto-warp, ...).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Region {
    /// Sub-chunks in file order.
    pub chunks: Vec<RegionChunk>,
}

/// One sub-chunk inside a `REGN` chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionChunk {
    /// `rNAM`: the region's name.
    Name(String),
    /// `rTIL`: the region's tiles, kept in encoded form so files round-trip exactly.
    Tiles(Vec<u8>),
    /// `rBSE`: the region is a base (flag games).
    Base,
    /// `rNAW`: antiwarp does not work here.
    NoAntiwarp,
    /// `rNWP`: weapons do not work here.
    NoWeapons,
    /// `rNFL`: flags dropped here respawn as neutral flags.
    NoFlagDrops,
    /// `rAWP`: players entering are warped to a destination.
    AutoWarp(AutoWarp),
    /// `rPYC`: embedded script text.
    Code(Vec<u8>),
    /// Any other sub-chunk, or a known one with unexpected contents.
    Other {
        /// Four-character sub-chunk type.
        kind: [u8; 4],
        /// Payload, without padding.
        data: Vec<u8>,
    },
}

/// Destination of an auto-warp region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoWarp {
    /// Destination x tile: 1-1023, 0 for the default, -1 to keep the player's x.
    pub x: i16,
    /// Destination y tile, same conventions as `x`.
    pub y: i16,
    /// Destination arena (NUL-padded), or `None` for the same arena.
    pub arena: Option<[u8; 16]>,
}

impl AutoWarp {
    /// The destination arena name, up to its first NUL byte.
    pub fn arena_name(&self) -> Option<&[u8]> {
        self.arena.as_ref().map(|a| {
            let end = a.iter().position(|&b| b == 0).unwrap_or(a.len());
            &a[..end]
        })
    }
}

impl Region {
    /// A region with a name and tiles.
    pub fn new(name: impl Into<String>, tiles: &RegionBitmap) -> Self {
        Self {
            chunks: alloc::vec![
                RegionChunk::Name(name.into()),
                RegionChunk::Tiles(tiles.encode())
            ],
        }
    }

    /// The first `rNAM` value. Regions without a name are ignored by servers.
    pub fn name(&self) -> Option<&str> {
        self.chunks.iter().find_map(|c| match c {
            RegionChunk::Name(n) => Some(n.as_str()),
            _ => None,
        })
    }

    /// Decodes and merges every `rTIL` sub-chunk.
    pub fn tiles(&self) -> Result<RegionBitmap, FormatError> {
        let mut out: Option<RegionBitmap> = None;
        for c in &self.chunks {
            if let RegionChunk::Tiles(data) = c {
                let t = RegionBitmap::decode(data)?;
                match &mut out {
                    None => out = Some(t),
                    Some(acc) => t.iter().for_each(|(x, y)| acc.set(x, y, true)),
                }
            }
        }
        Ok(out.unwrap_or_default())
    }

    fn has(&self, want: &RegionChunk) -> bool {
        self.chunks.iter().any(|c| c == want)
    }

    /// Whether the region is marked as a base.
    pub fn is_base(&self) -> bool {
        self.has(&RegionChunk::Base)
    }

    /// Whether antiwarp is disabled in the region.
    pub fn no_antiwarp(&self) -> bool {
        self.has(&RegionChunk::NoAntiwarp)
    }

    /// Whether weapons are disabled in the region.
    pub fn no_weapons(&self) -> bool {
        self.has(&RegionChunk::NoWeapons)
    }

    /// Whether flags dropped in the region respawn neutral.
    pub fn no_flag_drops(&self) -> bool {
        self.has(&RegionChunk::NoFlagDrops)
    }

    /// The auto-warp destination, if any.
    pub fn auto_warp(&self) -> Option<AutoWarp> {
        self.chunks.iter().find_map(|c| match c {
            RegionChunk::AutoWarp(w) => Some(*w),
            _ => None,
        })
    }
}

impl Metadata {
    /// Iterates over `ATTR` key/value pairs.
    pub fn attributes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.chunks.iter().filter_map(|c| match c {
            Chunk::Attribute { key, value } => Some((key.as_str(), value.as_str())),
            _ => None,
        })
    }

    /// The first value for attribute `key` (case-sensitive).
    pub fn attribute(&self, key: &str) -> Option<&str> {
        self.attributes().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// Iterates over regions.
    pub fn regions(&self) -> impl Iterator<Item = &Region> {
        self.chunks.iter().filter_map(|c| match c {
            Chunk::Region(r) => Some(r),
            _ => None,
        })
    }

    /// Parses a metadata section starting at the `"elvl"` header. Returns the
    /// metadata and the section's total length (the header's `totalsize`).
    pub fn parse(data: &[u8]) -> Result<(Self, usize), FormatError> {
        if u32_at(data, 0, "eLVL header")? != ELVL_MAGIC {
            return Err(FormatError::BadMagic {
                what: "eLVL header",
                offset: 0,
            });
        }
        let total = u32_at(data, 4, "eLVL header")? as usize;
        let reserved = u32_at(data, 8, "eLVL header")?;
        if total < ELVL_HEADER_LEN || total > data.len() {
            return Err(FormatError::BadLength {
                what: "eLVL section",
                offset: 4,
            });
        }
        let mut chunks = Vec::new();
        for raw in RawChunks::new(&data[ELVL_HEADER_LEN..total], ELVL_HEADER_LEN) {
            let (kind, body) = raw?;
            chunks.push(Chunk::decode(kind, body));
        }
        Ok((Self { reserved, chunks }, total))
    }

    /// Serialises the section, header included.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    /// Appends the serialised section to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(&ELVL_MAGIC.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&self.reserved.to_le_bytes());
        for c in &self.chunks {
            c.write(out);
        }
        let total = (out.len() - start) as u32;
        out[start + 4..start + 8].copy_from_slice(&total.to_le_bytes());
    }
}

impl Chunk {
    /// The chunk's four-character type.
    pub fn kind(&self) -> [u8; 4] {
        match self {
            Self::Attribute { .. } => *b"ATTR",
            Self::Region(_) => *b"REGN",
            Self::TileData(_) => *b"TILE",
            Self::Other { kind, .. } => *kind,
        }
    }

    fn decode(kind: [u8; 4], body: &[u8]) -> Self {
        let other = || Self::Other {
            kind,
            data: body.to_vec(),
        };
        match &kind {
            b"ATTR" => {
                let Ok(text) = core::str::from_utf8(body) else {
                    return other();
                };
                match text.split_once('=') {
                    Some((k, v)) => Self::Attribute {
                        key: k.into(),
                        value: v.into(),
                    },
                    None => other(),
                }
            }
            b"REGN" => {
                // Only decode regions that re-encode to the same bytes.
                let mut sub = Vec::new();
                for raw in RawChunks::new(body, 0) {
                    let Ok((k, b)) = raw else { return other() };
                    sub.push(RegionChunk::decode(k, b));
                }
                let region = Region { chunks: sub };
                let mut check = Vec::new();
                region.write_body(&mut check);
                if check == body {
                    Self::Region(region)
                } else {
                    other()
                }
            }
            b"TILE" => Self::TileData(body.to_vec()),
            _ => other(),
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        let kind = self.kind();
        match self {
            Self::Attribute { key, value } => {
                let mut body = Vec::with_capacity(key.len() + value.len() + 1);
                body.extend_from_slice(key.as_bytes());
                body.push(b'=');
                body.extend_from_slice(value.as_bytes());
                write_chunk(out, kind, &body);
            }
            Self::Region(r) => {
                let mut body = Vec::new();
                r.write_body(&mut body);
                write_chunk(out, kind, &body);
            }
            Self::TileData(d) | Self::Other { data: d, .. } => write_chunk(out, kind, d),
        }
    }
}

impl Region {
    fn write_body(&self, out: &mut Vec<u8>) {
        for c in &self.chunks {
            c.write(out);
        }
    }
}

impl RegionChunk {
    /// The sub-chunk's four-character type.
    pub fn kind(&self) -> [u8; 4] {
        match self {
            Self::Name(_) => *b"rNAM",
            Self::Tiles(_) => *b"rTIL",
            Self::Base => *b"rBSE",
            Self::NoAntiwarp => *b"rNAW",
            Self::NoWeapons => *b"rNWP",
            Self::NoFlagDrops => *b"rNFL",
            Self::AutoWarp(_) => *b"rAWP",
            Self::Code(_) => *b"rPYC",
            Self::Other { kind, .. } => *kind,
        }
    }

    fn decode(kind: [u8; 4], body: &[u8]) -> Self {
        let other = || Self::Other {
            kind,
            data: body.to_vec(),
        };
        let flag = |v: Self| if body.is_empty() { v } else { other() };
        match &kind {
            b"rNAM" => match core::str::from_utf8(body) {
                Ok(s) => Self::Name(s.into()),
                Err(_) => other(),
            },
            b"rTIL" => Self::Tiles(body.to_vec()),
            b"rBSE" => flag(Self::Base),
            b"rNAW" => flag(Self::NoAntiwarp),
            b"rNWP" => flag(Self::NoWeapons),
            b"rNFL" => flag(Self::NoFlagDrops),
            b"rAWP" if body.len() == 4 || body.len() == 20 => {
                let x = i16::from_le_bytes([body[0], body[1]]);
                let y = i16::from_le_bytes([body[2], body[3]]);
                let arena = body.get(4..20).map(|a| {
                    let mut buf = [0; 16];
                    buf.copy_from_slice(a);
                    buf
                });
                Self::AutoWarp(AutoWarp { x, y, arena })
            }
            b"rPYC" => Self::Code(body.to_vec()),
            _ => other(),
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        let kind = self.kind();
        match self {
            Self::Name(s) => write_chunk(out, kind, s.as_bytes()),
            Self::Tiles(d) | Self::Code(d) | Self::Other { data: d, .. } => {
                write_chunk(out, kind, d)
            }
            Self::Base | Self::NoAntiwarp | Self::NoWeapons | Self::NoFlagDrops => {
                write_chunk(out, kind, &[])
            }
            Self::AutoWarp(w) => {
                let mut body = Vec::with_capacity(20);
                body.extend_from_slice(&w.x.to_le_bytes());
                body.extend_from_slice(&w.y.to_le_bytes());
                if let Some(a) = &w.arena {
                    body.extend_from_slice(a);
                }
                write_chunk(out, kind, &body);
            }
        }
    }
}

fn write_chunk(out: &mut Vec<u8>, kind: [u8; 4], body: &[u8]) {
    out.extend_from_slice(&kind);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out.resize(out.len() + padding(body.len()), 0);
}

fn padding(len: usize) -> usize {
    (4 - len % 4) % 4
}

/// Iterates over `(type, payload)` pairs in a chunk list. Padding after the final
/// chunk may be missing.
struct RawChunks<'a> {
    data: &'a [u8],
    pos: usize,
    base: usize,
    failed: bool,
}

impl<'a> RawChunks<'a> {
    fn new(data: &'a [u8], base: usize) -> Self {
        Self {
            data,
            pos: 0,
            base,
            failed: false,
        }
    }
}

impl<'a> Iterator for RawChunks<'a> {
    type Item = Result<([u8; 4], &'a [u8]), FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.pos >= self.data.len() {
            return None;
        }
        let at = self.pos;
        let offset = self.base + at;
        let rest = &self.data[at..];
        if rest.len() < 8 {
            self.failed = true;
            return Some(Err(FormatError::Truncated {
                what: "eLVL chunk header",
                offset,
            }));
        }
        let kind = [rest[0], rest[1], rest[2], rest[3]];
        let len = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]) as usize;
        let Some(body) = rest.get(8..8 + len) else {
            self.failed = true;
            return Some(Err(FormatError::BadLength {
                what: "eLVL chunk",
                offset: offset + 4,
            }));
        };
        self.pos = (at + 8 + len + padding(len)).min(self.data.len());
        Some(Ok((kind, body)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Metadata {
        let mut tiles = RegionBitmap::new();
        tiles.set(5, 6, true);
        let mut base = Region::new("base", &tiles);
        base.chunks.push(RegionChunk::Base);
        base.chunks.push(RegionChunk::AutoWarp(AutoWarp {
            x: 512,
            y: -1,
            arena: None,
        }));
        let mut arena = [0; 16];
        arena[..3].copy_from_slice(b"pub");
        let mut warp = Region::new("warp", &tiles);
        warp.chunks.push(RegionChunk::AutoWarp(AutoWarp {
            x: 0,
            y: 0,
            arena: Some(arena),
        }));
        warp.chunks.push(RegionChunk::NoWeapons);
        warp.chunks.push(RegionChunk::Other {
            kind: *b"rXYZ",
            data: alloc::vec![1, 2, 3],
        });
        Metadata {
            reserved: 0,
            chunks: alloc::vec![
                Chunk::Attribute {
                    key: "NAME".into(),
                    value: "Test map".into()
                },
                Chunk::Region(base),
                Chunk::Region(warp),
                Chunk::Other {
                    kind: *b"DCME",
                    data: alloc::vec![9; 5]
                },
            ],
        }
    }

    #[test]
    fn round_trip() {
        let m = sample();
        let bytes = m.to_bytes();
        assert_eq!(bytes.len() % 4, 0);
        let (back, len) = Metadata::parse(&bytes).unwrap();
        assert_eq!(len, bytes.len());
        assert_eq!(back, m);
        assert_eq!(back.to_bytes(), bytes);
        assert_eq!(back.attribute("NAME"), Some("Test map"));
        let regions: Vec<_> = back.regions().collect();
        assert_eq!(regions[0].name(), Some("base"));
        assert!(regions[0].is_base());
        assert!(regions[0].tiles().unwrap().contains(5, 6));
        assert_eq!(
            regions[1].auto_warp().unwrap().arena_name(),
            Some(&b"pub"[..])
        );
        assert!(regions[1].no_weapons() && !regions[1].no_antiwarp());
    }

    #[test]
    fn odd_shapes_stay_raw() {
        // ATTR without '=' and rBSE with a payload are preserved verbatim.
        let mut region_body = Vec::new();
        write_chunk(&mut region_body, *b"rBSE", &[1]);
        let mut m = Vec::new();
        m.extend_from_slice(b"elvl\0\0\0\0\0\0\0\0");
        write_chunk(&mut m, *b"ATTR", b"novalue");
        write_chunk(&mut m, *b"REGN", &region_body);
        let total = m.len() as u32;
        m[4..8].copy_from_slice(&total.to_le_bytes());
        let (back, _) = Metadata::parse(&m).unwrap();
        assert!(matches!(back.chunks[0], Chunk::Other { .. }));
        let Chunk::Region(r) = &back.chunks[1] else {
            panic!()
        };
        assert!(matches!(r.chunks[0], RegionChunk::Other { .. }));
        assert_eq!(back.to_bytes(), m);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Metadata::parse(b"elvl").is_err());
        assert!(Metadata::parse(b"xlvl\x0c\0\0\0\0\0\0\0").is_err());
        assert!(Metadata::parse(b"elvl\x40\0\0\0\0\0\0\0").is_err());
        // Chunk claims more data than the section holds.
        assert!(Metadata::parse(b"elvl\x14\0\0\0\0\0\0\0ATTR\xff\0\0\0").is_err());
    }
}
