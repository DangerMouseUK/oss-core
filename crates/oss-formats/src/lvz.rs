//! `.lvz` archives: zlib-compressed sections holding images, replacement
//! graphics/sounds and LVZ object definitions.
//!
//! Layout (little-endian):
//!
//! ```text
//! "CONT" u32 section_count
//! section_count x {
//!     "CONT" u32 decompressed_size u32 file_time u32 compressed_size
//!     file name, NUL-terminated
//!     compressed_size bytes of zlib data (stored raw when the sizes are equal)
//! }
//! ```
//!
//! A section with `file_time == 0` and an empty name holds object definitions
//! ([`ObjectSection`]). Compressed bytes are kept as read, so archives rewrite
//! byte for byte; [`Section::data`] inflates on demand.

use alloc::vec::Vec;

use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::decompress_to_vec_zlib_with_limit;
pub use oss_proto::ObjectData;

use crate::FormatError;
use crate::error::u32_at;

/// `"CONT"` as a little-endian `u32`.
pub const LVZ_MAGIC: u32 = u32::from_le_bytes(*b"CONT");
/// `"CLV1"` object-section magic.
pub const CLV1: [u8; 4] = *b"CLV1";
/// `"CLV2"` object-section magic.
pub const CLV2: [u8; 4] = *b"CLV2";

/// A parsed `.lvz` archive.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lvz {
    /// Sections in file order.
    pub sections: Vec<Section>,
}

/// One archive section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// File name (raw bytes, no NUL); empty for object sections.
    pub name: Vec<u8>,
    /// File timestamp (0 for object sections).
    pub file_time: u32,
    /// Size of the data once inflated.
    pub decompressed_size: u32,
    /// The stored bytes: zlib data, or the plain data when its size equals
    /// `decompressed_size`.
    pub stored: Vec<u8>,
}

impl Section {
    /// Builds a section by compressing `data` (stored raw if compression does not
    /// make it smaller).
    pub fn new(name: &[u8], file_time: u32, data: &[u8]) -> Self {
        let z = compress_to_vec_zlib(data, 9);
        let stored = if z.len() < data.len() {
            z
        } else {
            data.to_vec()
        };
        Self {
            name: name.to_vec(),
            file_time,
            decompressed_size: data.len() as u32,
            stored,
        }
    }

    /// An object-definition section.
    pub fn objects(objects: &ObjectSection) -> Self {
        Self::new(&[], 0, &objects.to_bytes())
    }

    /// Whether this section holds object definitions.
    pub fn is_object_section(&self) -> bool {
        self.file_time == 0 && self.name.is_empty()
    }

    /// The section's contents, inflated if necessary.
    pub fn data(&self) -> Result<Vec<u8>, FormatError> {
        if self.stored.len() == self.decompressed_size as usize {
            return Ok(self.stored.clone());
        }
        let limit = self.decompressed_size as usize;
        let out = decompress_to_vec_zlib_with_limit(&self.stored, limit)
            .map_err(|_| FormatError::Decompress { offset: 0 })?;
        if out.len() != limit {
            return Err(FormatError::Decompress { offset: 0 });
        }
        Ok(out)
    }
}

impl Lvz {
    /// Parses an archive. Section data is not inflated here.
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        if u32_at(data, 0, "LVZ header")? != LVZ_MAGIC {
            return Err(FormatError::BadMagic {
                what: "LVZ header",
                offset: 0,
            });
        }
        let count = u32_at(data, 4, "LVZ header")?;
        let mut pos = 8;
        let mut sections = Vec::new();
        for _ in 0..count {
            let at = pos;
            if u32_at(data, at, "LVZ section")? != LVZ_MAGIC {
                return Err(FormatError::BadMagic {
                    what: "LVZ section",
                    offset: at,
                });
            }
            let decompressed_size = u32_at(data, at + 4, "LVZ section")?;
            let file_time = u32_at(data, at + 8, "LVZ section")?;
            let compressed = u32_at(data, at + 12, "LVZ section")? as usize;
            let name_at = at + 16;
            let rest = data.get(name_at..).unwrap_or(&[]);
            let nul = rest
                .iter()
                .position(|&b| b == 0)
                .ok_or(FormatError::Truncated {
                    what: "LVZ section name",
                    offset: name_at,
                })?;
            let body_at = name_at + nul + 1;
            let stored = data
                .get(body_at..body_at.saturating_add(compressed))
                .ok_or(FormatError::BadLength {
                    what: "LVZ section",
                    offset: at + 12,
                })?;
            sections.push(Section {
                name: rest[..nul].to_vec(),
                file_time,
                decompressed_size,
                stored: stored.to_vec(),
            });
            pos = body_at + compressed;
            // Each section needs at least a 16-byte header and a NUL; stop early on
            // absurd counts.
            if sections.len() as u64 > data.len() as u64 / 17 + 1 {
                return Err(FormatError::BadLength {
                    what: "LVZ section count",
                    offset: 4,
                });
            }
        }
        Ok(Self { sections })
    }

    /// Serialises the archive.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&LVZ_MAGIC.to_le_bytes());
        out.extend_from_slice(&(self.sections.len() as u32).to_le_bytes());
        for s in &self.sections {
            out.extend_from_slice(&LVZ_MAGIC.to_le_bytes());
            out.extend_from_slice(&s.decompressed_size.to_le_bytes());
            out.extend_from_slice(&s.file_time.to_le_bytes());
            out.extend_from_slice(&(s.stored.len() as u32).to_le_bytes());
            out.extend_from_slice(&s.name);
            out.push(0);
            out.extend_from_slice(&s.stored);
        }
        out
    }

    /// Parses every object section.
    pub fn object_sections(&self) -> Result<Vec<ObjectSection>, FormatError> {
        self.sections
            .iter()
            .filter(|s| s.is_object_section())
            .map(|s| ObjectSection::parse(&s.data()?))
            .collect()
    }
}

/// An image referenced by objects: a file in the archive (or a client graphic),
/// cut into an animation of `x_count * y_count` frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDef {
    /// Animation frames across.
    pub x_count: i16,
    /// Animation frames down.
    pub y_count: i16,
    /// Time for one pass through the animation (1/100 s).
    pub animation_time: i16,
    /// Image file name (no NUL).
    pub name: Vec<u8>,
}

/// The decoded contents of an object section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSection {
    /// `CLV1` or `CLV2`.
    pub version: [u8; 4],
    /// Object records.
    pub objects: Vec<ObjectData>,
    /// Images; [`ObjectData::image`] indexes this list.
    pub images: Vec<ImageDef>,
}

impl ObjectSection {
    /// Parses inflated object-section data.
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        let magic = data.get(..4).ok_or(FormatError::Truncated {
            what: "LVZ objects",
            offset: 0,
        })?;
        if magic != CLV1 && magic != CLV2 {
            return Err(FormatError::BadMagic {
                what: "LVZ objects",
                offset: 0,
            });
        }
        let mut version = [0; 4];
        version.copy_from_slice(magic);
        let n_obj = u32_at(data, 4, "LVZ objects")? as usize;
        let n_img = u32_at(data, 8, "LVZ objects")? as usize;
        let obj_end = n_obj
            .checked_mul(ObjectData::LEN)
            .and_then(|n| n.checked_add(12))
            .filter(|&e| e <= data.len())
            .ok_or(FormatError::BadLength {
                what: "LVZ object count",
                offset: 4,
            })?;
        let objects = data[12..obj_end]
            .as_chunks::<10>()
            .0
            .iter()
            .map(|c| ObjectData::from_bytes(*c))
            .collect();
        let mut pos = obj_end;
        let mut images = Vec::new();
        for _ in 0..n_img {
            let at = pos;
            let head = data.get(at..at + 6).ok_or(FormatError::Truncated {
                what: "LVZ image",
                offset: at,
            })?;
            let rest = &data[at + 6..];
            let nul = rest
                .iter()
                .position(|&b| b == 0)
                .ok_or(FormatError::Truncated {
                    what: "LVZ image name",
                    offset: at + 6,
                })?;
            images.push(ImageDef {
                x_count: i16::from_le_bytes([head[0], head[1]]),
                y_count: i16::from_le_bytes([head[2], head[3]]),
                animation_time: i16::from_le_bytes([head[4], head[5]]),
                name: rest[..nul].to_vec(),
            });
            pos = at + 6 + nul + 1;
        }
        Ok(Self {
            version,
            objects,
            images,
        })
    }

    /// Serialises the section contents (before compression).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version);
        out.extend_from_slice(&(self.objects.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.images.len() as u32).to_le_bytes());
        for o in &self.objects {
            out.extend_from_slice(&o.to_bytes());
        }
        for i in &self.images {
            out.extend_from_slice(&i.x_count.to_le_bytes());
            out.extend_from_slice(&i.y_count.to_le_bytes());
            out.extend_from_slice(&i.animation_time.to_le_bytes());
            out.extend_from_slice(&i.name);
            out.push(0);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Lvz {
        let objs = ObjectSection {
            version: CLV2,
            objects: alloc::vec![
                ObjectData::map(1, 8192, 8192),
                ObjectData::screen(2, 1, -5, 2, 7)
            ],
            images: alloc::vec![
                ImageDef {
                    x_count: 1,
                    y_count: 1,
                    animation_time: 0,
                    name: b"logo.png".to_vec()
                },
                ImageDef {
                    x_count: 4,
                    y_count: 2,
                    animation_time: 100,
                    name: b"anim.bm2".to_vec()
                },
            ],
        };
        let big: Vec<u8> = (0..5000u32).map(|i| (i % 7) as u8).collect();
        Lvz {
            sections: alloc::vec![
                Section::objects(&objs),
                Section::new(b"logo.png", 0x5F00_0000, &big),
                Section::new(b"tiny.txt", 1, b"x"),
            ],
        }
    }

    #[test]
    fn round_trip() {
        let lvz = sample();
        let bytes = lvz.to_bytes();
        let back = Lvz::parse(&bytes).unwrap();
        assert_eq!(back, lvz);
        assert_eq!(back.to_bytes(), bytes);
        // Compressible data is compressed; a 1-byte file is stored raw.
        assert!(back.sections[1].stored.len() < 5000);
        assert_eq!(back.sections[1].data().unwrap().len(), 5000);
        assert_eq!(back.sections[2].stored, b"x");
        assert_eq!(back.sections[2].data().unwrap(), b"x");
        let objs = back.object_sections().unwrap();
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].objects[1].screen_x(), -5);
        assert_eq!(objs[0].images[1].name, b"anim.bm2");
        assert_eq!(ObjectSection::parse(&objs[0].to_bytes()).unwrap(), objs[0]);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Lvz::parse(b"CONT").is_err());
        assert!(Lvz::parse(b"XXXX\0\0\0\0").is_err());
        assert!(Lvz::parse(b"CONT\x01\0\0\0CONT").is_err());
        assert!(Lvz::parse(b"CONT\xff\xff\xff\xff").is_err());
        let mut s = sample().sections.remove(1);
        s.stored[3] ^= 0xFF;
        s.stored.truncate(10);
        assert!(s.data().is_err());
        assert!(ObjectSection::parse(b"CLV1\xff\0\0\0\0\0\0\0").is_err());
        assert!(ObjectSection::parse(b"CLV1\0\0\0\0\x01\0\0\0\x01\0").is_err());
    }
}
