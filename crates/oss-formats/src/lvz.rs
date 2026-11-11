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
//!
//! # `CLV1` screen objects
//!
//! An object section is tagged `CLV1` or `CLV2`, and the two do not share a screen
//! layout. [`ObjectData`]'s `CLV2` split is reference index in bits 0-3 and signed
//! 12-bit offset in bits 4-15; **`CLV1` is the mirror of it** — reference in bits
//! 12-15, offset in bits 0-11 — with only three reference points instead of twelve
//! ([`Clv1Reference`]). Both were measured from a real Continuum client, the second
//! at two view sizes.
//!
//! Reading a `CLV1` word with the `CLV2` split is how Trench Wars' `entermsg.lvz`
//! banner came to be drawn 613 px too far right: `x_word = 0x4CF4` is "reference 4,
//! offset +1231" under `CLV2` and x = 1257, where Continuum draws it at 644
//! (`CentredBox` 1424 − 780 at a 1888-wide view).
//!
//! Because that mis-read is silent and costly, the layouts are kept apart by the
//! parser rather than by convention:
//!
//! * [`ObjectSection::parse`] **refuses** a `CLV1` section holding a screen object,
//!   with [`FormatError::Unsupported`]. A caller written against the `CLV2`
//!   accessors cannot place such an object wrongly, because it never receives one.
//! * [`ObjectSection::parse_with_clv1`] hands them over, for callers that read
//!   positions through [`ObjectData::clv1_screen_position`] and friends.
//!
//! `CLV1` *map* objects are read by both: a map object's words are a plain signed
//! pixel coordinate under either layout, and the `CLV1` map objects in real zone
//! files (Trench Wars' `pubtiles.lvz` and `pubcover.lvz`) read as sensible
//! tile-aligned map positions.

use alloc::vec::Vec;

use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::decompress_to_vec_zlib_with_limit;
pub use oss_proto::{CLV1_BOX, Clv1Reference, ObjectData, ObjectLayout};

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
    /// Which screen layout this section's objects use.
    pub fn layout(&self) -> ObjectLayout {
        if self.version == CLV1 {
            ObjectLayout::Clv1
        } else {
            ObjectLayout::Clv2
        }
    }

    /// Parses inflated object-section data, refusing `CLV1` screen objects.
    ///
    /// Use this unless the caller reads screen positions through
    /// [`ObjectData::clv1_screen_position`]: a `CLV1` screen object read with the
    /// `CLV2` accessors lands in the wrong place, so this returns
    /// [`FormatError::Unsupported`] rather than handing one over. See the module
    /// docs. [`ObjectSection::parse_with_clv1`] is the same parser without the
    /// refusal.
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        let section = Self::parse_with_clv1(data)?;
        if section.layout() == ObjectLayout::Clv1
            && let Some(i) = section.objects.iter().position(|o| !o.is_map_object())
        {
            return Err(FormatError::Unsupported {
                what: "LVZ CLV1 screen object",
                offset: 12 + i * ObjectData::LEN,
            });
        }
        Ok(section)
    }

    /// Parses inflated object-section data, `CLV1` screen objects included.
    ///
    /// Their positions come from [`ObjectData::clv1_screen_position`] and the other
    /// `clv1_*` accessors, **not** from [`ObjectData::screen_x`] and friends, which
    /// are the `CLV2` reading and would place them wrongly. [`ObjectSection::layout`]
    /// says which applies.
    pub fn parse_with_clv1(data: &[u8]) -> Result<Self, FormatError> {
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
        let objects: Vec<ObjectData> = data[12..obj_end]
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

    /// A `CLV1` section is read as far as it can be: map objects yes, screen
    /// objects no. See the module docs for why the screen words aren't guessed.
    #[test]
    fn clv1_screen_objects_are_refused_and_map_objects_are_not() {
        let section = |objects| {
            ObjectSection {
                version: CLV1,
                objects,
                images: alloc::vec![],
            }
            .to_bytes()
        };

        // Map objects are a plain pixel coordinate under either layout.
        let maps = section(alloc::vec![
            ObjectData::map(1, 6752, 3728),
            ObjectData::map(2, 11952, 7344),
        ]);
        let back = ObjectSection::parse(&maps).unwrap();
        assert_eq!(back.version, CLV1);
        assert_eq!(back.objects[1].map_x(), 11952);
        assert_eq!(back.objects[1].map_y(), 7344);

        // One screen object anywhere in the section refuses the whole section,
        // and the offset points at the record that caused it.
        let mixed = section(alloc::vec![
            ObjectData::map(1, 6752, 3728),
            ObjectData::screen(2, 4, 1231, 4, 6),
        ]);
        assert_eq!(
            ObjectSection::parse(&mixed),
            Err(FormatError::Unsupported {
                what: "LVZ CLV1 screen object",
                offset: 12 + ObjectData::LEN,
            })
        );

        // parse_with_clv1 hands the same section over, decoded.
        let back = ObjectSection::parse_with_clv1(&mixed).unwrap();
        assert_eq!(back.layout(), ObjectLayout::Clv1);
        assert_eq!(back.objects[0].map_x(), 6752);
        assert_eq!(back.objects[1].clv1_x_ref(), Clv1Reference::CentredBox);

        // The same words under a CLV2 tag are read as reference + offset.
        let mut clv2 = mixed.clone();
        clv2[..4].copy_from_slice(&CLV2);
        let back = ObjectSection::parse(&clv2).unwrap();
        assert_eq!(back.layout(), ObjectLayout::Clv2);
        assert_eq!(back.objects[1].x_ref(), 4);
        assert_eq!(back.objects[1].screen_x(), 1231);
    }

    /// Trench Wars' `entermsg.lvz`, the file all of this exists for: a `CLV1`
    /// section whose one screen object has `x_word = 0x4CF4`, `y_word = 0x0064`.
    /// Read with the `CLV2` layout that is "reference 4, offset +1231" and the
    /// banner lands at x = 1257; Continuum draws it at 644.
    #[test]
    fn the_trench_wars_entry_banner_lands_where_continuum_draws_it() {
        let mut data = alloc::vec![];
        data.extend_from_slice(&CLV1);
        data.extend_from_slice(&1u32.to_le_bytes()); // one object
        data.extend_from_slice(&1u32.to_le_bytes()); // one image
        data.extend_from_slice(&0u16.to_le_bytes()); // id 0, screen object
        data.extend_from_slice(&0x4CF4u16.to_le_bytes());
        data.extend_from_slice(&0x0064u16.to_le_bytes());
        data.extend_from_slice(&[0, 6]); // image 0, layer 6
        data.extend_from_slice(&((2u16 << 12) | 90).to_le_bytes()); // EnterArena, 90
        data.extend_from_slice(&[1, 0, 1, 0, 0, 0]); // 1x1 frames, no animation
        data.extend_from_slice(b"entermsg.jpg\0");

        // The default parser still declines to hand it to a CLV2 reader.
        assert_eq!(
            ObjectSection::parse(&data),
            Err(FormatError::Unsupported {
                what: "LVZ CLV1 screen object",
                offset: 12,
            })
        );

        // Read as CLV1 it is group 1 (the centred box) minus 780 in x, and the
        // view's top-left plus 100 in y.
        let section = ObjectSection::parse_with_clv1(&data).unwrap();
        assert_eq!(section.layout(), ObjectLayout::Clv1);
        let o = section.objects[0];
        assert!(!o.is_map_object());
        assert_eq!(o.clv1_x_ref(), Clv1Reference::CentredBox);
        assert_eq!(o.clv1_screen_x(), -780);
        assert_eq!(o.clv1_y_ref(), Clv1Reference::TopLeft);
        assert_eq!(o.clv1_screen_y(), 100);

        // Measured in Continuum at 1888x1016: the 600x250 banner's top-left is
        // (644, 100). The other two sizes are the same arithmetic, and all three
        // put the whole banner on screen -- including 1280x800, where reading the
        // word as CLV2 (x = 1257) is what clipped it.
        assert_eq!(o.clv1_screen_position(1888, 1016), (644, 100));
        assert_eq!(o.clv1_screen_position(1920, 1080), (660, 100));
        assert_eq!(o.clv1_screen_position(1280, 800), (340, 100));
        assert_eq!(o.screen_x(), 1231, "the CLV2 reading, which is the bug");
    }

    /// The reference table, from a real Continuum client at two view sizes.
    #[test]
    fn clv1_reference_table() {
        let at = |nibble: u8, offset: i16, w: i32, h: i32| {
            let word = (u16::from(nibble) << 12) | (offset as u16 & 0xFFF);
            let o = ObjectData {
                x_word: word,
                y_word: word,
                ..ObjectData::default()
            };
            o.clv1_screen_position(w, h)
        };

        // Offset 0 reads the reference point itself. Group 0 is the view's
        // top-left, group 2 its bottom-right, and group 1 the bottom-right corner
        // of a 960x960 box centred in the view.
        for n in 0..=3 {
            assert_eq!(at(n, 0, 1888, 1016), (0, 0), "nibble {n}");
            assert_eq!(at(n, 0, 1920, 1080), (0, 0), "nibble {n}");
        }
        for n in 4..=7 {
            assert_eq!(at(n, 0, 1888, 1016), (1424, 988), "nibble {n}");
            assert_eq!(at(n, 0, 1920, 1080), (1440, 1020), "nibble {n}");
        }
        for n in 8..=15 {
            assert_eq!(at(n, 0, 1888, 1016), (1888, 1016), "nibble {n}");
            assert_eq!(at(n, 0, 1920, 1080), (1920, 1080), "nibble {n}");
        }

        // Probes that were not used to fit the centred-box rule: at 1920x1080,
        // x at offset -700 lands on 740 and y at offset -500 on 520.
        assert_eq!(at(4, -700, 1920, 1080).0, 740);
        assert_eq!(at(4, -500, 1920, 1080).1, 520);

        // The last nibble of each of the two upper groups does not carry into the
        // group when the offset is negative: 1424 - 1 and 1888 - 1.
        assert_eq!(at(7, -1, 1888, 1016).0, 1423);
        assert_eq!(at(11, -1, 1888, 1016).0, 1887);

        // Nibble 3 is read uniformly as group 0, which is where we knowingly
        // differ from Continuum: it would put a negative offset on group 1
        // (1424 - 100 = 1324) and draw nothing below about -1385.
        assert_eq!(at(3, 100, 1888, 1016).0, 100);
        assert_eq!(at(3, -100, 1888, 1016).0, -100);

        // Offsets are signed 12-bit, so they wrap at the edges of that range.
        assert_eq!(at(0, 2047, 1888, 1016).0, 2047);
        assert_eq!(at(0, -2048, 1888, 1016).0, -2048);
    }
}
