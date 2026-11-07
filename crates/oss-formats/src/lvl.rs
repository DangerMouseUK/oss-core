//! `.lvl` level files: an optional tileset bitmap, optional eLVL metadata, and a
//! list of tiles.
//!
//! Layouts, as recognised by the first bytes of the file:
//!
//! * `"BM"`: a Windows bitmap (the tileset). Its file header's `bfSize` field
//!   (offset 2) is the offset of the tile list, and the reserved word at offset 6
//!   is the offset of the eLVL metadata section, or 0 if there is none.
//! * `"elvl"`: a metadata section with no tileset; tiles follow the section.
//! * anything else: the whole file is the tile list.
//!
//! The tile list is a sequence of little-endian `u32` entries: bits 0-11 are x,
//! bits 12-23 are y and bits 24-31 the tile type. Map coordinates run 0..1024.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::FormatError;
use crate::elvl::{Chunk, ELVL_MAGIC, Metadata};
use crate::error::u32_at;

/// Width and height of the map in tiles.
pub const MAP_SIZE: usize = 1024;

/// Offset of `bfSize` in the bitmap file header.
const BF_SIZE: usize = 2;
/// Offset of the reserved word that points at the eLVL section.
const BF_RESERVED: usize = 6;
/// Size of the bitmap file header.
const BF_HEADER_LEN: usize = 14;

/// One entry in the tile list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TileEntry {
    /// X coordinate (12 bits on the wire; valid maps use 0..1024).
    pub x: u16,
    /// Y coordinate (12 bits on the wire; valid maps use 0..1024).
    pub y: u16,
    /// Tile type; 0 is empty.
    pub tile: u8,
}

impl TileEntry {
    /// Decodes a packed 4-byte entry.
    pub fn from_u32(v: u32) -> Self {
        Self {
            x: (v & 0xFFF) as u16,
            y: ((v >> 12) & 0xFFF) as u16,
            tile: (v >> 24) as u8,
        }
    }

    /// Packs the entry into its 4-byte form. Coordinates are truncated to 12 bits.
    pub fn to_u32(self) -> u32 {
        u32::from(self.x & 0xFFF) | u32::from(self.y & 0xFFF) << 12 | u32::from(self.tile) << 24
    }
}

/// The tileset bitmap at the start of a level file.
///
/// Holds the bitmap bytes verbatim, starting with the 14-byte `"BM"` file header
/// and including any padding before the metadata section. The header's size and
/// metadata-offset fields are rewritten by [`Level::to_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tileset {
    /// Raw bitmap bytes, file header included.
    pub bytes: Vec<u8>,
}

/// A parsed level file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Level {
    /// The embedded tileset, if any.
    pub tileset: Option<Tileset>,
    /// eLVL metadata, if any.
    pub metadata: Option<Metadata>,
    /// Tile entries in file order (later entries win if coordinates repeat).
    pub tiles: Vec<TileEntry>,
    /// Bytes after the last whole tile entry (normally empty), kept for exact
    /// round-trips.
    pub trailing: Vec<u8>,
}

/// A dense 1024x1024 grid of tile types (1 MiB), indexed `[y * 1024 + x]`.
#[derive(Clone, PartialEq, Eq)]
pub struct TileGrid {
    cells: Box<[u8]>,
}

impl core::fmt::Debug for TileGrid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let used = self.cells.iter().filter(|&&t| t != 0).count();
        f.debug_struct("TileGrid")
            .field("non_empty", &used)
            .finish()
    }
}

impl Default for TileGrid {
    fn default() -> Self {
        Self::new()
    }
}

impl TileGrid {
    /// An empty grid.
    pub fn new() -> Self {
        Self {
            cells: vec![0; MAP_SIZE * MAP_SIZE].into_boxed_slice(),
        }
    }

    /// The tile at (`x`, `y`), or 0 outside the map.
    pub fn get(&self, x: u32, y: u32) -> u8 {
        if (x as usize) < MAP_SIZE && (y as usize) < MAP_SIZE {
            self.cells[y as usize * MAP_SIZE + x as usize]
        } else {
            0
        }
    }

    /// Sets the tile at (`x`, `y`); ignored outside the map.
    pub fn set(&mut self, x: u32, y: u32, tile: u8) {
        if (x as usize) < MAP_SIZE && (y as usize) < MAP_SIZE {
            self.cells[y as usize * MAP_SIZE + x as usize] = tile;
        }
    }

    /// All cells, row-major.
    pub fn cells(&self) -> &[u8] {
        &self.cells
    }

    /// Applies tile entries in order; out-of-range entries are ignored.
    pub fn apply(&mut self, tiles: impl IntoIterator<Item = TileEntry>) {
        for t in tiles {
            self.set(u32::from(t.x), u32::from(t.y), t.tile);
        }
    }

    /// The non-empty tiles as entries, row by row.
    pub fn entries(&self) -> Vec<TileEntry> {
        self.cells
            .iter()
            .enumerate()
            .filter(|&(_, &t)| t != 0)
            .map(|(i, &t)| TileEntry {
                x: (i % MAP_SIZE) as u16,
                y: (i / MAP_SIZE) as u16,
                tile: t,
            })
            .collect()
    }
}

/// Decodes a packed tile list; returns the entries and any leftover bytes.
pub fn parse_tile_list(data: &[u8]) -> (Vec<TileEntry>, &[u8]) {
    let (words, rest) = data.as_chunks::<4>();
    let tiles = words
        .iter()
        .map(|&w| TileEntry::from_u32(u32::from_le_bytes(w)));
    (tiles.collect(), rest)
}

impl Level {
    /// Parses a level file.
    ///
    /// A non-zero metadata pointer that does not lead to a valid eLVL section is
    /// tolerated (as other loaders do): the metadata is ignored and the bytes up to
    /// the tile list are kept as the tileset.
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        let mut level = Self::default();
        let tiles_at = if data.starts_with(b"BM") {
            let size = u32_at(data, BF_SIZE, "bitmap header")? as usize;
            let reserved = u32_at(data, BF_RESERVED, "bitmap header")? as usize;
            if size < BF_HEADER_LEN || size > data.len() {
                return Err(FormatError::BadLength {
                    what: "bitmap",
                    offset: BF_SIZE,
                });
            }
            let mut bitmap_end = size;
            if reserved != 0
                && reserved >= BF_HEADER_LEN
                && reserved < size
                && let Ok((meta, len)) = Metadata::parse(&data[reserved..size])
                && reserved + len == size
            {
                level.metadata = Some(meta);
                bitmap_end = reserved;
            }
            level.tileset = Some(Tileset {
                bytes: data[..bitmap_end].to_vec(),
            });
            size
        } else if u32_at(data, 0, "eLVL header").ok() == Some(ELVL_MAGIC) {
            let (meta, len) = Metadata::parse(data)?;
            level.metadata = Some(meta);
            len
        } else {
            0
        };
        let (tiles, rest) = parse_tile_list(&data[tiles_at..]);
        level.tiles = tiles;
        level.trailing = rest.to_vec();
        Ok(level)
    }

    /// Serialises the level. Files produced by common editors come back byte for
    /// byte; the bitmap header's size and metadata-offset fields are recomputed.
    pub fn to_bytes(&self) -> Vec<u8> {
        let meta = self.metadata.as_ref().map(Metadata::to_bytes);
        let mut out = Vec::with_capacity(
            self.tileset.as_ref().map_or(0, |t| t.bytes.len())
                + meta.as_ref().map_or(0, Vec::len)
                + self.tiles.len() * 4
                + self.trailing.len(),
        );
        if let Some(ts) = &self.tileset {
            out.extend_from_slice(&ts.bytes);
            out.resize(out.len().max(BF_HEADER_LEN), 0);
            out[..2].copy_from_slice(b"BM");
            let meta_at = match &meta {
                Some(m) => {
                    out.resize(out.len().next_multiple_of(4), 0);
                    let at = out.len();
                    out.extend_from_slice(m);
                    at
                }
                None => 0,
            };
            let size = out.len() as u32;
            out[BF_SIZE..BF_SIZE + 4].copy_from_slice(&size.to_le_bytes());
            out[BF_RESERVED..BF_RESERVED + 4].copy_from_slice(&(meta_at as u32).to_le_bytes());
        } else if let Some(m) = &meta {
            out.extend_from_slice(m);
        }
        for t in &self.tiles {
            out.extend_from_slice(&t.to_u32().to_le_bytes());
        }
        out.extend_from_slice(&self.trailing);
        out
    }

    /// Builds the dense tile grid: tiles from any `TILE` metadata chunks first,
    /// then the file's tile list.
    pub fn tile_grid(&self) -> TileGrid {
        let mut grid = TileGrid::new();
        if let Some(m) = &self.metadata {
            for c in &m.chunks {
                if let Chunk::TileData(d) = c {
                    grid.apply(parse_tile_list(d).0);
                }
            }
        }
        grid.apply(self.tiles.iter().copied());
        grid
    }

    /// Replaces the tile list with the grid's non-empty tiles, row by row.
    pub fn set_tiles_from_grid(&mut self, grid: &TileGrid) {
        self.tiles = grid.entries();
        self.trailing.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elvl::{Region, RegionChunk};
    use crate::region::RegionBitmap;

    fn fake_bitmap() -> Vec<u8> {
        // A 14-byte file header, a 40-byte info header, 256 palette entries and a
        // tiny pixel area: enough structure for the level container.
        let mut b = vec![0u8; 14 + 40 + 1024 + 37];
        b[..2].copy_from_slice(b"BM");
        b[10..14].copy_from_slice(&1078u32.to_le_bytes());
        b[14..18].copy_from_slice(&40u32.to_le_bytes());
        for (i, v) in b.iter_mut().enumerate().skip(54) {
            *v = (i * 7) as u8;
        }
        b
    }

    fn sample_tiles() -> Vec<TileEntry> {
        vec![
            TileEntry {
                x: 0,
                y: 0,
                tile: 1,
            },
            TileEntry {
                x: 1023,
                y: 1023,
                tile: 170,
            },
            TileEntry {
                x: 512,
                y: 300,
                tile: 255,
            },
            TileEntry {
                x: 512,
                y: 300,
                tile: 12,
            },
        ]
    }

    #[test]
    fn tile_entry_packing() {
        let t = TileEntry {
            x: 0x3FF,
            y: 0x123,
            tile: 0xAB,
        };
        assert_eq!(t.to_u32(), 0xAB1_233FF);
        assert_eq!(TileEntry::from_u32(t.to_u32()), t);
    }

    #[test]
    fn plain_tile_list() {
        let lvl = Level {
            tiles: sample_tiles(),
            ..Default::default()
        };
        let bytes = lvl.to_bytes();
        assert_eq!(bytes.len(), 16);
        let back = Level::parse(&bytes).unwrap();
        assert_eq!(back, lvl);
        let grid = back.tile_grid();
        assert_eq!(grid.get(512, 300), 12);
        assert_eq!(grid.get(1023, 1023), 170);
        assert_eq!(grid.get(5000, 0), 0);
    }

    #[test]
    fn with_tileset_and_metadata() {
        let mut region = RegionBitmap::new();
        region.set(10, 10, true);
        let mut r = Region::new("center", &region);
        r.chunks.push(RegionChunk::NoAntiwarp);
        let lvl = Level {
            tileset: Some(Tileset {
                bytes: fake_bitmap(),
            }),
            metadata: Some(Metadata {
                reserved: 0,
                chunks: vec![
                    Chunk::Attribute {
                        key: "NAME".into(),
                        value: "x".into(),
                    },
                    Chunk::Region(r),
                ],
            }),
            tiles: sample_tiles(),
            trailing: vec![7, 7],
        };
        let bytes = lvl.to_bytes();
        let meta_at = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
        assert_eq!(meta_at % 4, 0);
        assert_eq!(&bytes[meta_at..meta_at + 4], b"elvl");
        let back = Level::parse(&bytes).unwrap();
        // Parsing keeps the alignment padding as part of the bitmap bytes.
        assert_eq!(back.to_bytes(), bytes);
        assert_eq!(back.metadata, lvl.metadata);
        assert_eq!(back.tiles, lvl.tiles);
        assert_eq!(back.trailing, [7, 7]);
    }

    #[test]
    fn metadata_without_tileset() {
        let lvl = Level {
            metadata: Some(Metadata {
                reserved: 0,
                chunks: vec![Chunk::Attribute {
                    key: "A".into(),
                    value: "B".into(),
                }],
            }),
            tiles: sample_tiles(),
            ..Default::default()
        };
        let bytes = lvl.to_bytes();
        assert!(bytes.starts_with(b"elvl"));
        assert_eq!(Level::parse(&bytes).unwrap(), lvl);
    }

    #[test]
    fn grid_round_trip() {
        let mut grid = TileGrid::new();
        grid.set(3, 4, 9);
        grid.set(1023, 0, 1);
        let mut lvl = Level::default();
        lvl.set_tiles_from_grid(&grid);
        assert_eq!(lvl.tiles.len(), 2);
        assert_eq!(Level::parse(&lvl.to_bytes()).unwrap().tile_grid(), grid);
    }

    #[test]
    fn tolerates_bad_metadata_pointer() {
        let mut bytes = Level {
            tileset: Some(Tileset {
                bytes: fake_bitmap(),
            }),
            tiles: sample_tiles(),
            ..Default::default()
        }
        .to_bytes();
        bytes[6] = 60; // points into the palette, not at an eLVL header
        let lvl = Level::parse(&bytes).unwrap();
        assert!(lvl.metadata.is_none());
        assert_eq!(lvl.tiles, sample_tiles());
    }

    #[test]
    fn rejects_bad_bitmap_size() {
        let mut bytes = fake_bitmap();
        bytes[2..6].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Level::parse(&bytes).is_err());
        assert!(Level::parse(b"BM\x01").is_err());
    }
}
