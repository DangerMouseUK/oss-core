//! SubSpace content formats: `.lvl` maps (tileset bitmap + tile list), eLVL
//! metadata chunks (regions, attributes), `.lvz` archives and `.ossr` replays.
//!
//! All parsers take `&[u8]` and return `Result`; they never panic on malformed
//! input. Writers reproduce well-formed input files byte for byte.
#![no_std]

extern crate alloc;

pub mod elvl;
mod error;
pub mod lvl;
pub mod lvz;
pub mod region;
pub mod replay;

pub use elvl::{AutoWarp, Chunk, Metadata, Region, RegionChunk};
pub use error::FormatError;
pub use lvl::{GridStats, Level, MAP_SIZE, TileEntry, TileGrid, Tileset};
pub use lvz::{
    CLV1_BOX, Clv1Reference, ImageDef, Lvz, ObjectData, ObjectLayout, ObjectSection, Section,
};
pub use region::RegionBitmap;
pub use replay::{Record, RecordKind, Replay};

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
