//! SubSpace content formats: `.lvl` maps (tileset bitmap + tile list), eLVL
//! metadata chunks (regions, attributes) and `.lvz` archives.
//!
//! All parsers take `&[u8]` and return `Result`; they never panic on malformed
//! input. Writers reproduce well-formed input files byte for byte.
#![no_std]

extern crate alloc;

pub mod elvl;
mod error;
pub mod lvl;
pub mod region;

pub use elvl::{AutoWarp, Chunk, Metadata, Region, RegionChunk};
pub use error::FormatError;
pub use lvl::{Level, MAP_SIZE, TileEntry, TileGrid, Tileset};
pub use region::RegionBitmap;
