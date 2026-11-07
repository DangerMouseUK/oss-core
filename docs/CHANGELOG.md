# Changelog and API notes

For consumers of `oss-core` (oss-server, oss-client, bots, tools). Newest first. Crates are pre-1.0: names may still change, but changes are listed here.

## Unreleased

### oss-formats
- `Level::parse(&[u8]) -> Result<Level, FormatError>` / `Level::to_bytes()`: `.lvl` files with optional tileset (`Tileset { bytes }`, raw BMP incl. file header), optional eLVL `Metadata`, `tiles: Vec<TileEntry>` in file order. Well-formed files rewrite byte for byte.
- `Level::tile_grid() -> TileGrid` (dense 1024x1024, `get(x, y)`, `set`, `cells()`); `Level::set_tiles_from_grid`.
- `Metadata { reserved, chunks: Vec<Chunk> }`; `Chunk::{Attribute, Region, TileData, Other}`; helpers `attribute(key)`, `attributes()`, `regions()`.
- `Region { chunks: Vec<RegionChunk> }`, `RegionChunk::{Name, Tiles, Base, NoAntiwarp, NoWeapons, NoFlagDrops, AutoWarp, Code, Other}`; helpers `name()`, `tiles() -> RegionBitmap`, `is_base()`, `no_antiwarp()`, `no_weapons()`, `no_flag_drops()`, `auto_warp()`.
- `RegionBitmap` (1 bit per tile): `contains`, `set`, `iter`, `count`, `decode(rTIL bytes)`, `encode()`.
- Crate is `no_std` + `alloc`.
