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

### oss-proto
- `ClientSettings` (S2C `0x0F`, 1428 bytes): wire-shaped arrays (`bits`, `ships: [ShipSettings; 8]`, `longs`, `spawns: [SpawnPosition; 4]`, `shorts`, `bytes`, `prize_weights`) with named getters/setters (`ships[i].maximum_speed()`, `set_radius(..)`, `door_mode()`, ...). `decode(&[u8])`, `encode(&mut Vec<u8>)`, `to_bytes()`; exact for every byte.
- Config-name tables for servers filling settings generically: `SHIP_NAMES`, `LONG_KEYS` (+ `LONG_KEYS_X1000`), `SHORT_KEYS`, `BYTE_KEYS`, `PRIZE_WEIGHT_KEYS`, `SHIP_LONG_KEYS`, `SHIP_SHORT_KEYS`, `SHIP_BYTE_KEYS`, bitfield tables `ARENA_BITS`, `SHIP_MISC_BITS`, `SHIP_WEAPON_BITS` (`(key, lo, width)`), helpers `get_bits`/`set_bits`.
- `checksum`: `crc32`, `crc32_update`, `position_checksum`, `settings_checksum(key, &packet_bytes)`, `map_checksum(key, |x, y| tile)`, `map_crc32(&grid_cells)`, `vie_exe_checksum(key)`.
- `wire::{Reader, Writer}`, `FixedStr<N>` (NUL-padded text fields, raw bytes preserved).
- Crate is `no_std` + `alloc`.
