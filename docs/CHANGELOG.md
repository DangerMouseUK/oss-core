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

### oss-formats (lvz)
- `Lvz::parse` / `to_bytes` (byte-exact; compressed bytes kept as stored), `Section { name, file_time, decompressed_size, stored }`, `Section::data()` (inflate), `Section::new(name, time, data)` (deflate), `Section::objects(&ObjectSection)`, `Lvz::object_sections()`.
- `ObjectSection { version, objects: Vec<ObjectData>, images: Vec<ImageDef> }`. `ObjectData` is `oss_proto::ObjectData` (re-exported), with accessors for map/screen coordinates, layer, mode, display time.
- New dependencies: `oss-proto`, `miniz_oxide` 0.8 (MIT/Zlib/Apache-2.0, `no_std` + alloc).

### oss-proto (game packets)
- `s2c` and `c2s` modules: a struct per packet type implementing `Packet` (`TYPE`, `decode(&[u8])` with type byte, `encode`, `to_bytes`), type-byte constants in `s2c::kind` / `c2s::kind`, and dispatch enums `S2CPacket` / `C2SPacket` (`decode`, `encode`, `to_bytes`, `kind()`, `From<T>` for each packet, `Unknown { kind, data }` fallback). `Settings` and `Registration` variants are boxed.
- Multi-length packets: `PlayerId.extra`, `SpecData::{ExtraData, Player}`, `MapFilename::{Single, Files}`, `GoArena.optional_graphics` (26/27), `Login` (101/165; `ContLogin` wraps the 0x24 form), `MapRequest.index`, `SecurityResponse.continuum` (40/46), `Bricks` (empty = clear).
- **Breaking:** S2C position packets now carry `tail: PositionTail { None, Energy(u16), Extra(ExtraPositionData) }` (lengths 16/18/26 and 21/23/31) instead of `extra: Option<_>`.
- Shared structures in `common`: `PlayerData` (64-byte S2C 0x03 records, concatenatable), `Brick`, `DamageData`, `ObjectToggle`, `ObjectChange`, `SmallBatchedPosition` / `LargeBatchedPosition` / `PackedMotion` (0x39/0x3A), constants `chat_type`, `prize`, `object_change`; `c2s::client_features`, `c2s::arena_type`, `s2c::login_code`.
- `wire::Raw<N>` for long raw byte fields (banners).
