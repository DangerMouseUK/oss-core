# `.lvl` level files and eLVL metadata

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-formats` (`lvl`, `elvl`, `region` modules).

All integers are little-endian.

## Container

A level file is recognised by its first bytes:

| Starts with | Layout |
|-------------|--------|
| `BM` | tileset bitmap, optional eLVL section, tile list |
| `elvl` | eLVL section, tile list (no tileset; only newer servers understand this) |
| anything else | the whole file is the tile list |

### Tileset bitmap

A standard Windows BMP (8-bit, 256-colour palette, normally 304x160 = 19 x 10 tiles of 16 px). Two fields of the 14-byte BMP file header are reused:

| Offset | Size | Meaning |
|--------|------|---------|
| 0 | 2 | `BM` |
| 2 | 4 | offset of the tile list (classic files: 49718, the bitmap size) |
| 6 | 4 | offset of the eLVL section, 0 if none (usually 49720 when present) |
| 10 | 4 | offset of the pixel data |

Programs that predate eLVL see the metadata as surplus bitmap bytes and still find the tiles via the size field. The eLVL section starts on a 4-byte boundary, so 0-3 padding bytes may follow the bitmap.

Loaders tolerate a non-zero metadata offset that does not point at a valid `elvl` header: the metadata is ignored, the tiles are still read.

### Tile list

From the tile-list offset to end of file, 4-byte entries: bits 0-11 x, bits 12-23 y, bits 24-31 tile type. Coordinates are 0-1023; tile 0 is empty. If coordinates repeat, the later entry wins. Leftover bytes (fewer than 4) are ignored.

## eLVL section

Header (12 bytes): `elvl`, `u32` total section size including the header, `u32` reserved (0). Then chunks until the end of the section:

| Offset | Size | Meaning |
|--------|------|---------|
| 0 | 4 | type (four ASCII characters) |
| 4 | 4 | payload length, not counting padding |
| 8 | n | payload |
| 8+n | 0-3 | zero padding to a multiple of 4 |

Unknown chunk types must be preserved by editors. Seen in the wild: `DCID`, `DCWT` (written by a map editor).

| Chunk | Payload |
|-------|---------|
| `ATTR` | `KEY=value` ASCII, no terminator. One pair per chunk. Common keys: `NAME`, `VERSION`, `ZONE`, `MAPCREATOR`, `TILESETCREATOR`, `PROGRAM`. |
| `REGN` | a region: a list of sub-chunks in the same chunk format |
| `TSET` | a bitmap without the 14-byte file header (proposed; unused in practice) |
| `TILE` | a tile list in the format above (proposed; servers apply it before the file's own tile list) |

### Region sub-chunks

| Sub-chunk | Payload |
|-----------|---------|
| `rNAM` | region name (ASCII). Regions without a name are ignored. |
| `rTIL` | the region's tiles, run-length coded (below) |
| `rBSE` | empty; the region is a base |
| `rNAW` | empty; antiwarp has no effect inside |
| `rNWP` | empty; weapons have no effect inside |
| `rNFL` | empty; flags dropped inside respawn as neutral flags |
| `rAWP` | auto-warp: `i16 x, i16 y` (1-1023; 0 = default; -1 = keep current) optionally followed by a 16-byte NUL-padded arena name |
| `rPYC` | script text run on enter/exit (server-specific) |

### `rTIL` encoding

The 1024x1024 map is coded row by row. Each code is one byte, or two when bit 5 of the first byte is set; the count is `n + 1` where `n` is the low 5 bits (short form) or the low 2 bits of the first byte followed by the whole second byte (long form, up to 1024). In the long form bits 2-4 of the first byte are zero.

| Top 3 bits | Short | Long | Meaning |
|------------|-------|------|---------|
| `000` / `001` | 1-32 | 1-1024 | that many empty tiles in this row |
| `010` / `011` | 1-32 | 1-1024 | that many present tiles in this row |
| `100` / `101` | 1-32 | 1-1024 | that many rows with no tiles |
| `110` / `111` | 1-32 | 1-1024 | repeat the previous row that many times |

Runs in a row must add up to exactly 1024. Row codes (`10x`, `11x`) may only appear at the start of a row; repeat needs a previous row. The data must cover exactly 1024 rows, so an empty region is `A3 FF`.
