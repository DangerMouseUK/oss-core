# `.lvz` archives

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-formats::lvz` and `oss-proto::objects`. Evidence: [verification.md](../protocol/verification.md#file-formats-formats).

Little-endian throughout.

## Container

| Field | Size | Notes |
|-------|------|-------|
| magic | 4 | `CONT` |
| section count | 4 | |
| sections | ... | repeated |

Each section:

| Field | Size | Notes |
|-------|------|-------|
| magic | 4 | `CONT` |
| decompressed size | 4 | |
| file time | 4 | file timestamp; 0 for the object section |
| stored size | 4 | bytes that follow the name |
| name | n+1 | NUL-terminated; empty for the object section |
| data | stored size | zlib stream, **or the plain bytes when stored size equals decompressed size** |

Sections with a name are files: images (BMP/PNG/GIF/JPEG), replacement graphics (`.bm2`) and sounds that override the client's defaults while in the arena.

## Object section

The section with file time 0 and an empty name (after inflating):

| Field | Size |
|-------|------|
| magic `CLV1` or `CLV2` | 4 |
| object count | 4 |
| image count | 4 |
| objects | 10 each |
| images | variable |

Image entry: `i16` frames across, `i16` frames down, `i16` animation time (1/100 s), then a NUL-terminated file name.

### Object record (10 bytes)

Also used by the object move packet (S2C `0x36`).

| Bytes | Bits | Field |
|-------|------|-------|
| 0-1 | 0 | 1 = map object, 0 = screen object |
| | 1-15 | object id |
| 2-3 | | map object: x in pixels (`i16`). Screen object: bits 0-3 reference point, bits 4-15 signed offset |
| 4-5 | | same for y |
| 6 | | image index |
| 7 | | layer: 0 below all, 1 after background, 2 after tiles, 3 after weapons, 4 after ships, 5 after gauges, 6 after chat, 7 top-most |
| 8-9 | 0-11 | display time in 1/10 s (0 = forever) |
| | 12-15 | mode: 0 always shown, 1 on entering zone, 2 on entering arena, 3 on kill, 4 on death, 5 server controlled |

Screen reference points: 0 top-left, 1 centre (`C`), 2 bottom-right (`B`), 3 stats box (`S`), 4 specials top-right (`G`), 5 specials bottom-right (`F`), 6 below energy bar (`E`), 7 chat top-left (`T`), 8 radar top-left (`R`), 9 radar text (`O`), 10 weapons top-left (`W`), 11 weapons bottom-left (`V`).
