# Replay files (`.ossr`)

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-formats::replay`.

A replay records the game packets a client received, and optionally the ones it sent, with timestamps. It also holds the metadata and the map/LVZ files needed to play the recording back on another machine. Playback feeds the recorded server packets, at their times, to the same code that handles a live connection.

SubSpace and Continuum have no shared replay format. This format is defined by this project and versioned.

## Layout

Little-endian throughout.

**Header** (12 bytes):

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `OSSR` |
| 4 | 2 | version: 1 |
| 6 | 2 | flags: bit 0 set means the body is one zlib stream |
| 8 | 4 | reserved: 0 |

**Body:** records back to back, or, if flag bit 0 is set, a zlib stream that inflates to records.

**Record:**

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | kind |
| 1 | 4 | time: milliseconds since the recording started |
| 5 | 4 | data length |
| 9 | n | data |

## Record kinds

| Kind | Name | Data |
|---|---|---|
| `01` | metadata | UTF-8 `key=value`; the key ends at the first `=` |
| `02` | server packet | one complete game packet received from the server, as the transport delivers it (after reliable, cluster, big-data and sized-transfer unwrapping) |
| `03` | client packet | one complete game packet the recording client sent (optional) |
| `04` | file | `u8` name length, name, then the file contents exactly as the server stores them (map or LVZ) |
| `05` | marker | UTF-8 bookmark text |

Readers skip kinds they don't know, so new kinds can be added without a version bump. Times should not decrease.

**Suggested metadata keys:**

| Key | Value |
|---|---|
| `zone` | zone name |
| `server` | `host:port` |
| `arena` | arena name |
| `player` | the recording player's name |
| `client` | client name and version |
| `started` | wall-clock start time, RFC 3339 |
| `map` | map file name |

**Writing a recording:**

1. Write the header, then append records as they happen.
2. Write the map and LVZ files as `04` records when they are loaded.
3. Optionally, when the recording ends, rewrite it with the body compressed.

If a recording is cut off (for example by a crash), it still parses up to its last complete record. The parser reports the file as truncated.
