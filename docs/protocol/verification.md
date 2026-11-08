# What is verified, and how

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Everything in these pages is implemented in oss-core and covered by round-trip tests. This page says how much further each part has been checked, so readers know which details are confirmed and which are reasoned from incomplete evidence.

## Evidence levels

| Level | Meaning |
|---|---|
| **Vectors** | Checked byte for byte against the output of an unmodified reference implementation, run on synthetic or public-default inputs. The vectors are in `crates/oss-conformance/vectors/` and also run through the [conformance suite](../conformance.md). The reference is the ASSS 1.4.4 server modules compiled as-is, or nullspace's MIT exe checksum. |
| **Sources** | The layout and behaviour agree with the reference server's packet definitions and code, and with at least one other independent source. The other sources are the SubSpace 1.35 client's packet handler table (types up to `0x31`), Subspace Server .NET, MervBot, nullspace, the directory and billing servers, and the billing and directory protocol write-ups. Sources were read for behaviour only. Not checked against a running reference. |
| **Partly inferred** | The layout is confirmed by sources, but some fields' meaning is unknown or comes from a single source. Those fields are named, decoded as raw values, and preserved exactly on re-encode. |
| **Project spec** | Defined by this project. Its vectors check our implementation against our own specification, not against an independent one. |

**Live tests.** Behaviour exercised against `oss-server` (`oss-conformance server`) or with `oss-bot-sdk` (`oss-conformance client`) is noted as live. Both use oss-core's codecs, so they confirm consistency, not independence.

## Transport ([transport.md](transport.md), [encryption.md](encryption.md))

| Item | Level | Notes |
|---|---|---|
| `00 01` / `00 02` connect and VIE key exchange | **Vectors** | 16 key exchanges, including the edge-case keys 1 → −1 and `0x80000000` |
| VIE encryption and decryption | **Vectors** | 1,536 packets over 16 keys, including key 0 (no encryption) and `0xFFFFFFFF` |
| `00 03` reliable, `00 04` ack, duplicate handling, receive window | Sources | ASSS `net.c` plus the client handler table. Conformance (live): acks, single delivery of duplicates |
| `00 05` / `00 06` time sync, both request lengths | Sources | live |
| `00 07` disconnect | Sources | live |
| `00 08` / `00 09` big data, `00 0A` sized transfer, `00 0B`/`00 0C` cancel | Sources | Map downloads use them (live). The ASSS-compatible caps of 64 KiB (big) and 16 MiB (sized) are server limits, not protocol |
| `00 0E` cluster | Sources | live |
| `00 10`–`00 14` Continuum key expansion | Partly inferred | Only the shape is documented; the algorithm is not public, so it is not implemented here |
| Retransmission timing, window sizes, pacing of sized transfers | Sources, then our choice | Window 32 receive / 24 send and the 512/520 size limits follow ASSS. The retransmission timeout formula and sized-transfer pacing are our own choices, measured by the [soak harness](../performance.md) |

## Security checksums ([checksums.md](checksums.md))

| Item | Level | Notes |
|---|---|---|
| Position checksum (C2S `0x03`, S2C `0x05`) | **Vectors** | 48 C2S packets (8 corrupted), 40 S2C |
| Settings checksum | **Vectors** | 2 packets × 7 keys |
| Map checksum | **Vectors** | `smallmap.lvl` and 4 synthetic maps, 165 checksums, including big objects across the map edge and negative keys |
| Map checksum for keys ≥ `0x80000000` | **Vectors** for ASSS | ASSS wraps coordinates mod 1024. Whether the Continuum client does the same is **unconfirmed** |
| VIE exe checksum | **Vectors** | 32 keys (nullspace) |
| `map_crc32` (Continuum's extra map CRC in C2S `0x1A`) | Partly inferred | From a single source; not checked against a Continuum client |
| Game RNG (`VieRng`: prize and door seeds) | Sources | Park-Miller with the client's +123 step; agrees with the reference server and nullspace. Not checked against a running client |

## Settings packet ([settings.md](settings.md))

| Item | Level | Notes |
|---|---|---|
| The 1428-byte layout and every named key's bit position | **Vectors** | 846 keys × 2 configurations, read back from packets the reference server built |
| Decode and re-encode | **Vectors** | Both reference packets re-encode byte for byte |
| Meaning of individual settings | Sources | Names follow the reference server's configuration keys. What the client does with each value is documented there, not here |

## Game packets ([game-packets.md](game-packets.md))

All S2C and C2S packets round-trip in oss-core's tests and in the conformance vectors (canonical encodings), and property tests cover arbitrary field values. The table below gives the evidence for the layouts themselves.

| Packets | Level | Notes |
|---|---|---|
| S2C `0x0F` settings; the checksum bytes of C2S `0x03` and S2C `0x05` | **Vectors** | See above |
| S2C `0x02`, `0x03`, `0x04`, `0x06`–`0x0B`, `0x0E`, `0x10`, `0x12`–`0x16`, `0x18`, `0x19`, `0x1B`, `0x1C`, `0x1D`, `0x1F`–`0x23`, `0x25`, `0x27`, `0x28`, `0x29`, `0x2A`–`0x2F` | Sources | Defined by the reference server and listed in the client handler table. The arena-entry order (`0x01`, `0x0F`, `0x03`…, `0x29`, `0x02`) is also live |
| S2C `0x01` player id | Partly inferred | The optional trailing byte is of unknown meaning (kept as `extra`) |
| S2C `0x0D` frequency change | Partly inferred | The last byte is `0xFF` from servers; some clients read a ship there |
| S2C `0x1A` score reset | Sources | The client handler table and Subspace Server .NET call it a score reset; ASSS names the constant `TIMEDGAME` but does not use it |
| S2C `0x1E` banner toggle | Partly inferred | Meaning unclear in every source |
| S2C `0x24` speed game, `0x30` ad banner, `0x31` login OK | Partly inferred | Defined by sources but obsolete or rarely used; field meanings are from a single source |
| S2C `0x32` warp to, `0x33` login text, `0x34` Continuum version, `0x35`/`0x36` LVZ objects, `0x37`/`0x38` damage, `0x3B` redirect, `0x3C` select box | Sources | Continuum-era packets, beyond the 1.35 handler table: reference server and Subspace Server .NET |
| S2C `0x39`/`0x3A` batched positions | Sources | Continuum-only: Subspace Server .NET and nullspace. Not in the reference server |
| C2S `0x01`, `0x02`, `0x05`–`0x08`, `0x0A`–`0x10`, `0x13`–`0x16`, `0x18`, `0x19`, `0x1C`–`0x21`, `0x32` | Sources | Some of these are also live (`0x01`, `0x03`, `0x0C`) |
| C2S `0x09`/`0x24` login | Partly inferred | `unknown1`, the upper half of field 444 (client feature flags in one server), and the 12 reserved bytes (redirect data in one server) are kept raw |
| C2S `0x17` registration | Partly inferred | Layout from sources; the 13 hardware strings are free text whose meaning varies between clients |
| C2S `0x1A` security response | **Vectors** for the checksums, Sources for the layout | The Continuum timer-drift field is from a single source |
| C2S `0x1B` security violation | Partly inferred | The trailing message is optional and its contents are not specified |
| Voice (S2C `0x0C`, C2S `0x0E`) | Partly inferred | The compressed WAV payload is opaque here |

## Directory and billing ([directory.md](directory.md), [billing.md](billing.md))

| Item | Level | Notes |
|---|---|---|
| Zone registration, ping/pong, zone list | Sources | ASSS's directory client, the dirserver source (which also gives the acceptance rules), and the directory protocol write-up |
| All server ↔ biller packets | Sources | ASSS's billing client and packet definitions, Subspace Server .NET, and the billing protocol write-up. Biller identity (`0x33`) has two sizes in sources, so it is read to the end of the packet |

## Project protocols

| Item | Level | Notes |
|---|---|---|
| OpenSec v1 ([opensec.md](opensec.md)) | **Project spec** | Its primitives are checked against RFC 7748, RFC 8439 and RFC 5869 test vectors. An external cryptographic review is still to come |
| WebSocket relay `oss-relay.1` ([websocket-relay.md](websocket-relay.md)) | **Project spec** | Codec unit tests, fuzzing, and the relay vectors |
| `.ossr` replays ([../formats/replay.md](../formats/replay.md)) | **Project spec** | |

## File formats ([../formats](../formats))

| Item | Level | Notes |
|---|---|---|
| `.lvl` tiles and tileset | **Vectors** (map checksums) and real files | 20 real maps rewrite byte for byte (local test; the maps are not in the repository) |
| eLVL chunks and regions | Sources and real files | The reference server's map loader and Subspace Server .NET, plus real maps |
| `.lvz` | Sources and real files | 34 real LVZ files rewrite byte for byte (local test) |
