# SubSpace protocol reference

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

A versioned, implementation-driven description of the SubSpace/Continuum network protocol. Each page records packet layouts, field meanings, ordering rules and known quirks, verified against working implementations and the tests in this repository.

| Page | Contents |
|---|---|
| [transport.md](transport.md) | core `0x00` packets: setup, reliable delivery, clusters, big and sized transfers, time sync, disconnects, size limits |
| [encryption.md](encryption.md) | the VIE cipher, the shape of the Continuum handshake, the plug-in model |
| [opensec.md](opensec.md) | OpenSec v1: X25519 + ChaCha20-Poly1305 transport encryption (specification) |
| [websocket-relay.md](websocket-relay.md) | `oss-relay.1`: carrying datagrams over WebSocket for browser clients |
| [verification.md](verification.md) | what is verified against reference vectors, what comes from sources, and what is partly inferred |
| [game-packets.md](game-packets.md) | every server-to-client and client-to-server game packet |
| [packets/](packets/README.md) | one page per implemented packet (game, transport, billing, directory): byte layout and evidence |
| [settings.md](settings.md) | the 1428-byte arena settings packet and its configuration keys |
| [checksums.md](checksums.md) | file, position and security checksums; the game RNG |
| [directory.md](directory.md) | zone registration, pings and zone lists |
| [billing.md](billing.md) | zone ↔ billing server packets |

File formats are documented in [../formats](../formats): [`.lvl` and eLVL](../formats/lvl.md), [`.lvz`](../formats/lvz.md), [`.ossr` replays](../formats/replay.md).

Where sources disagree, the pages say so and give the reading this project implements. [verification.md](verification.md) records the evidence behind each part. Implementations can check themselves with the [conformance suite](../conformance.md); load figures are in [performance.md](../performance.md).
