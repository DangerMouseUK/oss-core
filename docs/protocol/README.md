# SubSpace protocol reference

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

A versioned, implementation-driven description of the SubSpace/Continuum network protocol. Each page records packet layouts, field meanings, ordering rules and known quirks, verified against working implementations and the tests in this repository.

| Page | Contents |
|---|---|
| [transport.md](transport.md) | core `0x00` packets: setup, reliable delivery, clusters, big and sized transfers, time sync, disconnects, size limits |
| [encryption.md](encryption.md) | the VIE cipher, the shape of the Continuum handshake, the plug-in model |
| [game-packets.md](game-packets.md) | every server-to-client and client-to-server game packet |
| [settings.md](settings.md) | the 1428-byte arena settings packet and its configuration keys |
| [checksums.md](checksums.md) | file, position and security checksums; the game RNG |

File formats are documented in [../formats](../formats): [`.lvl` and eLVL](../formats/lvl.md), [`.lvz`](../formats/lvz.md).

Where sources disagree, the pages say so and give the reading this project implements.
