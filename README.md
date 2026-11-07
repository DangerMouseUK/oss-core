# oss-core

Shared building blocks for Open SubSpace, an open-source, modern client and server that interoperate with existing SubSpace/Continuum zones and clients.

| Crate | What it does |
|-------|--------------|
| `oss-proto` | Packet types and codecs for the game protocol |
| `oss-net` | Sans-IO transport: reliable layer, clustering, file transfer, ciphers (VIE, OpenSec) |
| `oss-formats` | `.lvl` maps, eLVL metadata, `.lvz` archives |

`docs/protocol` is the project's protocol reference, written as we implement it.

Used by [oss-server](https://github.com/DangerMouseUK/oss-server) and [oss-client](https://github.com/DangerMouseUK/oss-client), and intended for bots and tools in any language or licence.

## Licence

Code: MIT (see `LICENSE`). Documentation in `docs/`: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

SubSpace and Continuum are the names of the original games; this project is an independent, compatible implementation and is not affiliated with their authors.
