# oss-core

Shared building blocks for Open SubSpace, an open-source, modern client and server that interoperate with existing SubSpace/Continuum zones and clients.

| Crate | What it does |
|-------|--------------|
| `oss-proto` | Packet types and codecs for the game protocol |
| `oss-net` | Sans-IO transport: reliable layer, clustering, file transfer, ciphers (VIE, OpenSec) |
| `oss-formats` | `.lvl` maps, eLVL metadata, `.lvz` archives, `.ossr` replays |
| `oss-bot-sdk` | Zone bots in a few lines: login, arena, players, chat, kills (example: `examples/greeter.rs`) |
| `oss-conformance` | Conformance suite for any implementation: 3,715 vector checks via a language-neutral adapter, plus live client and server checks (`docs/conformance.md`) |

## Getting started

- **Writing a client, bot or tool?** Start with [docs/implementing-a-client.md](docs/implementing-a-client.md). It walks through connecting, logging in, entering an arena, the map download, the security checks and playing, and says which crate does each part. For a bot, `oss-bot-sdk` already does all of it.
- **Checking an implementation**, in any language: [docs/conformance.md](docs/conformance.md).
- **The protocol:** [docs/protocol](docs/protocol/README.md), with one page per packet and the evidence behind each detail.
- **Performance and capacity planning:** [docs/performance.md](docs/performance.md).

`fuzz/` holds cargo-fuzz targets for every decoder and the transport.

Used by [oss-server](https://github.com/DangerMouseUK/oss-server) and [oss-client](https://github.com/DangerMouseUK/oss-client), and intended for bots and tools in any language or licence.

## Licence

Code: MIT (see `LICENSE`). Documentation in `docs/`: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

The test vectors are data: inputs and outputs recorded from reference implementations, some of which are GPL programs; each file's header says which. `crates/oss-formats/tests/fixtures/smallmap.lvl`, the reference server's GPL sample map, is used by this repository's tests only and is left out of the published crates.

SubSpace and Continuum are the names of the original games; this project is an independent, compatible implementation and is not affiliated with their authors.
