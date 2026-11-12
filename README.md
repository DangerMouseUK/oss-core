# oss-core

SubSpace is a top-down multiplayer space shooter from 1997. Ships drift; bullets and bombs
carry your momentum with them; a map is 1024×1024 tiles of asteroid and wall with flags to
take and a team to take them from. When the publisher walked away, the players kept the game
running themselves — and they still are, on a client called Continuum and on zones that have
been up for twenty years.

**Open SubSpace** is that game written again in Rust, from the wire protocol upwards, so that
it outlives the binaries it grew up in. Not an emulator wrapped around the originals and not a
fork of anything: every packet, file format and physics rule was read back from the software
that is still running, and implemented fresh. The point is that it interoperates: a real
Continuum client has played on our server (with its cipher supplied by a private module —
see [What is not here](#what-is-not-here)), and our client has played on zones nobody here
wrote.

| Repository | What it is | Licence |
|---|---|---|
| **oss-core** — you are here | The shared half: packets, transport, map and settings formats, the physics simulation, and a conformance suite anyone can run | MIT |
| [oss-server](https://github.com/DangerMouseUK/oss-server) | The zone server. Runs an existing ASSS zone directory unchanged, and accepts Continuum, VIE and Open SubSpace clients on one port | GPL-2.0-or-later |
| [oss-client](https://github.com/DangerMouseUK/oss-client) | The game client, plus a headless bot on the same session code | GPL-2.0-or-later |

`oss-core` has no game loop and no window. It is what you reach for when you are writing a
bot, a tool, a zone server or another client — in Rust directly, or in any language through
the conformance suite's adapter protocol. It is MIT on purpose, so that it can be used by
projects that have nothing else to do with this one.

## The crates

| Crate | What it does |
|-------|--------------|
| `oss-proto` | Packet types and codecs for the game protocol |
| `oss-net` | Sans-IO transport: reliable layer, clustering, file transfer, ciphers (VIE, OpenSec) |
| `oss-formats` | `.lvl` maps, eLVL metadata, `.lvz` archives, `.ossr` replays |
| `oss-sim` | Deterministic 100 Hz integer simulation of ships, weapons and collision: client prediction and the server's plausibility checks, from one body of code ([`SETTINGS.md`](crates/oss-sim/SETTINGS.md)) |
| `oss-bot-sdk` | Zone bots in a few lines: login, arena, players, chat, kills |
| `oss-conformance` | Conformance suite for any implementation: 3,761 vector checks through a language-neutral adapter, plus live client and server checks |

## Why you would trust it

This project's habit is that a claim names its evidence. These are the ones worth checking
first.

**3,761 recorded checks, and one command runs them.** The vectors are output captured from
unmodified reference implementations — ASSS 1.4.4's own modules compiled as-is, nullspace's
exe checksum — not from this code. They cover VIE key exchange and encryption, the settings
packet layout, position and weapon checksums, the billing and directory protocols, map
parsing and relay framing.

```sh
cargo run --release -p oss-conformance -- vectors
```

```
group                           pass    fail    skip
opensec.handshake                 15       0       0
opensec.record                    60       0       0
…
settings.layout                 1692       0       0
vie.decrypt                      768       0       0
vie.encrypt                      768       0       0
3761 passed, 0 failed, 0 skipped
```

**Every protocol page says how far it has been verified.** [`docs/protocol/verification.md`](docs/protocol/verification.md)
sets out the evidence levels — *Vectors*, *Sources*, *Partly inferred*, *Observed*, *Open* —
and every packet page in [`docs/protocol/packets/`](docs/protocol/packets/README.md) carries
its own. Where sources disagree the page says so rather than picking quietly.

**OpenSec's test vectors were reproduced by a second implementation that shares no code with
this one.** [`crates/oss-net/tests/vectors/opensec_check.py`](crates/oss-net/tests/vectors/opensec_check.py)
is standard-library Python written from [the specification](docs/protocol/opensec.md) alone,
with its own X25519, ChaCha20-Poly1305 and HKDF, each first checked against the RFCs' own
vectors. It re-derives every record and handshake, and applies every rejection rule:

```sh
python3 crates/oss-net/tests/vectors/opensec_check.py
```

```
OpenSec vectors agree with the spec: 20 records, 5 handshakes, 7 rejected client hellos,
13 rejected server hellos, 6 window sequences
```

**The client's prediction and the server's anti-cheat are the same code.** `oss-sim` is a
fixed-step integer simulation with no floating point, used by [oss-client](https://github.com/DangerMouseUK/oss-client)
to predict and by [oss-server](https://github.com/DangerMouseUK/oss-server) to validate, so
the two cannot drift into false positives.

**Performance is measured, not asserted.** The transport's share of a 500-player arena is
5.3% of one core at the fan-out ASSS's relay rules actually produce over a whole map, with
VIE; 8.5% with OpenSec. [`docs/performance.md`](docs/performance.md) has the method, the
machine, the control runs, and the cases that cost more. CI gates it on every push.

**Every decoder has a fuzz target.** `fuzz/` holds cargo-fuzz targets for every packet, map,
LVZ and replay decoder and for the transport — twelve of them, most checking a round-trip
property rather than only "did not panic" ([`fuzz/README.md`](fuzz/README.md)). Untrusted
input is not allowed to panic the client or the server.

## Write a bot

[`crates/oss-bot-sdk/examples/greeter.rs`](crates/oss-bot-sdk/examples/greeter.rs) is a
complete bot in about forty lines: it greets players as they arrive and answers `!ping`.
Point it at any zone.

```sh
cargo run -p oss-bot-sdk --example greeter -- 127.0.0.1:5000 GreeterBot password
```

Seen from another client in the same arena:

```
GreeterBot> Welcome, Visitor! Say !ping to test me.
GreeterBot> pong #1
```

The SDK handles the handshake, login, arena entry, the map download and the security
challenge; your code sees events (`PlayerEntered`, `Chat`, `Kill`, …) and calls
`bot.send_private`, `bot.reply` and friends. To depend on it from your own project:

```toml
[dependencies]
oss-bot-sdk = { git = "https://github.com/DangerMouseUK/oss-core" }
```

## Checking another implementation

The suite will drive anything that speaks a line-based stdin/stdout protocol — one request per
line in, one response per line out — in any language:

```sh
cargo run --release -p oss-conformance -- vectors -- python3 my_adapter.py
```

It also checks live software — a running server, or a client that connects to it:

```sh
cargo run --release -p oss-conformance -- server 127.0.0.1:5000
cargo run --release -p oss-conformance -- client --bind 127.0.0.1:5000
```

[`docs/conformance.md`](docs/conformance.md) documents the adapter protocol and every check
group. There are also `directory` and `biller` modes for zone registration and SSC billing.

## Documentation

- **Writing a client, bot or tool:** [docs/implementing-a-client.md](docs/implementing-a-client.md)
  walks the whole path — connect, log in, enter an arena, download the map, answer the
  security checks, play — and says which crate does each part.
- **The protocol:** [docs/protocol/](docs/protocol/README.md), one page per packet, each
  with the evidence behind it.
- **File formats:** [`.lvl` and eLVL](docs/formats/lvl.md), [`.lvz`](docs/formats/lvz.md),
  [`.ossr` replays](docs/formats/replay.md).
- **OpenSec**, the optional modern transport (X25519 + ChaCha20-Poly1305):
  [docs/protocol/opensec.md](docs/protocol/opensec.md).
- **Performance and capacity planning:** [docs/performance.md](docs/performance.md).
- **What changed:** [docs/CHANGELOG.md](docs/CHANGELOG.md).

## Build and test

Nothing outside this repository is needed; it is a plain Cargo workspace.

```sh
cargo build --workspace
cargo test --workspace
```

`fuzz/` is excluded from the workspace and built separately (see `fuzz/README.md`).

[oss-server](https://github.com/DangerMouseUK/oss-server) and
[oss-client](https://github.com/DangerMouseUK/oss-client) expect this repository as a
**sibling checkout** and reach it by relative path. Note that `cargo fmt --all` *in one of
those repositories* reaches back into this one and rewrites it, because `cargo metadata`
lists path dependencies outside the workspace; plain `cargo fmt` there does not. Inside
oss-core, `cargo fmt --all` is correctly scoped to this repository.

## What is not here

- **Continuum's own encryption.** Its key expansion is not public, and it is not implemented
  or reverse-engineered in these repositories; that is a deliberate licensing and community
  decision, not an omission. `oss-net` exposes `Acceptor` and `Cipher` so a private build can
  register its own and have the rest of the stack work unchanged — which is how a real
  Continuum client came to play on oss-server. [docs/protocol/encryption.md](docs/protocol/encryption.md)
  documents the *shape* of the `00 10`–`00 14` exchange and nothing more.
- **Published crates.** Nothing here is on crates.io yet; use a git dependency or a path to a
  checkout.
- **A stable API.** Everything is 0.1.x and moves when the evidence says it should; see the
  changelog.

## Contributing

Issues and pull requests are welcome, and corrections most of all: if you have a capture, a
reference binary's behaviour or a reading of the original client that contradicts a page in
`docs/protocol/`, that is the most useful thing you can bring. Say where the evidence came
from and the page will say so too.

Before sending a change, run all four:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

The doc gate is not optional — it is the only one that catches a broken intra-doc link, and
docs.rs builds with all features.

## Licence

Code: MIT (see [`LICENSE`](LICENSE)). Documentation in `docs/`:
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

The MIT/GPL split across the three repositories is deliberate. `oss-core` is MIT so that
anyone's bot, tool or alternative client can build on it whatever licence they use;
`oss-server` and `oss-client` are GPL-2.0-or-later because they follow ASSS, whose behaviour
they reproduce and whose GPL source may be ported into them.

The test vectors are data: inputs and outputs recorded from reference implementations, some
of which are GPL programs; each file's header says which.
`crates/oss-formats/tests/fixtures/smallmap.lvl`, the reference server's GPL sample map, is
used by this repository's tests only and is left out of the published crates.

SubSpace and Continuum are the names of the original games; this project is an independent,
compatible implementation and is not affiliated with their authors.
