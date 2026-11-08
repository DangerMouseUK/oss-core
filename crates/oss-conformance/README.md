# oss-conformance

A conformance suite for SubSpace/Continuum protocol implementations, part of [Open SubSpace](https://github.com/DangerMouseUK/oss-core). Use it to check a client, bot, server or library in any language.

```sh
oss-conformance vectors -- python3 my_adapter.py   # 3,725 offline checks via a stdin/stdout adapter
oss-conformance server zone.example:5000            # the suite acts as a client
oss-conformance client --bind 0.0.0.0:5000          # the suite acts as a zone
```

- **Vectors:** VIE encryption, every security checksum, the settings packet layout, OpenSec, canonical encodings of every packet, and WebSocket relay frames. Most come from running unmodified reference implementations. The implementation under test answers one-line requests on stdin/stdout, so an adapter can be written in any language.
- **Live server checks:** the transport (handshake, time sync, reliable delivery, duplicates, clusters, disconnect), login, arena entry, map download and the security exchange.
- **Live client checks:** the connection request, login, acknowledgements, arena entry, map download, position checksums, time sync and the security checksums.

The adapter protocol and every check are described in [`docs/conformance.md`](https://github.com/DangerMouseUK/oss-core/blob/main/docs/conformance.md). The library API (`adapter`, `live`, `vectors`) lets you run the same checks from Rust tests:

```rust
use oss_conformance::{adapter, vectors};

let report = adapter::run(&mut adapter::Reference, &vectors::cases(), Some("checksum."))?;
assert!(report.passed());
# Ok::<(), std::io::Error>(())
```

Licence: MIT. The vector files are data: some were produced by running GPL reference servers, and their headers say which.
