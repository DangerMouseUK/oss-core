# oss-net

A sans-IO transport for the SubSpace/Continuum protocol, part of [Open SubSpace](https://github.com/DangerMouseUK/oss-core). The same state machine serves clients, servers and bots, native and wasm. You feed it datagrams and a clock, and drain the datagrams it wants to send.

- Connection setup, reliable in-order delivery, clustering, and big and sized transfers with cancel.
- Time sync, disconnects and timeouts.
- `Server<A>` handles many connections keyed by address.
- Pluggable encryption through the `Cipher`, `Handshake` and `Acceptor` traits. VIE is built in, and so is OpenSec (X25519 + ChaCha20-Poly1305, default feature `opensec`). An external cipher can plug in without changes here.
- No per-packet allocations once warmed up, provided callers `recycle` buffers.

```rust
use oss_net::{Config, Connection, VieClientHandshake};

let mut conn = Connection::client(Config::client(), Box::new(VieClientHandshake::new(42)), 0);
let first = conn.poll_transmit().unwrap(); // the 00 01 connection request
// send it, then feed replies with conn.handle_datagram(now, &bytes),
// call conn.tick(now) every ~10 ms, and drain conn.poll_event().
# let _ = first;
```

Features:

| Feature | Default | Provides |
|---|---|---|
| `opensec` | yes | OpenSec encryption |
| `os-entropy` | yes | `opensec::os_entropy()` |

For `wasm32-unknown-unknown`, either disable `os-entropy` and pass your own entropy source, or configure getrandom's wasm backend.

The transport and OpenSec specifications (CC BY 4.0) are in [`docs/protocol`](https://github.com/DangerMouseUK/oss-core/tree/main/docs/protocol).

Licence: MIT.
