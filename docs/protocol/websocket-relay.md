# WebSocket relay (`oss-relay.1`)

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Codec: `oss-net::relay`. Evidence for each part: [verification.md](verification.md).

Browsers cannot send UDP datagrams, so a browser client can't talk to a zone directly. Instead, it opens a WebSocket to a **relay** and sends every SubSpace datagram as one WebSocket message. The relay forwards each datagram to the zone unchanged, and sends the zone's replies back the same way.

The relay never parses or alters the datagrams. Everything above it — connection setup, reliable delivery, clustering, VIE or OpenSec — works exactly as it does over UDP.

```
browser client ──WebSocket (wss)── relay ──UDP── zone
               one message = one datagram     one socket per browser
```

A relay can run as a separate process in front of an unmodified zone, or inside the server. Inside the server, it feeds datagrams straight into the transport, with the WebSocket session as the peer's address.

## Carrier

- **WebSocket** (RFC 6455) with the subprotocol `oss-relay.1` in `Sec-WebSocket-Protocol`.
  - A relay must refuse the upgrade if the client did not offer the subprotocol.
  - Pages served over HTTPS can only open `wss://`, so public relays need TLS.
- **Messages.** Every message is a **binary** message holding exactly one frame. A text message is a protocol error.
- **Byte streams.** Any reliable byte stream (raw TCP, a WebTransport stream) can carry the same frames. Each frame is prefixed with its length:
  - the prefix is a `u16` LE, in the range 1 to 1025;
  - a prefix of 0 or above 1025 means the peer isn't speaking this protocol, and the receiver closes the stream.
- **Browsers on UDP-like transports.** A browser on WebTransport *datagrams* could carry SubSpace datagrams without a relay framing at all. That is out of scope for v1.

## Frames

Each frame is one type byte, then the payload. Integers are little-endian.

| Type | Name | Direction | Payload |
|---|---|---|---|
| `0x01` | datagram | both | one SubSpace datagram, 1–1024 bytes, unchanged |
| `0x02` | hello | client → relay | `u8 version`, `u8 flags` (0), `u8 zone_len`, `zone_len` bytes of UTF-8 zone name (≤ 64; empty = the relay's default zone) |
| `0x03` | welcome | relay → client | `u8 version`, `u16 max_datagram`, `u32 idle_timeout_ms` |
| `0x04` | close | both | `u8 reason`, then a UTF-8 message filling the rest (≤ 120 bytes) |

**Datagrams.** The 1024-byte limit is generous on purpose: SubSpace datagrams are at most 520 bytes, plus 21 bytes when OpenSec is used.

**Forward compatibility.** Receivers ignore extra bytes after the known fields of `hello` and `welcome`, so later versions can append fields. An unknown frame type is a protocol error.

**Close reasons:**

| Value | Meaning |
|---|---|
| 0 | normal shutdown |
| 1 | unsupported version |
| 2 | unknown zone |
| 3 | busy (too many sessions in total or from this address) |
| 4 | idle timeout |
| 5 | protocol error (malformed or unexpected frame, rate limit) |
| 6 | banned |
| 7 | zone unreachable |

Treat other values like 0. The close message also fits in a WebSocket close frame's reason, so a relay may repeat it there.

## Session

1. The client opens the WebSocket and sends `hello`. It must not send datagrams before `welcome`; a relay drops (or treats as a protocol error) any datagram that arrives first.
2. The relay replies in one of two ways:
   - **Accept:** it sends `welcome` with the version it will speak (at most the client's), its `max_datagram`, and its idle timeout.
   - **Refuse:** it sends `close` (unsupported version, unknown zone, busy, banned) and closes the WebSocket.

   If no `hello` arrives within 10 seconds, the relay closes the connection.
3. **Datagrams flow both ways.**
   - The client then runs the normal SubSpace connection over the session, starting with its `00 01` connection request (or an OpenSec hello).
   - A datagram larger than the peer's `max_datagram` is dropped, not truncated.
4. **Ending the session.** Either side may send `close` and then close the WebSocket. Closing the WebSocket without `close` means reason 0.
   - Ending the relay session does **not** send a SubSpace disconnect. A client leaving properly sends `00 07` first, as usual.
   - When the WebSocket closes without one, the relay (or the server, for a built-in relay) should send `00 07` to the zone on the client's behalf. That way the player leaves at once instead of after the zone's 30-second timeout.

## One connection per peer

Each WebSocket session is one SubSpace peer:

- **Separate relay.** It opens one UDP socket per session, so the zone sees a distinct source address and port for each browser player. The relay forwards only datagrams from that socket's zone address back to that session.
- **Built-in relay.** The server keys the session in its connection table (in `oss-net`, `Server<A>`'s address type), for example `enum Peer { Udp(SocketAddr), Relay(u64) }`. It reports the browser's IP address, taken from the TCP connection (or a trusted proxy header), for bans and logs.

A separate relay hides the players' addresses from the zone, because all of them arrive from the relay's IP. Zones that ban by IP should either:

- trust only relays they run themselves, which enforce the bans on the relay side; or
- use a built-in relay.

## Limits a relay should enforce

| Limit | Suggested value |
|---|---|
| time to receive `hello` | 10 s |
| idle timeout (no frame either way) | 60 s; SubSpace keepalives keep a live session busy |
| sessions per client IP | 4 |
| sessions in total | as configured for the zone |
| frames per second per session, client → relay | 200 |
| bytes per second per session, client → relay | 64 KiB |
| datagram size | 1024 bytes (`max_datagram` in `welcome`) |

When a client exceeds a rate limit, the relay sends `close` with reason 5 and closes the WebSocket. Dropping excess frames instead is also acceptable: SubSpace's own retransmission copes.

## Encryption

The relay forwards datagrams byte for byte, so whatever encryption the client and zone agree on works end to end:

- **OpenSec** ([opensec.md](opensec.md)) protects the game traffic between the browser and the zone. A relay run by someone else sees only ciphertext, and a pinned server key still authenticates the zone itself, not the relay. OpenSec's 21-byte overhead fits within the 1024-byte limit. This is the recommended setup for browser clients.
- **TLS** (`wss://`) protects only the browser ↔ relay hop. It is needed regardless, because browsers require it on HTTPS pages.
- **VIE** passes through too, but adds no real protection. Plain WebSocket (`ws://`) with VIE is suitable only for local testing.

## Notes for implementers

- **Transport behaviour.** WebSocket runs over TCP, which is already reliable and ordered. SubSpace's reliable layer still runs on top and is harmless: retransmissions only happen if acknowledgements are late.
  - Packet loss over the relay shows up as latency (TCP head-of-line blocking) rather than loss.
  - Clients behind a relay may want a larger retransmission timeout. They need no other changes.
- **Time sync.** Sync packets (`00 05` / `00 06`) measure the full browser ↔ zone round trip, relay included, which is what the game needs.
- **Codec.** `oss-net::relay` provides:
  - `Frame`, for WebSocket messages;
  - `StreamDecoder` and `write_stream_frame`, for byte streams.

  It does no I/O. A browser client wraps `Connection::poll_transmit` output in `Frame::Datagram`, and feeds incoming `Frame::Datagram` payloads to `Connection::handle_datagram`.

## Trying it

`oss-net` carries a working pair:

- **`examples/relay_echo.rs`:** a relay in front of an echo zone.
- **`examples/browser.rs`:** `oss-net` compiled to WebAssembly, run in a browser.

The browser example opens the WebSocket with the `oss-relay.1` subprotocol and sends `hello`. On `welcome` it runs a normal `Connection`: OpenSec, falling back to VIE. It then checks that 50 small packets and one 3,000-byte packet (split across datagrams) come back in order.

```sh
cargo run -p oss-net --example relay_echo -- 127.0.0.1:5700
cargo build --release --target wasm32-unknown-unknown -p oss-net --example browser
wasm-bindgen --target web --out-dir crates/oss-net/examples/browser/pkg     target/wasm32-unknown-unknown/release/examples/browser.wasm
# serve crates/oss-net/examples/browser/ over HTTP, e.g.:
python -m http.server 8765 --directory crates/oss-net/examples/browser
# then open http://127.0.0.1:8765/index.html
```

Run on 2026-11-08 in a Chromium-based browser, the page reported `PASS: 51 packets … encryption Some(OpenSec)`. `wasm-bindgen` must match the `wasm-bindgen` version in `Cargo.lock`.

`tests/relay_e2e.rs` runs the same exchange natively, through a real WebSocket on loopback, with VIE and with OpenSec, on every CI run.
