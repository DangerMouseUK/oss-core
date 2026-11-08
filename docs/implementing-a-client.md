# Implementing a client with oss-core

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

This guide is for anyone writing a SubSpace-compatible client, bot or tool on top of these crates. It walks through what a client must do, in order, and which crate does each part.

For a complete, small example, read `crates/oss-bot-sdk/src/session.rs` (MIT). It does every step below in about 700 lines. If a bot is all you need, use `oss-bot-sdk` directly.

## The crates

| Crate | Use it for |
|---|---|
| `oss-net` | The connection: handshake, encryption (VIE, OpenSec), reliable delivery, clustering, big and sized transfers, time sync. It does no I/O itself: you feed it datagrams and the time, and send what it gives you. |
| `oss-proto` | Every packet as a Rust type (`S2CPacket`, `C2SPacket`), the 1428-byte settings packet (`ClientSettings`), and the checksums the server asks for. |
| `oss-formats` | Maps (`.lvl`, eLVL regions), LVZ archives, replays. |
| `oss-conformance` | Checking your client against a zone that the suite simulates. |

The protocol itself is documented in [protocol/](protocol/README.md), with one page per packet in [protocol/packets/](protocol/packets/README.md).

## 1. Connect

Create a `Connection` with a handshake and drive it from your event loop. `oss-net` never touches the socket or the clock.

```rust
use oss_net::{Config, Connection, Event, VieClientHandshake};

let mut conn = Connection::client(Config::client(), Box::new(VieClientHandshake::new(seed)), now_ms);
loop {
    // 1. every datagram from the server:  conn.handle_datagram(now_ms, &bytes);
    // 2. about every 10 ms:               conn.tick(now_ms);
    // 3. send everything it produces:     while let Some(d) = conn.poll_transmit() { socket.send(&d); conn.recycle(d); }
    // 4. handle events:
    while let Some(event) = conn.poll_event() {
        match event {
            Event::Connected => { /* send the login (step 2) */ }
            Event::Packet(p) => { /* a complete game packet: decode it (step 3) */ conn.recycle(p); }
            Event::Disconnected(reason) => { /* done */ }
            _ => {}
        }
    }
}
```

**Encryption:**

- **VIE** (`VieClientHandshake`) works with every SubSpace server.
- **OpenSec:** to use it where available, wrap `opensec::OpenSecClientHandshake` and the VIE handshake in `cipher::Fallback`. Servers that don't speak OpenSec ignore its hello, so the client drops back to VIE after a second.
- **Continuum's encryption** is not public. It plugs in through the same `Handshake` and `Cipher` traits from outside this repository.

**Sending.** Use `conn.send(&bytes, reliable)`, or `send_with` for priorities and droppable packets. Logins, chat and most commands go reliable; positions go unreliable.

## 2. Log in

Send C2S `0x09` (`c2s::Login`; `Login::default()` fills the usual constants) with the name and password.

The server answers with S2C `0x0A` (`s2c::LoginResponse`):

- **Codes 0, 6 and 13** mean you're in.
- **Code 1** means the name is unknown. Send the login again with `flags = 1` to create the account.
- The other codes are listed on the [login response page](protocol/packets/s2c-0a-login-response.md).

## 3. Enter an arena

Send C2S `0x01` (`c2s::GoArena`) as a spectator (ship 8), for a named arena or any public one. The server then sends, in this order:

1. S2C `0x01`: your player id;
2. S2C `0x0F`: the settings. Decode them with `ClientSettings::decode`, and **keep the raw 1428 bytes** for the settings checksum;
3. S2C `0x03`: every player already there, then you;
4. S2C `0x29`: the map's file name and CRC-32;
5. S2C `0x02`: arena entry complete.

Ask for a ship with C2S `0x18` only after `0x02`.

`oss_proto::settings::layout()` lists where every named setting lives, which helps you check which ones your simulation reads.

## 4. Get the map

If you don't already have a file with the announced name and CRC-32, send C2S `0x0C` (`c2s::MapRequest { index: None }`).

The map arrives as S2C `0x2A`: the file name, then the zlib-compressed `.lvl`. It travels as a sized transfer, and `oss-net` hands you the whole packet when it's complete.

Decompress it, check `oss_proto::checksum::crc32` against the announced value, then `oss_formats::Level::parse` it. Use `level.server_tile_grid()` for collision and for the map checksum: big objects are expanded the way servers expect.

## 5. Answer security checks

S2C `0x18` (`s2c::Security`) carries the prize and door seeds for `oss_proto::VieRng`. A non-zero `key` also asks for C2S `0x1A` (`c2s::SecurityResponse`) with:

- `settings_checksum(key, raw_settings_bytes)`;
- `map_checksum(key, |x, y| grid.get(x, y))`;
- `vie_exe_checksum(key)`: what a SubSpace 1.34 client reports.

All three are in `oss_proto::checksum`. Wrong values get you kicked from zones that check.

## 6. Play

- **Positions.** Send C2S `0x03` (`C2SPosition`) about every 100 ms while flying, and every second or so as a spectator. Set `time` to `conn.server_ticks(now)`. The encoder fills in the checksum.
- **Other players' positions** arrive as S2C `0x28` (small form) and `0x05` (with a weapon, or a large pid or bounty).
- **Chat** goes out as C2S `0x06` and comes in as S2C `0x07`. Text is single-byte, effectively Latin-1.
- **Everything else**, such as kills, prizes, flags, balls, bricks and LVZ objects, is one decode away: `S2CPacket::decode(&packet)`. The packet pages say what each field means and how sure we are of it.

## 7. Leave

Send C2S `0x02` to leave the arena, then `conn.disconnect()`, which sends `00 07`.

## Check your client

Run the suite as a zone and point your client at it:

```sh
oss-conformance client --bind 127.0.0.1:5000
```

It checks the connection request, login, acknowledgements, arena entry, map download, position checksums, time sync and all three security checksums (see [conformance.md](conformance.md)).

For a client in another language, `oss-conformance vectors -- <your adapter>` also checks your packet codecs, ciphers and checksums against 3,715 test vectors.

## Browsers

`oss-proto`, `oss-net` and `oss-formats` build for `wasm32-unknown-unknown`. A browser can't send UDP, so it carries each datagram in a WebSocket message through a relay ([protocol/websocket-relay.md](protocol/websocket-relay.md)). `oss_net::relay::Frame` does the framing; everything above it is the same `Connection`.
