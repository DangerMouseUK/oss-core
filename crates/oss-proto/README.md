# oss-proto

Wire types and codecs for the SubSpace/Continuum game protocol, part of [Open SubSpace](https://github.com/DangerMouseUK/oss-core).

- Every game packet in both directions (`S2CPacket`, `C2SPacket`), plus the core `0x00` transport packets.
- The 1428-byte arena settings packet (`ClientSettings`), with configuration-key tables.
- Directory-server and billing-server protocols.
- The security checksums (settings, map, VIE exe), the position checksum, CRC-32 and the game RNG (`VieRng`).

Decoders take `&[u8]` and never panic on malformed input. The crate is `no_std` + `alloc`. It is checked against vectors produced by running the reference server's own code.

```rust
use oss_proto::{S2CPacket, s2c};

let bytes = S2CPacket::from(s2c::PlayerLeaving { pid: 7 }).to_bytes();
match S2CPacket::decode(&bytes)? {
    S2CPacket::PlayerLeaving(p) => assert_eq!(p.pid, 7),
    other => panic!("unexpected {other:?}"),
}
# Ok::<(), oss_proto::DecodeError>(())
```

The protocol reference (CC BY 4.0) is in [`docs/protocol`](https://github.com/DangerMouseUK/oss-core/tree/main/docs/protocol).

Licence: MIT.
