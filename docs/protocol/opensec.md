# OpenSec v1

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Reference implementation: `oss-net::opensec`. Test vectors: `crates/oss-net/tests/vectors/opensec.txt`. Evidence for each part: [verification.md](verification.md).

OpenSec is a modern replacement for the VIE and Continuum ciphers, built from standard primitives:

- **Confidentiality and integrity** for every datagram, via ChaCha20-Poly1305 (RFC 8439).
- **Forward secrecy**, via ephemeral X25519 key agreement (RFC 7748) on every connection.
- **Server authentication** when the server has a long-term X25519 key that the client knows (pinned) or trusts on first use.
- **Replay protection**, via per-direction counters and a sliding window.
- **Coexistence with existing servers.** The client hello is ignored by servers that only speak SubSpace/Continuum, so clients can try OpenSec first and fall back to VIE.

It sits below the [transport](transport.md) exactly where VIE does: it encrypts whole datagrams after framing and decrypts them before dispatch.

Notation: `||` is concatenation; integers are little-endian; `X25519(k, P)` is the RFC 7748 function; `HKDF` is HKDF-SHA256 (RFC 5869).

## Handshake

### Client hello (client → server, 42 bytes, sent in the clear)

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | `00 01` |
| 2 | 4 | `OSEC` |
| 6 | 1 | version: 1 |
| 7 | 1 | flags: 0 |
| 8 | 2 | capabilities the client supports |
| 10 | 32 | client ephemeral public key `Ec` |

The client resends the hello every 250 ms until it gets an answer. Servers that don't support OpenSec ignore it, because they accept only 8-byte `00 01` packets. To fall back, a client switches to a VIE `00 01` after a timeout (about 1 s).

### Server hello (server → client, 58 or 90 bytes, sent in the clear)

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | `00 02` |
| 2 | 4 | `OSEC` |
| 6 | 1 | version: 1 |
| 7 | 1 | flags: 0 |
| 8 | 2 | selected capabilities |
| 10 | 32 | server ephemeral public key `Es` |
| 42 | 32 | server static public key `S`, present only if `SERVER_AUTH` is selected |
| end − 16 | 16 | confirmation tag |

**Capabilities:**

| Bit | Name | Meaning |
|---|---|---|
| 0x0001 | `SERVER_AUTH` | the server has a static key, sends it, and mixes it into the keys |

The server sets `SERVER_AUTH` exactly when it has a static key. For any other bit, it selects the intersection of the client's and its own capabilities. All other bits are reserved and must be 0.

### Key schedule

1. `ee = X25519(ec, Es)` on the client, or `X25519(es, Ec)` on the server. Reject the handshake if `ee` is all zero (a low-order point).
2. `es_static = X25519(ec, S)` on the client, or `X25519(s, Ec)` on the server, if `SERVER_AUTH` is selected; otherwise empty.
3. `transcript = SHA-256(client hello || server hello without its last 16 bytes)`.
4. `okm = HKDF(salt = "OpenSec v1 handshake", ikm = ee || es_static, info = transcript, L = 64)`.
5. `key_c2s = okm[0..32]`, `key_s2c = okm[32..64]`.
6. Confirmation tag: the ChaCha20-Poly1305 tag computed with key `key_s2c`, nonce `N(S2C, 0)`, associated data `transcript`, and an empty plaintext.

### Client checks

The client must:

1. verify the length, magic and version;
2. if it pinned a server key, require `SERVER_AUTH` and that `S` equals the pinned key;
3. recompute the keys and verify the confirmation tag.

Any failure ends the handshake. The client must **not** fall back to VIE after a failure, because that would allow a downgrade. Without a pin, the client may record `S` (trust on first use) and pin it next time.

The server treats the session as established when it sends its hello. The client's first encrypted datagram (normally its login) proves the client derived the same keys.

### Repeated hellos

If a server receives the same client hello again from the same address before any session traffic, it must resend the same server hello and must not derive new keys. A *different* hello from that address starts a new handshake.

## Records

Every datagram after the handshake, in both directions:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `0xF5` |
| 1 | 4 | low 32 bits of the sender's counter |
| 5 | n | ciphertext (the plaintext datagram, which may be a core packet) |
| 5+n | 16 | Poly1305 tag |

- **Counters.** Each direction has its own 64-bit counter. It starts at 1 for the first record (S2C counter 0 is used by the confirmation tag) and increases by one per datagram.
- **Nonce:** `N(dir, counter) = u32 dir || u64 counter`, where dir = 1 for client-to-server and 2 for server-to-client.
- **Associated data:** the 5-byte record header.
- **Overhead:** 21 bytes per datagram. Senders keep plaintext datagrams 21 bytes below their normal limit, so with a 512-byte limit the plaintext is at most 491 bytes.
- **The marker byte is never `0x00`,** so a server's check for connection requests (`00 01`), made before decryption, can never match an encrypted datagram.

**Receiving a record:**

1. Reconstruct the full counter from its low 32 bits by choosing the value closest to the highest counter accepted so far.
2. Drop the record if that counter is 0, already accepted, or more than 63 below the highest accepted.
3. Decrypt and verify, dropping the record on failure.
4. Only then mark the counter as accepted.

Rejected records are dropped silently; the transport's retransmission covers losses.

## Security notes

- **Pinning.** Without a pinned key, the first connection to a server can be intercepted by an active attacker, as with SSH's trust on first use. Distribute server keys out of band (for example, through a directory listing signed by its operator) and pin them.
- **Downgrade.** An attacker who drops OpenSec hellos can force VIE fallback. Clients that pinned a key should require OpenSec and never fall back.
- **Entropy.** Ephemeral keys must come from a cryptographically secure source. `oss-net` takes the source as a parameter (`opensec::os_entropy` uses the operating system).
- **Rekeying.** There is none. 64-bit counters do not wrap in practice, and connections are short-lived compared with the counter space.
- **Client identity.** v1 has none at this layer. Authenticating players stays with the game login (and, later, key-bound identities).
