# Encryption

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-net::vie` and `oss-net::cipher`. Evidence for each part: [verification.md](verification.md).

The connection request (`00 01`) carries a protocol word that selects the encryption family: 0x0001 for SubSpace's **VIE** cipher, 0x0011 for **Continuum**. Servers may also fall back to VIE, or to no encryption, for Continuum clients.

## VIE

**Key negotiation**

- The client picks a 32-bit key with the top bit set.
- The server answers `00 02` with the negated key and keys its cipher with that value.
- The client accepts only the negation of its key (enable VIE) or its own key echoed back (no encryption). A key of 0 also means no encryption.

**Some servers gate the response behind a challenge.** Subgame 1.34.14 does not answer `00 01` directly. It replies with a six-byte `00 05`, and sends nothing at all until the client echoes the id back:

| Step | Packet | Length |
|---|---|---|
| C→S | `00 01 u32 key, u16 protocol` | 8 |
| S→C | `00 05 u32 id` | 6 |
| C→S | `00 06 u32 id` (plus the usual `u32` time, ignored here) | 6 or 10 |
| S→C | `00 02 u32 key` (subgame appends a `00`) | 6 or 7 |

Measured against subgame 1.34.14 by black-box probing: the server reads only that first `u32` of the `00 06` and ignores anything after it, so the timestamp an ordinary sync response carries is optional in this role. **Why the server requires the exchange is not known.** ASSS does not use it.

The six-byte `00 05` is the short form of the [sync request](packets/core-05-sync-request.md), so a client whose core-packet router is already running during setup answers it without noticing there was a challenge — which is the likely reason this went undocumented. A client that only watches for `00 02` while connecting sees silence instead, and reads it as a server that is down.

**Table**

- The session key seeds a generator that fills 260 16-bit values (520 bytes). The table is read as 130 little-endian 32-bit words.
- Each step is `k ← (k mod 127773)·16807 − ⌊k / 127773⌋·2836 + 123`; a result ≤ 0 has 0x7FFFFFFF added. This is Park–Miller with Schrage's method, plus 123. The table entry is the low 16 bits of `k`.
- *Quirk:* the server-side reference computes `⌊k / 127773⌋` with a multiply-and-shift. It is exact for non-negative `k`, but for negative `k` it gives the floor minus one. Only the first step can see a negative `k` (a session key with the top bit set). Normal negotiation always produces a positive session key, so this quirk only matters for exact compatibility tests.

**Packet transform**

- The first byte stays plain, or the first two bytes for core (`0x00`) packets. Core packets that are only two bytes long are therefore never altered.
- The rest is processed as consecutive 32-bit little-endian words. Each word is XORed with its table word and with the *previous ciphertext word* (the session key for the first word).
- A trailing partial word is treated as zero-padded, and only its real bytes are written.
- Decryption runs the same chain, using the received ciphertext words.
- The length never changes.

**Key edge cases** (the first two confirmed against the reference server):

- **Client key 1.** The server answers −1 (`0xFFFFFFFF`) and encrypts with it. The reference server's own *client* code uses −1 as a "bad key" sentinel and would run unencrypted, which breaks the session. This project follows the server: −1 is a normal key.
- **Client key `0x80000000`.** Its negation is itself, so the response looks like "no encryption" to a client, yet the reference server keys VIE with it. A client must never offer this key. `oss-net` never generates it (`client_key_from_seed` maps it to `0x80000001`), and `VieAcceptor` encrypts just as the reference server does.
- **Client keys below 1024 (subgame only).** Subgame 1.34.14 ignores a connection request whose client key is below 1024 and answers nothing — bisected, with 1023 silent and 1024 answered. A key of 0, which is how a client asks for no encryption, therefore cannot work against it, although it is correct for ASSS. Measured against that one server; the reason for the floor is not known.

The test vectors in `crates/oss-net/tests/vectors/vie.txt` come from running the reference VIE module unmodified. They cover key exchange, tables and per-packet encryption for 16 keys, including the two above.

## Continuum (shape only)

The Continuum cipher and its key expansion are not part of this repository. The transport supports them through plug-in traits.

**Setup sequence**

| Step | Packet | Length | Encrypted? |
|---|---|---|---|
| C→S | `00 01 key, 0x0011` | 8 | no |
| S→C | `00 10 u32 key1, u32 key2` | 10 | no |
| C→S | `00 11 u32 key1, u16 1` | 8 | no; from here both sides use the cipher |
| S→C | `00 02 key` | 6 | apparently yes |
| S→C, later | `00 12` | 2 or more | yes, in session |
| C→S | `00 13 00 00, u32 seed, 20 × u32` | 88 | yes, in session |

**Framing and receive-path rules**

- Ciphertext is up to 2 bytes longer than plaintext: one check byte, plus an escape byte prepended when the ciphertext would otherwise look like a connection packet.
- Servers must therefore check for `00 01` / `00 11` *before* decrypting.
- `00 12` and `00 13` arrive through the normal receive path, possibly reliable or clustered, and are passed to the cipher.

**The `00 12` / `00 13` exchange**

Read from the 0.40 client's own handler for subtype `0x12`, by running it. No server has been observed sending a `00 12`, so what a server does with the answer — or whether any server asks — is unknown; what follows is only what this client replies.

- **The client never reads the `00 12`.** Neither its payload nor its length is touched, and there is no length gate: any `00 12` of two bytes or more is answered identically. It therefore carries no seed, and nothing in the reply echoes it.
- **The reply is 88 bytes**: the two header bytes `00 13`, two zero bytes, a `u32` seed, then twenty `u32` words. Little-endian throughout, like the rest of the protocol.
***REMOVED***
***REMOVED***
- **Nothing is re-keyed.** The handler builds the reply from a scratch expander and leaves the connection's own cipher state, including its key words, untouched.
- `00 13` is client-to-server only: the client's dispatch table sends subtype `0x13` to its unknown-packet arm.

## Plug-in API (`oss-net`)

- **`Acceptor`** (server): inspects a new peer's first raw datagram, sends raw replies, and returns either an established `Cipher` or a pending `Handshake`.
- **`Handshake`** (either side): consumes raw setup datagrams and finally yields a `Cipher`. On the client, its first `poll` emits `00 01`.
- **`Cipher`**: encrypts and decrypts whole datagrams. It also receives in-session core subtypes ≥ 0x10 and can queue packets of its own.
