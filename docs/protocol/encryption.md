# Encryption

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-net::vie` and `oss-net::cipher`.

The connection request (`00 01`) carries a protocol word that selects the encryption family: 0x0001 for SubSpace's **VIE** cipher, 0x0011 for **Continuum**. Servers may also fall back to VIE, or to no encryption, for Continuum clients.

## VIE

**Key negotiation**

- The client picks a 32-bit key with the top bit set.
- The server answers `00 02` with the negated key and keys its cipher with that value.
- The client accepts only the negation of its key (enable VIE) or its own key echoed back (no encryption). A key of 0 also means no encryption.

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

Test vectors live in `crates/oss-net/src/vie.rs`.

## Continuum (shape only)

The Continuum cipher and its key expansion are not part of this repository. The transport supports them through plug-in traits.

**Setup sequence**

| Step | Packet | Length | Encrypted? |
|---|---|---|---|
| C→S | `00 01 key, 0x0011` | 8 | no |
| S→C | `00 10 u32 key1, u32 key2` | 10 | no |
| C→S | `00 11 u32 key1, u16 1` | 8 | no; from here both sides use the cipher |
| S→C | `00 02 key` | 6 | apparently yes |
| S→C, later | `00 12 u32 seed` | ≥ 6 | yes, in session |
| C→S | `00 13 u32 seed, 20 × u32` | 86 | yes, in session |

**Framing and receive-path rules**

- Ciphertext is up to 2 bytes longer than plaintext: one check byte, plus an escape byte prepended when the ciphertext would otherwise look like a connection packet.
- Servers must therefore check for `00 01` / `00 11` *before* decrypting.
- `00 12` and `00 13` arrive through the normal receive path, possibly reliable or clustered, and are passed to the cipher.

## Plug-in API (`oss-net`)

- **`Acceptor`** (server): inspects a new peer's first raw datagram, sends raw replies, and returns either an established `Cipher` or a pending `Handshake`.
- **`Handshake`** (either side): consumes raw setup datagrams and finally yields a `Cipher`. On the client, its first `poll` emits `00 01`.
- **`Cipher`**: encrypts and decrypts whole datagrams. It also receives in-session core subtypes ≥ 0x10 and can queue packets of its own.
