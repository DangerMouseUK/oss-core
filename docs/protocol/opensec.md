# OpenSec v1

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

**Status: draft for external cryptographic review.** OpenSec is not yet deployed on any public server, so the wire format can still change. Section 8 lists the questions we would most like a reviewer to answer.

| | |
|---|---|
| Reference implementation | `crates/oss-net/src/opensec.rs` (Rust) |
| Test vectors | `crates/oss-net/tests/vectors/opensec.txt`, format in section 9 |
| Independent check | `crates/oss-net/tests/vectors/opensec_check.py`: a second implementation written from this document alone, standard-library Python with its own X25519, ChaCha20-Poly1305 and HKDF. It reproduces every vector and applies every rejection rule |
| Evidence levels | [verification.md](verification.md) |

## 1. What it is for

SubSpace and Continuum encrypt game traffic with home-grown ciphers: VIE (an XOR keystream from a 32-bit key; see [encryption.md](encryption.md)) and Continuum's own scheme. Neither gives confidentiality against a passive observer or any integrity. OpenSec replaces them for clients and servers that both support it.

- **Built from standard primitives:** X25519, ChaCha20-Poly1305, HKDF-SHA256 and SHA-256.
- **Coexists with the old protocol:** it sits below the [transport](transport.md) exactly where VIE does. Servers that only speak SubSpace/Continuum ignore its hello, so a client can try OpenSec first and fall back.

The protocol is deliberately small: one round trip, one optional server key, no certificates and no negotiation beyond one capability bit.

## 2. Threat model and goals

**Attacker.** A network attacker who can read, drop, delay, reorder, replay and inject UDP datagrams, and send datagrams with any source address. The attacker does not control either endpoint.

**Goals.**

| | Goal |
|---|---|
| G1 | **Confidentiality and integrity** of every datagram after the handshake. |
| G2 | **Forward secrecy:** recording a session and later stealing the server's long-term key, or either side's state after the session ends, reveals nothing about the session's traffic. |
| G3 | **Server authentication** when the client already knows the server's static public key (pinned, or trusted on first use). The client then knows it shares keys with the holder of that key. |
| G4 | **No replays.** Each record is accepted at most once. Records may be reordered within a 64-record window. |
| G5 | **Independent keys** per session and per direction. |
| G6 | **No amplification:** answering a hello, even one from a spoofed address, never sends more bytes than were received. |

**Non-goals.**

- **Client authentication.** Players still log in with the game's password login, now inside the encrypted channel.
- **Hiding metadata.** Datagram sizes, timing, the low 32 bits of each record counter, and the fact that OpenSec is in use are all visible.
- **Denial-of-service resistance** beyond G6. An on-path attacker can always drop traffic; see section 8 for off-path concerns.
- **Server authentication without a pin.** The first connection to an unpinned server is open to an active attacker, as with SSH.
- Post-quantum security, and protection against compromised endpoints.

## 3. Notation and primitives

- `||` is concatenation. All integers are **little-endian**. `u16`, `u32` and `u64` are their sizes in bytes on the wire: 2, 4 and 8.
- `X25519(k, u)`: RFC 7748, section 5, including scalar clamping and masking the top bit of `u`. Private keys are 32 random bytes; clamping happens inside the function. `pub(k) = X25519(k, 9)`.
- `SHA256`: FIPS 180-4.
- `HKDF(salt, ikm, info, L)`: HKDF-SHA256, extract then expand (RFC 5869).
- `Seal(key, nonce, ad, plaintext) -> (ciphertext, tag)` and `Open`: the ChaCha20-Poly1305 AEAD of RFC 8439, section 2.8, with a 32-byte key, a 12-byte nonce and a 16-byte tag.
- `N(dir, counter) = u32(dir) || u64(counter)`, a 12-byte nonce. `dir` is 1 for client-to-server (C2S) and 2 for server-to-client (S2C).
- "Low-order result": an X25519 output of 32 zero bytes. That is what a small-order peer key produces. Implementations compare the output with zero; in RustCrypto's terms, the result is not "contributory".

## 4. Handshake

```
client                                          server
  generate ephemeral ec, Ec = pub(ec)
  ClientHello(Ec) ─────────────────────────────▶  check; generate ephemeral es, Es = pub(es)
                                                   derive keys; session established
  ◀───────────────────────────── ServerHello(Es [, S], confirm tag)
  check; derive keys; verify tag
  session established
  first record (normally the game login) ──────▶  first proof that the client has the keys
```

### 4.1 Client hello (client → server, 90 bytes, in the clear)

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | `00 01` (the SubSpace connection-request type) |
| 2 | 4 | `OSEC` (`4F 53 45 43`) |
| 6 | 1 | version: `01` |
| 7 | 1 | flags: `00` |
| 8 | 2 | capabilities the client supports (u16); v1 clients send `SERVER_AUTH` (0x0001) |
| 10 | 32 | client ephemeral public key `Ec` |
| 42 | 48 | padding: zeros |

The padding makes the client hello as long as the largest server hello (G6). Its value is not checked, but it is part of the transcript, so it is authenticated whenever the server is.

A SubSpace/Continuum server accepts only an 8-byte `00 01`, so it ignores this packet.

### 4.2 Server processing

The server ignores the hello (sends nothing, keeps no state) unless all of these hold, checked in order:

1. The length is exactly 90, and bytes 0–5 are `00 01 OSEC`.
2. The version is 1.
3. `ee = X25519(es, Ec)` is not a low-order result, where `es` is a fresh ephemeral private key.

The flags byte and the padding are ignored. They are covered by the transcript (section 4.4).

**Selected capabilities.** The server selects `client_caps & server_caps`. It then sets `SERVER_AUTH` if and only if it has a static key pair `(s, S = pub(s))`. A v1 server's own capabilities are just `SERVER_AUTH`, so all other bits come out 0.

The server then derives the keys (section 4.4), sends its hello, and considers the session established. Records from the client may arrive straight away.

### 4.3 Server hello (server → client, 58 or 90 bytes, in the clear)

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | `00 02` |
| 2 | 4 | `OSEC` |
| 6 | 1 | version: `01` |
| 7 | 1 | flags: `00` |
| 8 | 2 | selected capabilities (u16) |
| 10 | 32 | server ephemeral public key `Es` |
| 42 | 32 | server static public key `S`; present only if `SERVER_AUTH` is selected |
| end − 16 | 16 | confirmation tag |

### 4.4 Key schedule

```
ee         = X25519(ec, Es)               client side
           = X25519(es, Ec)               server side
es_static  = X25519(ec, S) / X25519(s, Ec)   if SERVER_AUTH is selected, else empty (zero bytes)
transcript = SHA256(client_hello || server_hello[0 .. len − 16])
okm        = HKDF(salt = "OpenSec v1 handshake" (20 ASCII bytes),
                  ikm  = ee || es_static     (32 or 64 bytes),
                  info = transcript, L = 64)
key_c2s    = okm[0 .. 32]
key_s2c    = okm[32 .. 64]
confirm    = tag of Seal(key_s2c, N(2, 0), ad = transcript, plaintext = empty)
```

The transcript covers both hellos byte for byte, including the capabilities, `S`, the flags and the padding. Any change to either hello therefore changes both keys.

### 4.5 Client processing

The client fails the handshake on the first of these that does not hold:

1. The length is at least 58, bytes 0–5 are `00 02 OSEC`, and the version is 1.
2. The selected capabilities contain no bit the client did not offer.
3. The length is exactly 90 if `SERVER_AUTH` is selected, otherwise exactly 58.
4. `ee` is not a low-order result.
5. If the client has pinned a key for this server: `SERVER_AUTH` is selected and `S` equals the pinned key.
6. If `SERVER_AUTH` is selected: `es_static` is not a low-order result.
7. The confirmation tag equals the one the client computes (compared in constant time).

**After a failure,** the client must not fall back to VIE for that server, because that would turn any tampering into a downgrade. It may retry OpenSec.

**On success,** the client uses the keys. If the server sent `S` and nothing was pinned, the client may record `S` and pin it from then on (trust on first use).

Datagrams that don't start with `00 02 OSEC` don't affect the handshake. The exception is `00 07` (the SubSpace disconnect), which ends it.

### 4.6 Retransmission and duplicates

**Client resends.** The client sends its hello again every 250 ms until it gets a server hello. Every copy is identical, so it keeps the same ephemeral key. The reference client gives up after 10 s.

**Server, same address, before any session traffic:**

- **An identical hello** (the server's reply was lost): the server resends its stored server hello byte for byte. It does not derive new keys.
- **A different hello:** the server starts a new handshake and replaces the keys.

**Server, after session traffic has started:** a new `00 01` (OpenSec or VIE) from the same address ends the old session, and the client's retries then reach a fresh one. This is the legacy reconnect behaviour; see section 8, question 2.

**Client after success.** Later copies of the server hello are not records (they don't start with `F5`), so they are dropped.

### 4.7 Fallback and downgrade

A client that gets no answer within about 1 s may fall back to a VIE `00 01`. An attacker who drops OpenSec hellos can force this fallback. A client that has a pinned key for the server must never fall back.

## 5. Records

Every datagram after the handshake, in both directions:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `F5` |
| 1 | 4 | low 32 bits of the sender's record counter (u32) |
| 5 | n | ciphertext: the plaintext datagram (a game or core packet, or a cluster of them) |
| 5 + n | 16 | Poly1305 tag |

- **Overhead.** 21 bytes per datagram. With SubSpace's 512-byte datagram limit, a sender keeps plaintext datagrams to at most 491 bytes.
- **Marker byte.** The marker is never `00`, so a server's check for connection requests (`00 01`), made before decryption, can never match a record.

### 5.1 Sending

Each direction has a 64-bit counter. The first record has counter 1, and each record increments it.

- **Counter 0** in the S2C direction is the confirmation tag's nonce; a record never uses counter 0.
- **No wrap.** A sender must close the session rather than reuse a counter.
- **Sealing:**
  ```
  header = F5 || u32(counter mod 2^32)
  (ct, tag) = Seal(key_dir, N(dir, counter), ad = header, plaintext)
  ```

### 5.2 Receiving

The receiver keeps `highest` (the largest counter accepted so far, initially 0) and a record of which of the 64 counters `highest − 63 .. highest` it has accepted.

```
if len < 21 or byte 0 != F5: drop
low  = u32 at offset 1
c    = (highest with its low 32 bits cleared) | low
if c + 2^31 < highest:                  c += 2^32     # low wrapped forward
elif c > highest + 2^31 and c >= 2^32:  c -= 2^32     # low is from before the wrap
if c == 0 or c + 63 < highest or c was already accepted: drop
plaintext = Open(key_dir, N(dir, c), ad = bytes 0..5, ciphertext, tag)
if that fails: drop                      # state unchanged
accept c: highest = max(highest, c), mark c as seen
```

- **Dropped records leave no trace.** A forged or corrupted record never changes the receiver's state, so it cannot burn a counter.
- **The window.** A record more than 63 behind the highest accepted counter is dropped even if it is genuine. The transport's retransmission recovers it.
- **Jumps.** Reconstruction picks the counter nearest `highest`. The sender may therefore run up to 2^31 records ahead of what the receiver has seen; a real session never comes close.

## 6. Why the goals hold (informal)

- **G1, G5.** Keys come from HKDF over the X25519 output(s), with the transcript as `info`, so they are bound to this session's ephemeral keys and both hellos. The two directions use different keys and different nonce prefixes. Within a direction, nonces never repeat, because counters are never reused, so ChaCha20-Poly1305's requirements are met. Record headers are associated data, so the marker and counter bits can't be altered unnoticed.
- **G2.** `ee` depends only on ephemeral keys, which are discarded after the handshake. Without them, `es_static` alone (computable later by whoever steals `s`) doesn't give `okm`.
- **G3.** With `SERVER_AUTH`, `okm` depends on `X25519(ec, S)`, which only the holder of `s` (or of `ec`) can compute. The confirmation tag proves the server derived the keys before the client sends anything. Because the transcript covers `S` and the capabilities, an attacker can't strip `SERVER_AUTH` or substitute a key without breaking the tag. A pinning client rejects a hello without `SERVER_AUTH` outright.
- **Low-order checks.** These stop either side from being pushed onto a predictable shared secret by a small-order key share.
- **G4.** This follows from the receive algorithm in section 5.2.
- **G6.** The client hello is 90 bytes and a server hello is at most 90, so each spoofed hello gets at most one reply, of no more bytes than it carried.

**What the client does not get:**

- No confirmation that the server received *its* hello unaltered beyond what the transcript gives.
- No identity of its own.

**What the server does not get:**

- No confirmation that the client holds the keys until the first valid C2S record.

## 7. Implementation requirements

- **Randomness.** Ephemeral and static keys must come from a cryptographically secure generator. `oss-net` takes the source as a parameter. `opensec::os_entropy` uses the operating system; in browsers, `getrandom` uses `crypto.getRandomValues`.
- **Constant-time comparisons** for the confirmation tag and AEAD tags.
- **Erase ephemeral private keys** after the handshake.
- **Hello payloads:** never let a handshake failure produce a reply. The server simply ignores invalid hellos.

## 8. Known limitations and questions for reviewers

1. **Handshake cost from spoofed hellos.** Each valid-looking hello costs the server one or two X25519 operations and a small per-address entry, and the hello's source address is unverified. G6 prevents amplification, but not CPU or memory exhaustion. Is a stateless retry cookie (as in DTLS's HelloVerifyRequest, or QUIC's Retry) worth a second round trip here? The legacy protocol has the same property for `00 01` without the cryptography.
2. **Unauthenticated reconnects end sessions.** As in the legacy protocol, a `00 01` from a live session's address ends that session (section 4.6). An off-path attacker who knows a player's address and port can spoof one. One option is to ignore connection requests while authenticated records keep arriving, and let the old session time out instead. That would slow down genuine reconnects behind NAT rebinding.
3. **Version negotiation.** A server that doesn't support the requested version ignores the hello, so the client can't tell "no OpenSec" from "a different OpenSec version". Should the server answer with a list of supported versions, and if so, how is that authenticated against downgrade?
4. **Server identity.** Only `S` binds the session to a server; nothing names the zone. Two zones sharing a static key are indistinguishable to the client. Should the transcript include a zone name or the directory listing's identifier?
5. **Confirmation tag construction.** The tag is the Poly1305 tag of an empty-plaintext AEAD under `key_s2c` with nonce `N(2, 0)`, which records never use. Is using the record key for this acceptable, or should HKDF output a separate confirmation key?
6. **Static-key mixing.** `ikm = ee || es_static`, without the Noise-style chaining of separate HKDF steps. Is the concatenation sound here, given that the transcript is the HKDF `info`, not the salt?
7. **No client key confirmation** in the handshake (section 6). It costs nothing in practice, because the client's first record follows at once. Is there an attack against a server that treats the session as established on sending its hello?
8. **Window size.** 64 records is about half a second of a busy client's traffic. Too small, or fine given retransmission?
9. **No rekeying.** Sessions last hours at most, at under 100 records per second, far from any ChaCha20-Poly1305 usage limit. Is that analysis right?
10. **Metadata.** Lengths and timing reveal which game packets are being sent, and in practice possibly the player's actions. Padding records would cost bandwidth on a protocol that sends small packets. Is padding worth recommending?

## 9. Test vectors

`crates/oss-net/tests/vectors/opensec.txt` is plain text, one item per line, and its header describes the format. It holds:

- **Two complete handshakes**, anonymous and with `SERVER_AUTH`, from fixed private keys. They list every intermediate value: public keys, both hellos, `ee`, `es_static`, the transcript, `okm`, the two keys and the confirmation tag.
- **Records in both directions**, with their nonces. One uses counter 2^32 + 5, whose header carries only the low bits.
- **Client hellos a server must ignore:** unpadded, too long, an unknown version, and three low-order keys (0, 1 and a point of order 8).
- **Server hellos a client must reject:** each breaks exactly one rule of section 4.5 (bad tag, tampered fields, length, version, an unoffered capability, low-order ephemeral or static key, pin mismatch, pin against an anonymous server). Where needed they are built with a *valid* confirmation tag, so only the rule under test fails.
- **Replay-window sequences:** receiver decisions for reordering, replays, the window edge, forged records (which must not burn a counter), wrapping past 2^32, and large jumps.

Three things check the file:

- **Rust.** The `published_vectors` test (`cargo test -p oss-net --features opensec,os-entropy`) regenerates the file and requires it to match byte for byte; set `OSS_REGEN_VECTORS=1` to rewrite it.
- **Python.** `python3 crates/oss-net/tests/vectors/opensec_check.py` re-derives everything from this document with no shared code.
- **Conformance suite.** It turns the handshakes and records into adapter checks for other implementations ([conformance.md](../conformance.md)).

## 10. Changes

- **2026-11-08, prepared for review:**
  - The client hello is padded to 90 bytes (G6). Before, it was 42 bytes, which a spoofed hello could amplify 2.1×.
  - Clients now reject capabilities they didn't offer and a low-order `es_static`.
  - Section 4.2 now specifies the server's checks, and section 5.2 specifies counter reconstruction exactly.
  - The vectors gained intermediate values, nonces, negative cases and window sequences, plus an independent checker.
  - Added the threat model and the reviewer questions.
- **2026-11-07:** first version.
