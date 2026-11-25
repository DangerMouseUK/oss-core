# Encryption

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-net::vie` and `oss-net::cipher`. Evidence for each part: [verification.md](verification.md).

The connection request (`00 01`) carries a protocol word that selects the encryption family: 0x0001 for SubSpace's **VIE** cipher, 0x0011 for **Continuum**. Servers may also fall back to VIE, or to no encryption, for Continuum clients.

## The three eras

Game traffic has been encrypted three different ways over the life of this game. All three names are used throughout these repositories; this is the one place that introduces them.

| Era | What it is | Where this project stands |
|---|---|---|
| **VIE** | The original SubSpace cipher, named after **Virgin Interactive Entertainment**, the game's publisher — the 1998 client's version resource carries that name. An XOR keystream over a table expanded from a 32-bit session key, negotiated in the clear. It gives no confidentiality against anyone on the path and no integrity at all. | **Implemented in full, with vectors** — the rest of this page |
| **Continuum** | The scheme the Continuum client brought in when it replaced the original SubSpace client, and still what most long-running zones require. The builds measured here are 0.38 and 0.40. | **Deliberately not implemented.** Only the handshake's [shape](#continuum-shape-only) is documented. A module developed outside these repositories supplies it as a [mechanism](#mechanisms-oss-net), which is how a real Continuum client came to play on oss-server |
| **OpenSec** | This project's own, and the only one of the three that is modern cryptography: X25519, ChaCha20-Poly1305 and HKDF-SHA256, optional at both ends. | **Implemented and specified in full** — [opensec.md](opensec.md) |

One of the three is withheld, and only its method. That the Continuum scheme exists, that zones require it, that this project interoperates with it, and that a module for it is being developed are all stated plainly here and in the READMEs. How it works is not, and will not be.

"No encryption" is a fourth case rather than an era: a VIE key of 0, or a client key echoed back unchanged, means the session runs in the clear. **It is reached only when both ends have been set to allow it**, never by negotiation — see [no encryption, and why it is not negotiable](#no-encryption-and-why-it-is-not-negotiable).

## VIE

**Key negotiation**

- The client picks a 32-bit key with the top bit set.
- The server answers `00 02` with the negated key and keys its cipher with that value.
- The client accepts the negation of its key, which enables VIE. Its own key echoed back, or a key of 0, means no encryption — and `oss-net` takes that answer only from a handshake that asked for an unencrypted session, because nothing in this exchange is authenticated. See below.

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
- **Client key `0x80000000`.** Its negation is itself, so one response means both "VIE with this key" and "no encryption". The reference server keys VIE with it, so `oss-net` reads the answer as VIE: the ambiguity is resolved towards encrypting, at both ends. A client must never offer this key, and `oss-net` never generates it (`client_key_from_seed` maps it to `0x80000001`).
- **Client keys below 1024 (subgame only).** Subgame 1.34.14 ignores a connection request whose client key is below 1024 and answers nothing — bisected, with 1023 silent and 1024 answered. A key of 0, which is how a client asks for no encryption, therefore cannot work against it. ASSS does honour it; `oss-net`'s `VieAcceptor` deliberately does not, which is the one place this implementation answers a documented vector differently (see below). Measured against that one server; the reason for the floor is not known.

The test vectors in `crates/oss-net/tests/vectors/vie.txt` come from running the reference VIE module unmodified. They cover key exchange, tables and per-packet encryption for 16 keys, including the two above.

## No encryption, and why it is not negotiable

Nothing in the `00 01` / `00 02` exchange is authenticated. It is two datagrams in the clear, and a server's "I will not encrypt" is just the client's own key sent back. So anything that can watch the path and send a datagram can produce that answer — on the first connection, before any attempt has failed and with nothing to step down from. Treated as a protocol outcome, "no encryption" is therefore available to an attacker rather than to an operator.

`oss-net` treats it as a **policy** instead: a decision somebody makes at each end, which the other end cannot make for them.

| | |
|---|---|
| **Server** | `VieAcceptor` declines a request whose client key is 0 rather than answering it. Unencrypted sessions are `NullAcceptor`'s job, and a server registers that acceptor only because an operator asked for it — behind `VieAcceptor`, so it sees only the requests VIE declined. |
| **Client** | `VieClientHandshake` fails the handshake on a `00 02` that echoes its key back. `VieClientHandshake::unencrypted()` is the handshake that asked for one and will accept it; `accept_refusal()` opts an ordinary handshake in, for a link that carries nothing secret and would otherwise not connect at all. |

Both ends must therefore have been set before any session runs in the clear, and a forged answer gets a failed handshake instead of a readable session. `crates/oss-net/tests/encryption_floor.rs` demonstrates the exposure and pins the behaviour; it keeps one deliberate run of the old behaviour so the demonstration cannot quietly stop demonstrating anything.

**What it costs.** `oss-net` can no longer talk to a server that genuinely refuses encryption, and no longer serves a client that genuinely cannot encrypt, unless the operator or the user says so. That is a real interoperability loss against ASSS, which honours a zero key. It is not a loss against the original server, which ignores client keys below 1024 and so never answered a request for no encryption in the first place.

## Continuum (shape only)

The Continuum cipher and its key expansion are not part of this repository. The transport supports them through the traits every [mechanism](#mechanisms-oss-net) is built from.

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
- **The seed is the client's own.** It is computed locally, not taken from anything the server sent — which is why nothing in the reply echoes the `00 12`. How the client derives it is not documented here and is not in this repository.
- **The session table is what the reply's twenty words carry.** The key expansion derives it from that seed; the expansion itself is not in this repository.
- **Nothing is re-keyed.** The handler builds the reply from a scratch expander and leaves the connection's own cipher state, including its key words, untouched.
- `00 13` is client-to-server only: the client's dispatch table sends subtype `0x13` to its unknown-packet arm.

## Mechanisms (`oss-net`)

A **mechanism** is one way of securing a connection: no encryption, VIE, OpenSec, or one supplied from outside these repositories. The word is the one SASL and GSSAPI use for the same job. Implemented in `oss-net::mechanism`.

### The three traits a mechanism is built from

- **`Acceptor`** (server): inspects a new peer's first raw datagram, sends raw replies, and returns either an established `Cipher` or a pending `Handshake`.
- **`Handshake`** (either side): consumes raw setup datagrams and finally yields a `Cipher`. On the client, its first `poll` emits the opening datagram (`00 01` for VIE).
- **`Cipher`**: encrypts and decrypts whole datagrams. It also receives in-session core subtypes ≥ 0x10 and can queue packets of its own.

### One description per mechanism

Each mechanism is described once, as a `Mechanism`:

| Part | What it is |
|---|---|
| **Identifier** | The word typed in settings and on the command line. This project's own are `none`, `vie`, `continuum` and `opensec`, and no other short word is accepted. Anyone else names theirs `name@their-domain`, the SSH convention (RFC 4250 §4.6.1): at most 64 characters, printable ASCII with no spaces or commas, one `@`, and a domain name after it. Owning the domain is the only permission needed, so two names cannot collide. **Short names match without regard to case (`VIE` is `vie`); `name@domain` names match exactly.** Identifiers are for settings, logs and records; none goes on the wire. |
| **Display name** | What people see: `None`, `Subspace`, `OpenSecurity`. Only identifiers are typed; a display name is never accepted in their place. |
| **Strength** | Places it relative to the others. `none` is 0, `vie` 1000, `opensec` 3000; the gaps leave room between them. Equal strengths are ordered by identifier. |
| **Selection** | *Automatic* (it may be tried on its own) or *by name only* (only when somebody names it). |
| **Era** | What the zone should treat the connection as: `SubSpace`, `Continuum` or `Modern`. It decides, for example, which login form is sent. The mechanism declares it rather than leaving it to be guessed from its name. |
| **Halves** | A *client half* that builds a fresh `Handshake` for each connection, and a *server half* that builds the server's `Acceptor`. Either may be missing. |

### What a program can speak, and what it prefers

These are two objects, kept apart on purpose. Where one list does both jobs, the order code happens to run in becomes the security policy without anybody choosing it.

- **`MechanismRegistry`** is what the program **can** speak. The order mechanisms are registered in means nothing: they are kept by strength. `MechanismRegistry::builtin()` holds `none`, `vie` and `opensec`. **Adding a mechanism is one call to `register`**, and it then takes its place in everything below.
- **`MechanismPolicy`** is what the program **prefers**, in order. By default it is the automatic mechanisms, strongest first, worked out from their strengths. A person can write a different order; it is checked against the registry.

Read from them, rather than written out by hand:

| | Example |
|---|---|
| The start-up line: every mechanism the program has, weakest first | `Mechanisms supported: None, Subspace, OpenSecurity` |
| The client's automatic order, first tried first | `Automatic order: OpenSecurity, then Subspace` |
| What a server has switched on, weakest first | `Mechanisms enabled on this zone: Subspace, OpenSecurity` |
| Choosing one mechanism by name | `--security vie` |
| The words the command line and settings accept | `none`, `vie`, `opensec` |

### The floor

**Nothing automatic goes below VIE.** `none`, and anything weaker than VIE, can only be chosen by name: the registry refuses one declared automatic, and a policy refuses to put one in its automatic order. A server serves `none` only when an operator switches it on, and then asks it after every automatic mechanism. A client reaches it only when a person asks for it by name. Both ends have to be set before a session runs in the clear; see [no encryption, and why it is not negotiable](#no-encryption-and-why-it-is-not-negotiable).

**A key on record means that mechanism and nothing else.** When a client has a server's key recorded by a mechanism, the automatic order is just that mechanism, so there is nothing to step down to. A mechanism a person names is used whatever key is on record.

### What a new mechanism's opening must look like

**Our server offers a new peer's first datagram to the mechanisms only if it begins `00 01` or `00 11`.** Anything else from an address it does not know is dropped before any acceptor sees it. So every mechanism's opening datagram must begin with one of those two pairs.

The server then asks each acceptor in its policy's order, and **the first that takes the datagram wins.** A new mechanism's opening must therefore not be one an existing acceptor would also take. VIE's acceptor takes a `00 01` exactly 8 bytes long; OpenSec's takes a `00 01` followed by the four bytes `OSEC` ([opensec.md](opensec.md)); the deliberate no-encryption acceptor takes the same 8-byte `00 01` as VIE, which is why it is asked last. A mechanism that can tell its own opening apart by length or by content alongside those is safe in any order.

## Stepping between mechanisms

A client that can speak several mechanisms tries them in turn, from the strongest down, each one a *rung* of a `Ladder` (a `Fallback` is the same thing with two rungs). The ladder also reports which mechanism won, and so which era the connection is. Every rung talks to the same server, so **an attempt the client gives up on can leave the server holding a connection for it**: the server may have answered late, answered in another mechanism, or taken one mechanism's opening for another's. Servers differ in what they then do with the next rung's request from the same address, and some keep the first connection (its keys, or the kind of client it recorded) until it is closed, so the next rung is answered and its login is then dropped without a word. A live zone was seen doing exactly that in November 2026.

The rule, in `oss-net`, used by every client and bot built on it:

1. **A rung steps down on silence, or at once on an answer in a mechanism it recognises.** On silence, after the ladder's time limit (counted from when the rung is first given the chance to send), unless the rung reports that the server has answered (`Handshake::answered`), in which case the clock stops however long setup takes. On a recognised answer, the rung returns `Step::StepDown` and the ladder moves on immediately. The last rung has no such limit beyond its own. A *failure* still ends the connection instead (no fallback on a tampered answer), and a key on record still means no fallback at all.
2. **The rung being left closes what the server may hold for it** (`Handshake::abandon`): typically a disconnect, if the server answered.
3. **The next rung starts from a fresh local endpoint.** The connection asks its driver once per step down (`Connection::take_fresh_endpoint`); a driver that can rebinds its socket to a new local port before the next rung's first datagram. The server then meets the next rung as a client it has never seen. The client drivers in these repositories all rebind.
4. **A driver that cannot rebind is still served.** The next rung starts on the same endpoint: at once if the rung left closed nothing, otherwise after `FRESH_ENDPOINT_GRACE_MS`, so the server can let the closed connection go. Some servers send a plain `00 07` of their own when they finish with a connection the client closed; the first such `00 07` before the next rung is answered is read as that goodbye, not as a refusal of the next rung.

`OpenSecClientHandshake` uses the rule itself: a SubSpace server that takes the OpenSec hello for its own connection request (the hello begins with `00 01` and a SubSpace protocol word) and answers it is recognised, stepped down from at once, and closed.

**Our server's side** (`Server::handle_datagram`): an identical repeat of the request a connection came from is answered again, identically; a *different* request before the session starts is a new connection and replaces the old one outright (cipher, kind of client, sequence numbers), ending the old one with `Event::Disconnected(Reconnect)` and no `00 07`; a request after the session starts ends the old connection, and the client's next request opens a new one. A connection the client closes is let go at once. ASSS and Subspace Server .NET instead reuse the first connection for a second request before login, which is why the client rule above does not rely on the server's.

`tests/stepping_down.rs` holds a server that keeps a connection's first handshake until it is closed, and shows each part of the rule against it.
