# Checksums and the game RNG

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-proto::checksum` and `oss-proto::rng`. Evidence for each part: [verification.md](verification.md).

## File checksums

The map and LVZ file names in S2C `0x29`, and the news checksum in the login response, use standard CRC-32: IEEE polynomial, reflected, initial value and final XOR `0xFFFFFFFF`, the same as zlib's `crc32`.

## Position checksum

C2S `0x03` and S2C `0x05` carry a byte that makes the XOR of the packet's fixed part equal to zero: 22 bytes for `0x03`, 21 for `0x05`. To compute it, set the checksum byte to 0 and XOR those bytes together. Extra position data is not covered.

## Security response checksums

### The key space

**A checksum key is a 31-bit number: a server may send `1..=0x7FFF_FFFF` and nothing else.** Zero is reserved for "these are seeds only, do not answer", and nothing at or above `0x8000_0000` is a legitimate key. A server with no key table must bound its draw accordingly rather than send a raw 32-bit random number.

The bound is a property of the protocol rather than a convention, on three independent grounds.

- **Every key table counted draws from it.** Across three tables written by three different generators — 1,500 keys — not one has bit 31 set. Zero appears exactly once per table, as the first pair's key, which is the "seeds only" value that ASSS, Subspace Server .NET and `oss-server` all deliberately skip.
- **Above the bound the question has no agreed answer.** The map checksum is the one of the three values that turns the key into a position, and the implementations divide it differently (see below). Below the bound every reading is the same arithmetic and they agree exactly; at or above it they sample different columns. A server sending such a key is asking a question it cannot score, whatever the client does with it.
- **A real client did not survive one.** A genuine SubSpace 1.34 client sent a key with bit 31 set stopped responding entirely: no security response, no position packets, nothing until the session timed out. Two such keys, both fatal; four keys inside the bound, all four answered normally. *Why* it behaves that way has not been established and is not documented here.

### The values

When S2C `0x18` carries a non-zero key, the client answers C2S `0x1A` with the following values, all computed with that key.

- **Settings checksum.** Read the 1428-byte settings packet (type byte included) as 357 little-endian `u32` words and sum `word XOR key` over them (wrapping).
- **Map checksum.** Let `k` be the key. `k` stays the same throughout; the result is accumulated in a separate running sum.
  - Start with `sum = k`.
  - Visit rows `y = k mod 32, k mod 32 + 32, …` and columns `x = k mod 31, k mod 31 + 31, …`, all below 1024.
  - **The reference implementations take those two remainders on a *signed* copy of the key; `oss-proto` divides unsigned.** For every key a server may legitimately send this makes no difference at all — the two are the same arithmetic and produce identical checksums — so an implementer may use either. The readings part company only at or above `0x8000_0000`, which is [outside the key space](#the-key-space): there the signed reading starts at a negative row and column, the reference server wraps coordinates modulo 1024 so that x = −1 reads column 1023, and no two implementations agree. What Continuum does there is unconfirmed, and no key a server may send can tell you.
  - The grid is the *server view* of the map. Big objects are expanded over their area: large asteroid (217) 2×2, wormhole (220) 5×5, space station (219) 6×6, anchored at the listed tile and wrapping at the edge.
  - For every visited tile numbered 1–160 or 171 (safe zone), `sum += k XOR tile` (wrapping). Always XOR the **original** key `k`, never the running sum. XORing the sum gives a plausible-looking checksum that real clients reject. The reference server writes it `key += savekey ^ tile`, with `savekey` the unchanged original.
  - The result is `sum`.
  - Vectors: `crates/oss-formats/tests/vectors/map-checksum-synthetic.txt` (generated maps) and the `smallmap.lvl` entries of `map-checksum.txt`, also in the conformance suite. The other real maps in `map-checksum.txt` are not in the repository.
- **Map CRC (Continuum only).** A CRC over the dense 1024 × 1024 tile array in row-major order, skipping every tile that is not 1–160 or 171. It uses the CRC-32 table, starts at `0xFFFFFFFF` and has no final inversion.
- **Exe checksum (the value VIE servers expect).** A fixed function of the key: eight groups of constants, each combined by alternately adding `(constant OR key)` and XORing `(constant XOR key)`, summed with a final constant. The implementation and test vectors are in `oss-proto::checksum::vie_exe_checksum`. The original SubSpace 1.34 client reports zero here and computes nothing (measured 2026-11-13); servers should read a zero as "not applicable". Continuum clients report a checksum of their own executable instead. What a *matching* value does and does not establish is [below](#what-the-vie-exe-checksum-proves).

### What the VIE exe checksum proves

The check is the protocol's only executable-attestation channel: the server names a key, the client folds that key over its own executable image, and the server computes the same function and compares. The keying is the whole point — a static value could be replayed by anything that had seen it once, so the client has to be able to *recompute*.

**What a match establishes is narrower than the name suggests, and it is worth stating plainly, because the name does not.** `vie_exe_checksum` has never been checked against the 1998 binary's own answer, and now cannot be: the only client that could settle it reports zero and computes nothing. What it *has* been checked against is nullspace, MervBot, Subspace Server .NET, and the compiled security module ASSS ships. Those are four independent projects but one lineage — every one of them carries the same constants from a single 1990s hand transcription of the original routine, and a transcription can preserve every constant it copied and still be wrong about the arithmetic around them.

> **A matching value means "your implementation agrees with the same 1990s transcription ours does". It does not mean "you are SubSpace 1.34", and no measurement still available would make it mean that.**

That is worth having: it catches an implementation that computes the value *wrongly*, which is a real class of defect and the one this check can still detect. It should not be read as attestation of a binary.

The checksums also travel the other way, and that is the direction a real client enforces: the login response carries the server's idea of the client executable, and a genuine 1.34 client compares both values and quits with a security violation when it disagrees. See [S2C `0x0A`](packets/s2c-0a-login-response.md).

## Game RNG

Prize placement, prize types and door states use a shared generator seeded from S2C `0x18` (prize seed, door seed). Each step computes

`s ← (s mod 127773)·16807 − (s div 127773)·2836 + 123`

on a signed 32-bit state, with truncating division, adding `0x7FFFFFFF` if the result is below 1. This is the Park–Miller minimal-standard generator plus 123. Clients and servers must make the same sequence of calls for their results to agree.
