# Checksums and the game RNG

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-proto::checksum` and `oss-proto::rng`. Evidence for each part: [verification.md](verification.md).

## File checksums

The map and LVZ file names in S2C `0x29`, and the news checksum in the login response, use standard CRC-32: IEEE polynomial, reflected, initial value and final XOR `0xFFFFFFFF`, the same as zlib's `crc32`.

## Position checksum

C2S `0x03` and S2C `0x05` carry a byte that makes the XOR of the packet's fixed part equal to zero: 22 bytes for `0x03`, 21 for `0x05`. To compute it, set the checksum byte to 0 and XOR those bytes together. Extra position data is not covered.

## Security response checksums

When S2C `0x18` carries a non-zero key, the client answers C2S `0x1A` with the following values, all computed with that key.

- **Settings checksum.** Read the 1428-byte settings packet (type byte included) as 357 little-endian `u32` words and sum `word XOR key` over them (wrapping).
- **Map checksum.** Let `k` be the key, read as a signed 32-bit integer. `k` stays the same throughout; the result is accumulated in a separate running sum.
  - Start with `sum = k`.
  - Visit rows `y = k mod 32, k mod 32 + 32, …` and columns `x = k mod 31, k mod 31 + 31, …`, all below 1024. The modulo truncates, so the starting row and column are negative for negative keys. The reference server then wraps coordinates modulo 1024, so x = −1 reads column 1023. Whether Continuum clients do the same is unconfirmed.
  - The grid is the *server view* of the map. Big objects are expanded over their area: large asteroid (217) 2×2, wormhole (220) 5×5, space station (219) 6×6, anchored at the listed tile and wrapping at the edge.
  - For every visited tile numbered 1–160 or 171 (safe zone), `sum += k XOR tile` (wrapping). Always XOR the **original** key `k`, never the running sum. XORing the sum gives a plausible-looking checksum that real clients reject. The reference server writes it `key += savekey ^ tile`, with `savekey` the unchanged original.
  - The result is `sum`.
  - Vectors: `crates/oss-formats/tests/vectors/map-checksum-synthetic.txt` (generated maps) and the `smallmap.lvl` entries of `map-checksum.txt`, also in the conformance suite. The other real maps in `map-checksum.txt` are not in the repository.
- **Map CRC (Continuum only).** A CRC over the dense 1024 × 1024 tile array in row-major order, skipping every tile that is not 1–160 or 171. It uses the CRC-32 table, starts at `0xFFFFFFFF` and has no final inversion.
- **Exe checksum (SubSpace clients).** A fixed function of the key: eight groups of constants, each combined by alternately adding `(constant OR key)` and XORing `(constant XOR key)`, summed with a final constant. The implementation and test vectors are in `oss-proto::checksum::vie_exe_checksum`. Continuum clients report a checksum of their own executable instead.

## Game RNG

Prize placement, prize types and door states use a shared generator seeded from S2C `0x18` (prize seed, door seed). Each step computes

`s ← (s mod 127773)·16807 − (s div 127773)·2836 + 123`

on a signed 32-bit state, with truncating division, adding `0x7FFFFFFF` if the result is below 1. This is the Park–Miller minimal-standard generator plus 123. Clients and servers must make the same sequence of calls for their results to agree.
