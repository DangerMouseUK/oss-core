# Checksums and the game RNG

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-proto::checksum` and `oss-proto::rng`.

## File checksums

The map and LVZ file names in S2C `0x29`, and the news checksum in the login response, use standard CRC-32: IEEE polynomial, reflected, initial value and final XOR `0xFFFFFFFF`, the same as zlib's `crc32`.

## Position checksum

C2S `0x03` and S2C `0x05` carry a byte that makes the XOR of the packet's fixed part equal to zero: 22 bytes for `0x03`, 21 for `0x05`. To compute it, set the checksum byte to 0 and XOR those bytes together. Extra position data is not covered.

## Security response checksums

When S2C `0x18` carries a non-zero key, the client answers C2S `0x1A` with the following values, all computed with that key.

- **Settings checksum.** Read the 1428-byte settings packet (type byte included) as 357 little-endian `u32` words and sum `word XOR key` over them (wrapping).
- **Map checksum.** Treat the key as a signed 32-bit integer `k`.
  - Start with the sum equal to the key.
  - Visit rows `y = k mod 32, k mod 32 + 32, …` and columns `x = k mod 31, k mod 31 + 31, …`, all below 1024. The modulo truncates, so it is negative for negative keys; positions outside the map count as empty.
  - For every visited tile numbered 1–160 or 171 (safe zone), add `key XOR tile` (wrapping).
- **Map CRC (Continuum only).** A CRC over the dense 1024 × 1024 tile array in row-major order, skipping every tile that is not 1–160 or 171. It uses the CRC-32 table, starts at `0xFFFFFFFF` and has no final inversion.
- **Exe checksum (SubSpace clients).** A fixed function of the key: eight groups of constants, each combined by alternately adding `(constant OR key)` and XORing `(constant XOR key)`, summed with a final constant. The implementation and test vectors are in `oss-proto::checksum::vie_exe_checksum`. Continuum clients report a checksum of their own executable instead.

## Game RNG

Prize placement, prize types and door states use a shared generator seeded from S2C `0x18` (prize seed, door seed). Each step computes

`s ← (s mod 127773)·16807 − (s div 127773)·2836 + 123`

on a signed 32-bit state, with truncating division, adding `0x7FFFFFFF` if the result is below 1. This is the Park–Miller minimal-standard generator plus 123. Clients and servers must make the same sequence of calls for their results to agree.
