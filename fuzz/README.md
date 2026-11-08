# oss-core fuzz targets

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for every decoder and for the transport. This crate is not part of the main workspace, so ordinary builds and CI don't compile libFuzzer. CI only checks that the targets compile.

| Target | What it exercises | Checks beyond "no panic" |
|---|---|---|
| `proto_c2s` | every client-to-server game packet | decoded packets re-encode to bytes that decode to the same value |
| `proto_s2c` | every server-to-client game packet, settings included | same |
| `proto_core` | core `0x00` packets | same |
| `proto_misc` | billing and directory packets | same |
| `formats_lvl` | `.lvl` + eLVL, eLVL sections alone, region bitmaps | rewrite → parse gives the same value |
| `formats_lvz` | `.lvz` archives, section inflation, object sections | same |
| `formats_replay` | `.ossr` replays | rewrite (plain and compressed) gives the same records |
| `net_server` | `oss_net::Server` fed datagrams from four peers, with sends, big and sized transfers, and disconnects in between | no datagram over `max_send` |
| `net_client` | an established client `Connection` fed arbitrary datagrams | same |
| `net_vie` | VIE with arbitrary keys | encrypt → decrypt is the identity |
| `net_opensec` | OpenSec records against a reference replay window; server and client handshakes | exactly the right records are accepted, with their plaintext; tampered and truncated records are rejected |

## Running

You need a nightly toolchain and `cargo install cargo-fuzz`.

```sh
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run net_server -- -max_total_time=300
```

**On Windows (MSVC)**, put the AddressSanitizer runtime on `PATH` first. It lives in the Visual Studio tools directory, for example `VC/Tools/MSVC/<version>/bin/Hostx64/x64`. Without it, targets exit with `STATUS_DLL_NOT_FOUND`.

**Seed corpora.** Corpora and crash artifacts are git-ignored. For the format targets, seed the corpus with real files you have locally, prefixed with a `0x00` byte (the targets use the first byte to pick a mode). Never commit those files.

**Regressions.** Every crash found so far is kept as a regression test in the crate it affected (search for "fuzz" in `crates/*/tests`).
