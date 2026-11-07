# oss-core — agent conventions

Shared Rust crates for Open SubSpace (a SubSpace/Continuum-compatible client and server). Consumers: `oss-server`, `oss-client`, bots, third-party tools. Licence **MIT**; `docs/` is **CC BY 4.0**.

## Crates
- `oss-proto` — packet structs/enums + encode/decode. Pure data, `no_std`-friendly where practical (`alloc` ok).
- `oss-net` — **sans-IO** transport state machine (no sockets, no clocks: callers pass `now` and datagrams). Client and server roles. Ciphers behind a trait (`null`, `vie`, later `opensec`); a private implementation of another cipher must be pluggable without changing this crate.
- `oss-formats` — `.lvl`, eLVL chunks, `.lvz`.

## Rules
- This crate set must stay permissive. Do **not** translate code from GPL sources (ASSS, Subspace Server .NET) into this repo. Implement from behaviour, protocol facts and tests; MIT sources (e.g. nullspace) may be used with attribution in a comment.
- Decoders never panic on untrusted input; return `Result`. Fuzz-friendly APIs (`&[u8]` in, typed value out).
- Every packet type gets a round-trip test; every cipher gets fixed test vectors.
- Wire layout is little-endian and byte-exact; document each packet in `docs/protocol/` in your own words when you implement it.
- No game assets, captures, personal data or machine-specific paths in the repo. Synthetic test data only.
- Keep dependencies few and permissive (`cargo deny check` must pass).
- Before committing: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Commits: imperative subject, small and focused.
