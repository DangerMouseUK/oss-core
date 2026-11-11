# oss-core — agent conventions

Shared Rust crates for Open SubSpace (a SubSpace/Continuum-compatible client and server). Consumers: `oss-server`, `oss-client`, bots, third-party tools. Licence **MIT**; `docs/` is **CC BY 4.0**.

## Crates
- `oss-proto` — packet structs/enums + encode/decode. Pure data, `no_std`-friendly where practical (`alloc` ok).
- `oss-net` — **sans-IO** transport state machine (no sockets, no clocks: callers pass `now` and datagrams). Client and server roles. Ciphers behind a trait (`null`, `vie` and `opensec`, all implemented); a private implementation of another cipher must be pluggable without changing this crate.
- `oss-formats` — `.lvl`, eLVL chunks, `.lvz`, `.ossr` replays.
- `oss-sim` — deterministic 100 Hz integer simulation of ships, weapons and map collision, driven by the arena settings. Shared by the client (prediction) and the server (the `validate` plausibility API behind its anti-cheat). Moved here from oss-client; changes belong here, not in a consumer. `SETTINGS.md` is **generated** from `src/coverage.rs` by `OSS_UPDATE_SETTINGS_DOC=1 cargo test -p oss-sim settings_doc` — never hand-edit it.
- `oss-bot-sdk` — zone bots in a few lines: login, arena entry, players, chat, positions, the security exchange.
- `oss-conformance` — the cross-implementation conformance suite: offline vector checks driven through a language-neutral stdin/stdout adapter, plus live client and server checks (`docs/conformance.md`).

## Rules
- This crate set must stay permissive. Do **not** translate code from GPL sources (ASSS, Subspace Server .NET) into this repo. Implement from behaviour, protocol facts and tests; MIT sources (e.g. nullspace) may be used with attribution in a comment.
- Decoders never panic on untrusted input; return `Result`. Fuzz-friendly APIs (`&[u8]` in, typed value out).
- Every packet type gets a round-trip test; every cipher gets fixed test vectors.
- Wire layout is little-endian and byte-exact; document each packet in `docs/protocol/` in your own words when you implement it.
- Prefer synthetic test data. Small default maps (e.g. `tests/fixtures/smallmap.lvl`, from the GPL ASSS sample zone) may be committed as fixtures. Never commit `Continuum.exe` or its DLLs, third-party zone downloads, captures, personal data or machine-specific paths.
- Keep dependencies few and permissive (`cargo deny check` must pass).
- Before committing, all four: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, and `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`.
  **The doc gate is not optional and the other three cannot stand in for it.** CI runs it as the `docs`
  job, and it is the only one that catches a rustdoc fault — a public item linking to a private one, a
  broken intra-doc link, a bad code fence. On 2026-11-11 `main` went red on exactly that (a doc comment
  linking to a private constant) after fmt, clippy and tests all passed locally and the consuming repo
  compiled clean against the change.
- Commits: imperative subject, small and focused.
