# oss-core — agent conventions

Shared Rust crates for Open SubSpace (a SubSpace/Continuum-compatible client and server). Consumers: `oss-server`, `oss-client`, bots, third-party tools. Licence **MIT**; `docs/` is **CC BY 4.0**.

## What must never reach this repository

**This section is identical in all four public repositories. Change it in all four or
in none.** It is written as a test rather than a list on purpose: a rule written as a
list of past mistakes guards only the places where mistakes have already happened.

### The test

**Before anything is committed, ask: does this narrow the search for someone trying to
obtain the material that is being kept back?** If it does, it does not go in — however
small it is, however incidental to what you were doing, and whatever else in the commit
is perfectly fine.

That test is the rule. There is deliberately no list of examples under it: **an example
of what is being kept back would describe what is being kept back**, which is the thing
the test exists to prevent.

### What fails it

**Anything specific about the withheld material fails the test** — its nature, how it
works, how it is made or organised, where it came from, where it is kept, why it is kept
back, or anything about any of those. Paraphrase counts, and so does a partial answer: a
detail is not made safe by being small, vague or incomplete, because a search is
narrowed a little at a time. A denial counts too, since a denial names the thing it
denies.

**The names of anything private fail it as well** — repositories, tools, files, paths,
notes, and any relationship stated between them. A private name is a pointer, so a bare
name with nothing else said about it can be the whole leak.

**So does a signpost.** A sentence that tells a reader where withheld detail is kept, or
to look somewhere for it, fails the test even when it names nothing. Drop the sentence;
do not reword it into a vaguer signpost.

### Where this applies

**Not only to file content.** All of it applies equally to:

- **commit messages**, subject and body;
- **branch names and tag names**;
- code comments, test fixtures and their headers, documentation prose, changelog
  entries;
- issue and pull-request text, release notes, CI logs and workflow output;
- and anything a note or report quotes out of any of the above.

**A repository is its history, not its tip.** Taking something out at the tip does not
unpublish it. Once a commit is pushed, the only remedies are a rewrite and the lead's
decision, so the cheap moment is before the commit, every time.

### It applies to passing remarks

**The subject of a commit does not limit the rule.** A commit about something unrelated
is checked exactly as carefully as one about the private material, because that is
where nobody is looking. An aside, a parenthesis, a "while I was at it", a name
mentioned only to explain something else — those are where this kind of thing slips
through, not in the places anyone is guarding.

### When you find something the guard missed

**Report it to the lead, and add it to the guard, in the same change.** Do not handle it
quietly and move on: a gap that is noticed and not closed is a gap that gets found again
the hard way. **Do not add it to this section as an example** — this section is public,
and an example here would publish the very thing the guard was just taught to stop.

### What is permitted, so this is not read as a gag

- **Compatibility is permitted. The method is not.** A public client or server may be
  fully compatible with the original. What may not appear is anything about how.
- **Saying that something is supplied by a private module is allowed**, and so is naming
  the public interface it plugs into. The cipher trait, the security hooks and the
  documentation describing their shape are this repository's own contents and belong
  here. They are what makes the rest work unchanged.
- **Saying the material exists and is being kept back is allowed**, including in public
  documentation, as long as the saying carries nothing that fails the test above. The
  public repositories already say it, and should.
- **The VIE-era stack and OpenSec are public in full**, constants, vectors and all.
  Nothing in this section narrows them, and nothing here is a reason to redact them.

### The mechanical check

A local guard refuses a commit whose staged content, message or ref names match a
private pattern list. **The list is not in this repository and must never be**: a
denylist of forbidden terms, committed to a public repository, is itself a disclosure —
the most efficient index to the problem anyone could write. It is kept outside this
repository, and the hooks that read it live in `.git/hooks`, which is neither committed
nor cloned.

Three things about it that matter more than its existence:

- **It fails closed.** If it cannot find or read its list it refuses the commit and says
  so. A check that passes when it cannot find its list is worse than no check at all.
- **It is a floor, not a ceiling.** It matches known shapes and has nothing to say about
  one nobody has thought of yet. **The test at the top of this section is the rule; the
  guard only catches the part of it that a regular expression can see.**
- **A clone does not have it.** Anyone working from a fresh clone, without the private
  list, has no guard at all — only this section and review. That is the price of not
  publishing the list, and it is the right way round: the written rule travels, the index
  does not.

Bypassing the guard with `--no-verify` is a decision to report to the lead, not a step.

### When in doubt

**It does not go in.** There is no deadline that trades against this. It cannot be
reasoned around case by case, and it does not expire. Ask the lead instead of deciding.

The reasoning behind all of the above is recorded as decisions **`D10`, `D17`, `D19`
and `D33`**. If you think one of them is wrong, that is a question for the lead rather
than an edit.

## If the local-only card is not beside this file

This repository is one of several developed together, and what is agreed across them —
conventions, decisions already taken, and work already in progress — is recorded outside
it, in a checkout that the local-only card beside this file names. That card is
deliberately not committed, so a working copy can arrive without it: a fresh clone does,
and so does a secondary working tree made from this one.

**A missing card is not evidence that there is no earlier work.** If you are working
here and it is not present, stop and ask for it rather than carrying on from this file
alone. Do not re-decide something that has already been settled, and do not start work
that may already belong to somebody else.

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
- Prefer synthetic test data. Small default maps (e.g. `tests/fixtures/smallmap.lvl`, from the GPL ASSS sample zone) may be committed as fixtures. Never commit `Continuum.exe` or its DLLs, `scrty*` files, third-party zone downloads, captures, personal data or machine-specific paths.
- Keep dependencies few and permissive (`cargo deny check` must pass).
- Before committing, all four: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, and `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`.
  **The doc gate is not optional and the other three cannot stand in for it.** CI runs it as the `docs`
  job, and it is the only one that catches a rustdoc fault — a public item linking to a private one, a
  broken intra-doc link, a bad code fence. On 2026-11-11 `main` went red on exactly that (a doc comment
  linking to a private constant) after fmt, clippy and tests all passed locally and the consuming repo
  compiled clean against the change.
  **And the writing form reformats every file in the workspace, including ones another
  session has uncommitted.** Harmless while one session worked at a time; not harmless now.
  On 2026-11-12 two sessions reformatted each other's in-progress files within one hour, in
  opposite directions, and neither could have known. **When you may not be alone in the
  checkout, run `cargo fmt --check` first** — it names the files it would change — and use
  the writing form only when that list is your own; verify your own files with
  `rustfmt --check --edition 2024 <file>`. Saying afterwards that someone else's file was
  dirty does not un-reformat it.
- Commits: imperative subject, small and focused.
