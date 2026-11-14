# Contributing to oss-core

Thanks for looking. This file is the short version of what a change needs to be
mergeable here, so that you find out before you spend an evening on it rather
than after.

`oss-core` is the shared half of the project — packets, transport, formats,
physics, conformance — and it is used by the client, the server, bots and
third-party tools. Changes here ripple outwards, so the bar is a little higher
than you might expect for a hobby project.

## Before you commit anything

**Read [the "What must never reach this repository" section of
`CLAUDE.md`](CLAUDE.md#what-must-never-reach-this-repository).** It is not long,
it is the same in all four of the project's public repositories, and it applies
to commit messages, branch names and pull-request text as well as to files.

Two things about it that are easy to miss:

- It is a **test**, not just a list. The list is worked examples.
- There is a local guard that enforces part of it, and **a fresh clone does not
  have it.** If you are working from your own clone, the written rule and review
  are the only checks there are.

If you think something you want to write might be covered, ask in an issue
before you write it. Nobody will mind the question.

## The licence rule, which is the one people trip over

**This crate set is MIT, and it has to stay that way.** The reason is in
[the README's licence section](README.md#licence) and is worth understanding
rather than just obeying: `oss-core` is MIT so that anyone's bot, tool or
alternative client can build on it under whatever licence they like. A GPL
obligation arriving in these crates would take that away from every downstream
user at once.

So, concretely:

> **Do not translate code from GPL sources into this repository.** That means
> ASSS, Subspace Server .NET, and anything else under a copyleft licence.

This is not a rule about *looking*. It is a rule about *copying*, and the
difference matters because otherwise it reads as an instruction you cannot
follow.

**What is fine:**

- Reading ASSS, running it, and comparing this code's behaviour against it.
- Implementing from observed behaviour, from protocol facts, and from tests.
- **Recording ASSS's output as test data.** This is encouraged — it is how most
  of the conformance suite was built. See the provenance rule below.
- Using **MIT** sources such as nullspace, with attribution in a comment next to
  what you used.

**What is not:**

- Transliterating a GPL function into Rust, however much you rename as you go.
- Lifting a table, a constant block or an algorithm's structure out of GPL
  source.

If you are unsure which side of the line your change sits on, **say so in the
pull request**. An honest "I had ASSS open while I wrote this, here is what I
took from it" is easy to deal with. Finding out later is not.

**A note on the other two repositories:** `oss-server` and `oss-client` are
GPL-2.0-or-later, so **this rule does not apply there** and the answer is
different. Do not carry this page's rule across; read theirs.

## Provenance for test data

Vectors recorded from a reference implementation are welcome, and they carry a
requirement: **each file's header names the source it was produced from** — the
implementation, its version, and the source file or module. Fifteen existing
vector files do this; follow whichever is closest to what you are adding.

The point is that anyone can tell, years later, which numbers are evidence and
which are this project's own assertions. A vector with no provenance is not
evidence of anything.

## The invariants

These are what review will actually check, so they are worth knowing up front:

- **Decoders never panic on untrusted input.** Return `Result`. No `unwrap` or
  `expect` on anything that came off a wire or out of a file. A panic here is a
  remote crash in somebody's server.
- **Fuzz-friendly shapes**: `&[u8]` in, typed value out.
- **Every packet type gets a round-trip test.**
- **Every cipher gets fixed test vectors.**
- **Wire layout is little-endian and byte-exact**, and each packet you implement
  gets documented in [`docs/protocol/`](docs/protocol/) **in your own words**.
- Keep dependencies few and permissive. `cargo deny check` must pass.
- Prefer synthetic test data. Do not commit third-party binaries, captures,
  personal data or machine-specific paths.

## Generated files

[`crates/oss-sim/SETTINGS.md`](crates/oss-sim/SETTINGS.md) is **generated** from
`src/coverage.rs`. Never hand-edit it. Regenerate with:

```sh
OSS_UPDATE_SETTINGS_DOC=1 cargo test -p oss-sim settings_doc
```

## Before you open a pull request

Run all four. CI runs the same ones, so this only saves you a round trip:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

**The fourth one is not optional and the other three do not stand in for it.**
It is the only one that catches a rustdoc fault — a public item linking to a
private one, a broken intra-doc link, a bad code fence — and `main` has gone red
on exactly that after the other three passed locally.

`cargo fmt --all` is correct **in this repository**. It is not correct in
`oss-server` or `oss-client`, where it reaches across into a sibling checkout;
if you work in those too, read their `CONTRIBUTING.md`.

## Changes that span repositories

Shared code lives here. If the client or the server needs something different
from `oss-proto`, `oss-net`, `oss-formats` or `oss-sim`, **the change belongs
here rather than being worked around there** — and `oss-core` lands first,
because the other two build against it.

`oss-sim` deserves a particular mention: the client uses it for prediction and
the server uses it for plausibility checks, from one body of code. A change that
makes those two disagree produces false anti-cheat findings against real
players, so simulation changes get looked at carefully.

## Practical things

- **Open an issue first for anything large.** For a typo or an obvious fix, just
  send the pull request.
- Commits: imperative subject, small and focused.
- There is no CLA and there is no copyright assignment. Your contribution is
  yours, under this repository's licence.
- One maintainer, volunteering. Reviews may be slow. Pinging a quiet pull
  request after a week or so is welcome, not rude.

## Security

**Do not report a security vulnerability in a pull request or a public issue.**
See [`SECURITY.md`](SECURITY.md) — there is a private channel, and it is the
right way in.
