//! A conformance suite for SubSpace/Continuum protocol implementations.
//!
//! Any client, bot, server or library, in any language, can use it to show
//! that it speaks the protocol correctly. It has three parts:
//!
//! * **Vectors** ([`vectors`], [`adapter`]): 3,749 offline checks built
//!   from published test vectors, most produced by running unmodified reference
//!   implementations. They cover:
//!   * VIE encryption;
//!   * the security checksums (settings, map, exe, position);
//!   * the settings packet layout;
//!   * OpenSec;
//!   * canonical encodings of every game and transport packet;
//!   * relay frames.
//!
//!   The implementation under test is driven through a tiny line-based
//!   *adapter* protocol over standard input/output, so it can be written in any
//!   language.
//! * **Live server checks** ([`live::check_server`]): the suite connects to a
//!   running server as a client and checks the transport (handshake, sync,
//!   reliable delivery, duplicates, clusters, disconnect), login, arena entry,
//!   map download and the security exchange.
//! * **Live client checks** ([`live::check_client`]): the suite acts as a zone
//!   and checks a connecting client: connection request, login, acknowledgements,
//!   arena entry, map download, position checksums, time sync and the security
//!   checksums.
//!
//! The `oss-conformance` binary runs all three; `docs/conformance.md` describes
//! the checks and the adapter protocol.

pub mod adapter;
pub mod live;
pub mod report;
pub mod vectors;

pub use report::{Outcome, Report, Status};

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
