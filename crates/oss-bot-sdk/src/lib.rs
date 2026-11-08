//! Write SubSpace/Continuum zone bots in a few lines.
//!
//! A bot is a [`Handler`] that reacts to [`BotEvent`]s and acts through the
//! [`Session`]: chat, change ship or team, move. [`run`] connects over UDP, logs
//! in, enters the arena and drives the handler until the connection ends.
//!
//! ```no_run
//! use oss_bot_sdk::{BotConfig, BotEvent, Session};
//!
//! let config = BotConfig::new("PingBot", "secret").arena("0");
//! oss_bot_sdk::run("127.0.0.1:5000", config, &mut |bot: &mut Session, event| {
//!     if let BotEvent::Chat(msg) = event
//!         && msg.text == "!ping"
//!     {
//!         bot.reply(&msg, "pong");
//!     }
//! })?;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! What the session handles for you:
//!
//! * the transport (VIE by default, or OpenSec; see [`Encryption`]);
//! * login, including creating the account if the name is new;
//! * entering the arena, then switching to the configured ship;
//! * the player list, kept up to date from enter/leave/ship/team packets;
//! * position updates (every second as a spectator, ten times a second in a
//!   ship) from the state set with [`Session::set_position`];
//! * the server's security checks: settings, exe and map checksums, with the
//!   map downloaded once per arena.
//!
//! [`Session`] does no I/O itself, so the same bot also runs inside tests,
//! simulations or a custom event loop.

mod session;
mod text;

#[cfg(not(target_family = "wasm"))]
mod runner;

#[cfg(not(target_family = "wasm"))]
pub use runner::{Handler, run};
pub use session::{
    BotConfig, BotEvent, ChatKind, ChatMessage, Encryption, MyPosition, Player, SPECTATOR, Session,
};
pub use text::{from_latin1, to_latin1};

/// Re-exported for [`BotEvent::Disconnected`] and custom transports.
pub use oss_net::DisconnectReason;
/// Re-exported for [`BotEvent::Packet`] and [`Session::send_packet`].
pub use oss_proto;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
