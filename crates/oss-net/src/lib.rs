//! Sans-IO transport for the SubSpace protocol.
//!
//! Implements the core (`0x00`-prefixed) layer: connection setup, reliable delivery,
//! acknowledgements, clustering, chunked and sized transfers, time sync and the
//! pluggable packet ciphers. Callers feed datagrams in and pull datagrams out; the
//! same state machine serves clients, servers and bots, native and wasm.
//!
//! * [`Connection`]: one peer (client or server end).
//! * [`Server`]: many connections keyed by address, with [`Acceptor`]s choosing
//!   the encryption from each client's first datagram.
//! * [`cipher`]: the [`Cipher`] / [`Handshake`] / [`Acceptor`] plug-in traits, plus
//!   null and VIE implementations ([`VieAcceptor`], [`VieClientHandshake`]).
//!
//! A minimal client loop:
//!
//! ```
//! use oss_net::{Config, Connection, Event, VieClientHandshake};
//!
//! let mut conn = Connection::client(Config::client(), Box::new(VieClientHandshake::new(42)), 0);
//! // The first datagram (00 01 ...) is ready to send.
//! let first = conn.poll_transmit().unwrap();
//! assert_eq!(&first[..2], &[0x00, 0x01]);
//! conn.recycle(first); // after sending it
//! // ... feed replies with conn.handle_datagram(now, &bytes),
//! // call conn.tick(now) every ~10 ms, and drain conn.poll_event():
//! while let Some(event) = conn.poll_event() {
//!     if let Event::Packet(p) = event {
//!         // handle the game packet, then hand the buffer back
//!         conn.recycle(p);
//!     }
//! }
//! ```
//!
//! Recycling buffers is optional, but with it a connection performs no heap
//! allocations per packet once warmed up.

pub mod cipher;
mod connection;
#[cfg(feature = "opensec")]
pub mod opensec;
mod server;
pub mod vie;

pub use cipher::{
    Accept, Acceptor, Cipher, CipherContext, CipherKind, Fallback, Handshake, NullAcceptor,
    NullCipher, Step, VieAcceptor, VieClientHandshake,
};
pub use connection::{
    Config, Connection, DisconnectReason, Event, Priority, SendFlags, Stats, TransferId, ticks,
};
pub use server::Server;
pub use vie::VieCipher;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
