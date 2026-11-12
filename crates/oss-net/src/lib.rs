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
pub mod relay;
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

/// `WSA_IO_PENDING`: the operation was accepted and is still running. Windows
/// reports it as an error code, but it means "not finished", not "failed". No
/// Unix `errno` reaches 997, so it needs no `cfg`.
const WSA_IO_PENDING: i32 = 997;

/// Whether a socket error means "no progress yet, come back later" rather than a
/// connection that has broken.
///
/// This crate does no IO itself, but every caller that wires a socket to it has
/// to answer this question, and on Windows the obvious answer is wrong.
/// [`ErrorKind::WouldBlock`](std::io::ErrorKind::WouldBlock) and
/// [`TimedOut`](std::io::ErrorKind::TimedOut) are the portable cases. Windows
/// adds a third that the standard library does not classify: because its sockets
/// are created for overlapped IO, a read or write on a short timeout
/// occasionally reports `WSA_IO_PENDING` (OS error 997, "Overlapped I/O
/// operation is in progress"), which arrives as
/// [`ErrorKind::Uncategorized`](std::io::ErrorKind). Code that matches on the
/// kind alone therefore reads a *still in progress* code as fatal and drops a
/// working connection.
///
/// A broken connection is still a broken connection: resets, aborts and
/// protocol faults are not retryable and this returns `false` for them.
///
/// ```
/// use std::io::{Error, ErrorKind};
///
/// assert!(oss_net::would_block(&Error::from(ErrorKind::WouldBlock)));
/// assert!(oss_net::would_block(&Error::from(ErrorKind::TimedOut)));
/// // Windows' "accepted, still running", which has no ErrorKind of its own.
/// assert!(oss_net::would_block(&Error::from_raw_os_error(997)));
/// // A peer that went away is not something to retry.
/// assert!(!oss_net::would_block(&Error::from(ErrorKind::ConnectionReset)));
/// ```
pub fn would_block(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) || e.raw_os_error() == Some(WSA_IO_PENDING)
}

#[cfg(test)]
mod would_block_tests {
    use std::io::{Error, ErrorKind};

    /// Windows reports a socket operation that is still running as OS error 997
    /// with no `ErrorKind`, so matching on the kind alone misses it. Losing this
    /// case drops live connections on Windows; see `would_block`.
    #[test]
    fn windows_io_pending_is_not_a_failure() {
        let pending = Error::from_raw_os_error(997);
        assert!(
            !matches!(
                pending.kind(),
                ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
            ),
            "997 carries no kind of its own, which is why it has to be named by number"
        );
        assert!(super::would_block(&pending));
    }

    #[test]
    fn the_portable_cases_are_retryable() {
        assert!(super::would_block(&Error::from(ErrorKind::WouldBlock)));
        assert!(super::would_block(&Error::from(ErrorKind::TimedOut)));
    }

    /// The point of the predicate is that it still says no. A version that
    /// tolerated these would hide exactly the faults the relay tests look for.
    #[test]
    fn a_broken_connection_is_not_retryable() {
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::NotConnected,
            ErrorKind::UnexpectedEof,
        ] {
            assert!(!super::would_block(&Error::from(kind)), "{kind:?}");
        }
        // The two Windows codes behind a reset and an abort, by number.
        assert!(!super::would_block(&Error::from_raw_os_error(10054)));
        assert!(!super::would_block(&Error::from_raw_os_error(10053)));
    }
}

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
