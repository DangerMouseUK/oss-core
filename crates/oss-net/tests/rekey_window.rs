//! The re-key window: when a server-side connection's cipher can still be
//! replaced, and what that costs.
//!
//! `Server::handle_datagram` treats a fresh `00 01` from an address that
//! already has a connection in one of two ways, and the whole of the difference
//! is `Connection::session_started`. Before the session starts, the acceptor
//! chain is re-run and the cipher it returns replaces the connection's,
//! silently, keeping sequence numbers and queues. After it starts, the same
//! datagram closes the connection instead.
//!
//! So the window opens when the server establishes the connection and closes
//! when the first reliable or game packet is delivered. Its width is set by the
//! peer and the link, not by any work this crate does: the real client sends
//! its login the moment it sees `Event::Connected`, which puts the close one
//! round trip after the open. These tests pin both ends of that and the
//! round-trip relation, because two threads reasoned about this window in
//! November 2026 and neither ran it.

#![cfg(feature = "opensec")]

use std::sync::{Arc, Mutex};

use oss_net::opensec::{Entropy, OpenSecAcceptor, OpenSecClientHandshake, ServerKey};
use oss_net::{
    CipherKind, Config, Connection, DisconnectReason, Event, Fallback, Handshake, Server,
    VieAcceptor, VieClientHandshake,
};

const ADDR: u32 = 3;

/// The gap a staggered second connection attempt would use: RFC 8305's Happy
/// Eyeballs figure, which is what the November 2026 research note proposed.
const STAGGER_MS: u64 = 250;

fn entropy(seed: u64) -> Entropy {
    let s = Mutex::new(seed | 1);
    Arc::new(move |b: &mut [u8]| {
        let mut x = s.lock().unwrap();
        for v in b.iter_mut() {
            *x ^= *x << 13;
            *x ^= *x >> 7;
            *x ^= *x << 17;
            *v = *x as u8;
        }
    })
}

/// A server offering OpenSec first and VIE as the legacy rung, as a zone does.
fn opensec_server(key: Option<ServerKey>) -> Server<u32> {
    let mut s = Server::new(Config::server());
    s.add_acceptor(Box::new(OpenSecAcceptor::new(key, entropy(7))));
    s.add_acceptor(Box::new(VieAcceptor::default()));
    s
}

/// The datagram a client's first tick puts on the wire.
fn first_datagram(hs: Box<dyn Handshake>) -> Vec<u8> {
    let mut c = Connection::client(Config::client(), hs, 0);
    c.poll_transmit().expect("the handshake emits on tick 0")
}

fn opensec_client(seed: u64) -> Connection {
    let hs = OpenSecClientHandshake::new(&entropy(seed), None);
    Connection::client(Config::client(), Box::new(hs), 0)
}

/// Server-clock times at which the window opened and closed.
#[derive(Debug, Default)]
struct Window {
    opened: Option<u64>,
    closed: Option<u64>,
}

/// Runs a client and a server over a link with a fixed one-way delay, one
/// millisecond at a time, and records when the server's window opened and
/// closed.
///
/// `login` makes the client behave like the real one, which sends its login
/// reliably from the `Event::Connected` arm before the next flush
/// (`oss-client/crates/oss-session/src/lib.rs`, `drain_net`). With `login`
/// false the client connects and says nothing, which is the case that shows the
/// window has no upper bound of its own.
///
/// A one-way delay of 0 is not instant: a datagram handed to the link during a
/// step is read at the start of the next one, so 0 and 1 both mean "one step".
fn drive(
    client: &mut Connection,
    server: &mut Server<u32>,
    one_way_ms: u64,
    until_ms: u64,
    login: bool,
) -> Window {
    let mut wire: Vec<(u64, bool, Vec<u8>)> = Vec::new();
    let mut window = Window::default();
    let mut sent_login = false;
    for now in 0..=until_ms {
        let (due, later) = std::mem::take(&mut wire)
            .into_iter()
            .partition::<Vec<_>, _>(|(t, _, _)| *t <= now);
        wire = later;
        for (_, to_server, d) in due {
            if to_server {
                server.handle_datagram(now, ADDR, &d);
            } else {
                client.handle_datagram(now, &d);
            }
        }
        while let Some(e) = client.poll_event() {
            if login && !sent_login && matches!(e, Event::Connected) {
                client.send(&[0x24u8; 64], true);
                sent_login = true;
            }
        }
        while server.poll_event().is_some() {}
        client.tick(now);
        server.tick(now);
        while let Some(d) = client.poll_transmit() {
            wire.push((now + one_way_ms, true, d));
        }
        while let Some((_, d)) = server.poll_transmit() {
            wire.push((now + one_way_ms, false, d));
        }
        if let Some(c) = server.connection(&ADDR) {
            if window.opened.is_none() && c.is_connected() {
                window.opened = Some(now);
            }
            if window.closed.is_none() && c.session_started() {
                window.closed = Some(now);
            }
        }
    }
    window
}

/// While the window is open, a connection request a *different* mechanism
/// claims replaces the cipher, and nothing is emitted to say so.
#[test]
fn a_different_mechanism_re_keys_silently_while_the_window_is_open() {
    let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
    let hello = first_datagram(Box::new(OpenSecClientHandshake::new(&entropy(1), None)));
    server.handle_datagram(0, ADDR, &hello);
    while server.poll_transmit().is_some() {}
    let connected: Vec<Event> =
        std::iter::from_fn(|| server.poll_event().map(|(_, e)| e)).collect();
    assert!(matches!(connected[..], [Event::Connected]));
    let conn = server.connection(&ADDR).expect("accepted");
    assert_eq!(conn.cipher_kind(), Some(CipherKind::OpenSec));
    assert!(!conn.session_started(), "the window is open");

    let vie = first_datagram(Box::new(VieClientHandshake::new(5)));
    server.handle_datagram(10, ADDR, &vie);
    while server.poll_transmit().is_some() {}
    let after: Vec<Event> = std::iter::from_fn(|| server.poll_event().map(|(_, e)| e)).collect();

    assert_eq!(server.len(), 1, "the connection survives the swap");
    assert_eq!(
        server.connection(&ADDR).unwrap().cipher_kind(),
        Some(CipherKind::Vie),
        "the second mechanism's cipher replaced the first"
    );
    assert!(
        after.is_empty(),
        "the swap emits nothing, so a consumer cannot see it: {after:?}"
    );
}

/// Once the window has closed, the same datagram ends the connection instead.
#[test]
fn the_same_request_closes_the_connection_once_the_window_has_closed() {
    let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
    let mut client = opensec_client(1);
    let w = drive(&mut client, &mut server, 1, 50, true);
    assert!(w.closed.is_some(), "the login closed the window: {w:?}");
    assert_eq!(
        server.connection(&ADDR).unwrap().cipher_kind(),
        Some(CipherKind::OpenSec)
    );

    let vie = first_datagram(Box::new(VieClientHandshake::new(5)));
    server.handle_datagram(100, ADDR, &vie);
    let after: Vec<Event> = std::iter::from_fn(|| server.poll_event().map(|(_, e)| e)).collect();
    assert_eq!(server.len(), 0, "the connection is gone, not re-keyed");
    assert!(
        after
            .iter()
            .any(|e| matches!(e, Event::Disconnected(DisconnectReason::Reconnect))),
        "and it says so: {after:?}"
    );
}

/// The window's width is the client's turnaround, which is one round trip. It
/// is not a property of this crate: nothing in the open-to-close interval is
/// work `oss-net` does.
#[test]
fn the_window_is_one_round_trip_wide() {
    for one_way in [1u64, 5, 25, 50, 125, 200] {
        let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
        let mut client = opensec_client(1);
        let w = drive(&mut client, &mut server, one_way, 8 * one_way + 20, true);
        let (opened, closed) = (w.opened.expect("opened"), w.closed.expect("closed"));
        assert_eq!(opened, one_way, "opens when the hello lands");
        assert_eq!(
            closed - opened,
            2 * one_way,
            "one-way {one_way} ms: the window is one round trip wide, not a fixed cost"
        );
    }
}

/// A connection that is established and then says nothing keeps its window
/// open. Time sync does not close it; only reliable or game data does. The only
/// bound is `Config::timeout_ms`, and every `00 01` resets that.
#[test]
fn a_connection_that_never_logs_in_keeps_the_window_open() {
    let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
    let mut client = opensec_client(1);
    let w = drive(&mut client, &mut server, 1, 6_000, false);
    assert_eq!(w.opened, Some(1));
    assert_eq!(w.closed, None, "nothing closed it in six seconds");
    let conn = server.connection(&ADDR).expect("still connected");
    assert!(conn.is_connected() && !conn.session_started());
    assert!(
        client.stats().datagrams_sent > 1,
        "the client was not silent: time sync alone does not close the window"
    );
}

/// What the window costs a staggered second attempt. A client that sends its
/// legacy request `STAGGER_MS` after its modern hello only ever reaches an open
/// window when the round trip is longer than the stagger — and when it is
/// shorter, the timer never fires at all, because the modern hello has already
/// been answered. The boundary is `round trip == STAGGER_MS`, nothing to do
/// with how long a key swap takes.
#[test]
fn a_stagger_reaches_the_window_only_when_the_round_trip_exceeds_it() {
    for one_way in [50u64, 100, 124, 125, 126, 200] {
        let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
        let hs: Box<dyn Handshake> = Box::new(Fallback::new(
            Box::new(OpenSecClientHandshake::new(&entropy(1), None)),
            Box::new(VieClientHandshake::new(5)),
            STAGGER_MS,
        ));
        let mut client = Connection::client(Config::client(), hs, 0);
        drive(&mut client, &mut server, one_way, 4 * STAGGER_MS, true);

        let round_trip = 2 * one_way;
        let expected = if round_trip > STAGGER_MS {
            CipherKind::Vie
        } else {
            CipherKind::OpenSec
        };
        assert_eq!(
            server.connection(&ADDR).unwrap().cipher_kind(),
            Some(expected),
            "one-way {one_way} ms (round trip {round_trip} ms, stagger {STAGGER_MS} ms)"
        );
        assert_eq!(
            client.cipher_kind(),
            Some(expected),
            "and both ends agree, one-way {one_way} ms"
        );
    }
}
