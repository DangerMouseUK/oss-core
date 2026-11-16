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
    drive_link(
        client,
        server,
        Link::clean(one_way_ms),
        Inject::default(),
        until_ms,
        login,
    )
    .window
}

/// A link with a fixed one-way delay, optional jitter and optional loss. A
/// clean link is the special case with both at zero.
#[derive(Debug, Clone, Copy)]
struct Link {
    one_way_ms: u64,
    /// Each datagram is held an extra 0..=`jitter_ms`, which also reorders.
    jitter_ms: u64,
    /// Chance in a thousand that a datagram is dropped, each way.
    loss_per_mille: u64,
    /// Seed for the loss and jitter draws, so a run is reproducible.
    seed: u64,
}

impl Link {
    fn clean(one_way_ms: u64) -> Self {
        Link {
            one_way_ms,
            jitter_ms: 0,
            loss_per_mille: 0,
            seed: 1,
        }
    }
}

/// A deliberate interference with the client's datagrams, so a hazard can be
/// shown rather than waited for.
#[derive(Debug, Clone, Copy, Default)]
struct Inject {
    /// Drop the client's datagram with this index, counting from zero over
    /// every datagram it hands to the link.
    drop_nth: Option<u32>,
    /// Deliver a second copy of each legacy `00 01` this many ms behind the
    /// first. Duplication and reordering are the only ways a `00 01` can reach
    /// the server after the window has shut.
    dup_legacy_after_ms: Option<u64>,
    /// Hold the client's datagram with this index back by this many extra ms,
    /// which is reordering stated exactly instead of drawn at random.
    delay_nth_ms: Option<(u32, u64)>,
}

/// What a run of [`drive_link`] ended up doing.
#[derive(Debug)]
struct Run {
    window: Window,
    client_kind: Option<CipherKind>,
    server_kind: Option<CipherKind>,
    /// Whether the server still has a connection for the address at the end.
    server_has_connection: bool,
    /// Why the client stopped, if it did.
    client_failure: Option<DisconnectReason>,
}

/// xorshift64, so loss and jitter are reproducible from the link's seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn is_legacy_request(d: &[u8]) -> bool {
    d.len() == 8 && d[0] == 0 && d[1] == 1
}

/// The general form of [`drive`]: the same step-by-step loop over a link that
/// may drop, delay, reorder and duplicate.
fn drive_link(
    client: &mut Connection,
    server: &mut Server<u32>,
    link: Link,
    inject: Inject,
    until_ms: u64,
    login: bool,
) -> Run {
    // (due, sequence, to_server, bytes). The sequence keeps datagrams that fall
    // due in the same millisecond in the order they were sent.
    let mut wire: Vec<(u64, u64, bool, Vec<u8>)> = Vec::new();
    let mut rng = Rng(link.seed | 1);
    let mut window = Window::default();
    let mut sent_login = false;
    let mut client_datagrams = 0u32;
    let mut seq = 0u64;
    let mut client_failure = None;
    for now in 0..=until_ms {
        let (mut due, later) = std::mem::take(&mut wire)
            .into_iter()
            .partition::<Vec<_>, _>(|(t, _, _, _)| *t <= now);
        wire = later;
        due.sort_by_key(|(t, s, _, _)| (*t, *s));
        for (_, _, to_server, d) in due {
            if to_server {
                server.handle_datagram(now, ADDR, &d);
            } else {
                client.handle_datagram(now, &d);
            }
        }
        while let Some(e) = client.poll_event() {
            match e {
                Event::Connected if login && !sent_login => {
                    client.send(&[0x24u8; 64], true);
                    sent_login = true;
                }
                Event::Disconnected(r) => client_failure = client_failure.or(Some(r)),
                _ => {}
            }
        }
        while server.poll_event().is_some() {}
        client.tick(now);
        server.tick(now);
        while let Some(d) = client.poll_transmit() {
            let idx = client_datagrams;
            client_datagrams += 1;
            if inject.drop_nth == Some(idx) {
                continue;
            }
            if let (Some(extra), true) = (inject.dup_legacy_after_ms, is_legacy_request(&d)) {
                seq += 1;
                wire.push((now + link.one_way_ms + extra, seq, true, d.clone()));
            }
            let held = match inject.delay_nth_ms {
                Some((n, ms)) if n == idx => ms,
                _ => 0,
            };
            post(&mut wire, &mut rng, link, now + held, &mut seq, true, d);
        }
        while let Some((_, d)) = server.poll_transmit() {
            post(&mut wire, &mut rng, link, now, &mut seq, false, d);
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
    Run {
        window,
        client_kind: client.cipher_kind(),
        server_kind: server.connection(&ADDR).and_then(|c| c.cipher_kind()),
        server_has_connection: server.connection(&ADDR).is_some(),
        client_failure,
    }
}

/// Hands one datagram to the link, dropping and delaying it as the link says.
fn post(
    wire: &mut Vec<(u64, u64, bool, Vec<u8>)>,
    rng: &mut Rng,
    link: Link,
    now: u64,
    seq: &mut u64,
    to_server: bool,
    d: Vec<u8>,
) {
    if link.loss_per_mille > 0 && rng.next() % 1000 < link.loss_per_mille {
        return;
    }
    let jitter = if link.jitter_ms == 0 {
        0
    } else {
        rng.next() % (link.jitter_ms + 1)
    };
    *seq += 1;
    wire.push((now + link.one_way_ms + jitter, *seq, to_server, d));
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

/// A staggered client gets exactly one try at the modern handshake, because
/// the gap before it falls back is the same 250 ms as the modern handshake's
/// own resend timer, and `Fallback::poll` tests the switch first. So a single
/// lost hello is not a delay, it is a permanent downgrade — and nothing on
/// either end records that it happened.
#[test]
fn one_lost_hello_downgrades_the_connection_for_good() {
    // The coupling the whole test rests on: the stagger is not longer than the
    // modern handshake's own resend timer, so the switch always pre-empts the
    // resend and the hello is sent exactly once. Checked at compile time, so
    // moving either constant breaks the build here rather than quietly turning
    // this into a test of something else.
    const _: () = assert!(STAGGER_MS <= OpenSecClientHandshake::RESEND_MS);

    // Dropping the hello, and nothing else, on an otherwise perfect link.
    let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
    let hs: Box<dyn Handshake> = Box::new(Fallback::new(
        Box::new(OpenSecClientHandshake::new(&entropy(1), None)),
        Box::new(VieClientHandshake::new(5)),
        STAGGER_MS,
    ));
    let mut client = Connection::client(Config::client(), hs, 0);
    let run = drive_link(
        &mut client,
        &mut server,
        Link::clean(25),
        Inject {
            drop_nth: Some(0),
            dup_legacy_after_ms: None,
            delay_nth_ms: None,
        },
        2_000,
        true,
    );
    assert_eq!(run.client_kind, Some(CipherKind::Vie));
    assert_eq!(run.server_kind, Some(CipherKind::Vie));
    assert_eq!(
        run.client_failure, None,
        "the connection is fine, just not the one that was offered"
    );

    // The same link, dropping the datagram after the hello instead: the cipher
    // is unaffected, so it is the hello specifically and not loss in general.
    let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
    let hs: Box<dyn Handshake> = Box::new(Fallback::new(
        Box::new(OpenSecClientHandshake::new(&entropy(1), None)),
        Box::new(VieClientHandshake::new(5)),
        STAGGER_MS,
    ));
    let mut client = Connection::client(Config::client(), hs, 0);
    let run = drive_link(
        &mut client,
        &mut server,
        Link::clean(25),
        Inject {
            drop_nth: Some(1),
            dup_legacy_after_ms: None,
            delay_nth_ms: None,
        },
        2_000,
        true,
    );
    assert_eq!(run.client_kind, Some(CipherKind::OpenSec));
    assert_eq!(run.server_kind, Some(CipherKind::OpenSec));
}

/// A second copy of a connection request is harmless while the window is open
/// and fatal once it has shut, and the boundary is exactly one round trip
/// behind the original — the width of the window itself. On a fast link that
/// is a very small amount of reordering, so the hazard is worst where the link
/// is best.
#[test]
fn a_duplicate_request_is_fatal_exactly_one_round_trip_late() {
    for one_way in [10u64, 25, 50] {
        let round_trip = 2 * one_way;
        for (behind, fatal) in [(round_trip, false), (round_trip + 1, true)] {
            let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
            let hs: Box<dyn Handshake> = Box::new(Fallback::new(
                Box::new(OpenSecClientHandshake::new(&entropy(1), None)),
                Box::new(VieClientHandshake::new(5)),
                STAGGER_MS,
            ));
            let mut client = Connection::client(Config::client(), hs, 0);
            let run = drive_link(
                &mut client,
                &mut server,
                Link::clean(one_way),
                Inject {
                    // Lose the hello, so the client really does send a `00 01`
                    // and there is something to duplicate.
                    drop_nth: Some(0),
                    dup_legacy_after_ms: Some(behind),
                    delay_nth_ms: None,
                },
                STAGGER_MS + 4 * one_way + behind + 50,
                true,
            );
            let width = run.window.closed.zip(run.window.opened).map(|(c, o)| c - o);
            assert_eq!(
                width,
                Some(round_trip),
                "one-way {one_way} ms: the window should be one round trip wide"
            );
            assert_eq!(
                !run.server_has_connection, fatal,
                "one-way {one_way} ms, duplicate {behind} ms behind: {run:?}"
            );
            if fatal {
                assert_eq!(
                    run.client_failure,
                    Some(DisconnectReason::Remote),
                    "and the client is told, rather than left hanging"
                );
            }
        }
    }
}

/// Loss and jitter small against the round trip do not leave the two ends
/// holding different ciphers. The re-key is what keeps them in step: the server
/// follows whatever the client's last connection request claimed, and the
/// client only commits once it has an answer. This is the property the November
/// 2026 design note doubted, so it is worth a standing check rather than one
/// reading.
///
/// **The bound is real and the next test is where it breaks.** This covers
/// 20% loss with jitter up to 20 ms. A sweep of 20,000 runs per cell on
/// 2026-11-16 found no disagreement at all up to 160 ms of jitter on a 240 ms
/// round trip, and 2.08% at 320 ms, where the two connection requests can
/// arrive in the wrong order. Do not read this test as saying more than it
/// measures.
#[test]
fn ordinary_loss_and_jitter_leave_the_ends_on_the_same_cipher() {
    let mut connected = 0;
    let seeds = 24;
    for seed in 0..seeds {
        for one_way in [25u64, 150] {
            let link = Link {
                one_way_ms: one_way,
                jitter_ms: 20,
                loss_per_mille: 200,
                seed: seed * 0x9E37_79B9 + 7,
            };
            let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
            let hs: Box<dyn Handshake> = Box::new(Fallback::new(
                Box::new(OpenSecClientHandshake::new(&entropy(1), None)),
                Box::new(VieClientHandshake::new(5)),
                STAGGER_MS,
            ));
            let mut client = Connection::client(Config::client(), hs, 0);
            let run = drive_link(
                &mut client,
                &mut server,
                link,
                Inject::default(),
                6_000,
                true,
            );
            if let (Some(c), Some(s)) = (run.client_kind, run.server_kind) {
                assert_eq!(c, s, "seed {seed}, one-way {one_way} ms: {run:?}");
            }
            if run.window.closed.is_some() {
                connected += 1;
            }
        }
    }
    // Without this the test would pass on a link that never connects at all.
    assert!(
        connected * 4 >= seeds * 2 * 3,
        "only {connected} of {} runs reached a session; the check above would \
         be close to vacuous",
        seeds * 2
    );
}

/// The clean-link reading — safe below a 250 ms round trip, downgrades above
/// it — does not survive ordinary jitter. At a 240 ms round trip, which the
/// clean link puts comfortably on the modern side, a 0..40 ms wobble in each
/// direction is enough to push most connections over the stagger and onto the
/// legacy cipher. The boundary is not a line; it is a smear as wide as the
/// jitter.
#[test]
fn jitter_moves_the_boundary_the_clean_link_appeared_to_fix() {
    let one_way = 120; // a 240 ms round trip: 10 ms inside the stagger
    let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
    let hs: Box<dyn Handshake> = Box::new(Fallback::new(
        Box::new(OpenSecClientHandshake::new(&entropy(1), None)),
        Box::new(VieClientHandshake::new(5)),
        STAGGER_MS,
    ));
    let mut client = Connection::client(Config::client(), hs, 0);
    let run = drive_link(
        &mut client,
        &mut server,
        Link::clean(one_way),
        Inject::default(),
        2_000,
        true,
    );
    assert_eq!(
        run.client_kind,
        Some(CipherKind::OpenSec),
        "on a clean link a 240 ms round trip stays on the modern cipher"
    );

    let seeds = 16;
    let mut downgraded = 0;
    for seed in 0..seeds {
        let link = Link {
            one_way_ms: one_way,
            jitter_ms: 40,
            loss_per_mille: 0,
            seed: seed * 0x9E37_79B9 + 7,
        };
        let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
        let hs: Box<dyn Handshake> = Box::new(Fallback::new(
            Box::new(OpenSecClientHandshake::new(&entropy(1), None)),
            Box::new(VieClientHandshake::new(5)),
            STAGGER_MS,
        ));
        let mut client = Connection::client(Config::client(), hs, 0);
        let run = drive_link(
            &mut client,
            &mut server,
            link,
            Inject::default(),
            3_000,
            true,
        );
        assert_eq!(run.client_kind, run.server_kind, "seed {seed}: {run:?}");
        if run.client_kind == Some(CipherKind::Vie) {
            downgraded += 1;
        }
    }
    assert!(
        downgraded * 2 > seeds,
        "jitter of 0..40 ms each way downgraded {downgraded} of {seeds} runs at \
         a 240 ms round trip; the clean-link figure says none of them should"
    );
}

/// The modern handshake's own retransmission can kill the connection it just
/// made, and the stagger has nothing to do with it.
///
/// An OpenSec hello is a `00 01` connection request (`opensec.rs::is_client_hello`
/// checks exactly that), so a resent hello reaches the same branch of
/// `Server::handle_datagram` as a legacy one. While the window is open a
/// byte-identical repeat is recognised and answered harmlessly. After the
/// window shuts it closes the connection instead.
///
/// `OpenSecClientHandshake` resends every 250 ms, so a resend only happens when
/// the first answer has not arrived by then — and on a link with a fixed delay
/// that is self-cancelling: if the answer is later than 250 ms the resend is
/// always earlier than the login it would have to overtake. It takes
/// reordering. The client sends the resend at 250 ms and the login a moment
/// later, on the heels of the answer; if the link delivers those two out of
/// order, the connection the client has just established is closed from under
/// it.
#[test]
fn a_resent_hello_can_close_the_session_it_just_opened() {
    // A 252 ms round trip: the answer arrives at 252, two milliseconds after
    // the client has given up waiting and resent the hello at 250.
    let one_way = 126;
    let nominal = |delay_of_the_resend| {
        let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
        let mut client = opensec_client(1);
        drive_link(
            &mut client,
            &mut server,
            Link::clean(one_way),
            Inject {
                drop_nth: None,
                dup_legacy_after_ms: None,
                // Datagram 0 is the hello, 1 is the resend at 250 ms, 2 is the
                // login sent when the answer lands at 252 ms.
                delay_nth_ms: Some((1, delay_of_the_resend)),
            },
            1_500,
            true,
        )
    };

    // In order, the resend lands at 376 and the login at 378. The repeat is
    // byte-identical to the request the connection came from and the window is
    // still open, so the server answers it again and keeps the connection.
    let in_order = nominal(0);
    assert_eq!(in_order.window.closed, Some(378));
    assert!(
        in_order.server_has_connection,
        "a repeat inside the window is harmless: {in_order:?}"
    );
    assert_eq!(in_order.client_failure, None);
    assert_eq!(in_order.client_kind, Some(CipherKind::OpenSec));

    // Ten milliseconds of reordering puts the same datagram at 386, eight
    // milliseconds the wrong side of the login. The server closes the
    // connection it finished setting up moments earlier.
    let reordered = nominal(10);
    assert_eq!(
        reordered.window.closed,
        Some(378),
        "the session still starts at the same moment"
    );
    assert!(
        !reordered.server_has_connection,
        "the resend arrived after the window shut: {reordered:?}"
    );
    assert_eq!(
        reordered.client_failure,
        Some(DisconnectReason::Remote),
        "and the client is dropped by the server it just connected to"
    );

    // It is the lateness and nothing else: the same delay applied while the
    // window is still open leaves the connection alone. Four milliseconds puts
    // the resend at 380 -- still after the login at 378, so this is the
    // tightest case that must still fail -- while one millisecond puts it at
    // 377, inside the window, and must not.
    assert!(!nominal(4).server_has_connection, "380 is outside");
    assert!(nominal(1).server_has_connection, "377 is inside");
}

/// How much reordering it takes to trigger the kill above, as a rule rather
/// than one reading: the last hello resend goes out at the largest multiple of
/// the resend timer below the round trip, and the login goes out when the
/// answer lands, so the two are separated by the round trip modulo the resend
/// timer. A round trip just over a multiple of 250 ms leaves almost no margin
/// at all.
#[test]
fn the_margin_before_a_resent_hello_is_the_round_trip_modulo_the_resend_timer() {
    for one_way in [126u64, 150, 200, 251, 376] {
        let round_trip = 2 * one_way;
        let margin = round_trip % OpenSecClientHandshake::RESEND_MS;
        // The hello goes out at 0 and again every resend interval until the
        // answer lands, so the client's datagrams are: 0 the hello, then one
        // per resend, then the login. The last resend is the one that can
        // overtake the login.
        let resends = round_trip / OpenSecClientHandshake::RESEND_MS;
        assert!(
            margin > 0,
            "a round trip on the boundary has no last resend"
        );
        let mut first_lethal = None;
        for held in 0..=(margin + 20) {
            let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
            let mut client = opensec_client(1);
            let run = drive_link(
                &mut client,
                &mut server,
                Link::clean(one_way),
                Inject {
                    drop_nth: None,
                    dup_legacy_after_ms: None,
                    delay_nth_ms: Some((resends as u32, held)),
                },
                4 * round_trip + 600,
                true,
            );
            assert_eq!(
                run.client_kind,
                Some(CipherKind::OpenSec),
                "one-way {one_way} ms: the cipher is not what is at stake here"
            );
            if !run.server_has_connection {
                first_lethal = Some(held);
                break;
            }
        }
        assert_eq!(
            first_lethal,
            Some(margin + 1),
            "one-way {one_way} ms (round trip {round_trip} ms): the resend should \
             be survivable by exactly {margin} ms of reordering and no more"
        );
    }
}

/// Where that bound breaks: if the link delivers the two connection requests
/// in the wrong order, the ends really can end up on different ciphers, and
/// the connection is then dead without either end saying so.
///
/// The client sends its modern hello, gives up on it after the stagger and
/// sends a legacy request. If the legacy request overtakes the hello, the
/// server builds a legacy connection, answers it, and *then* receives the
/// hello — which is still inside the window, so it re-keys the server to the
/// modern cipher. The client, which committed to legacy when the answer
/// arrived, cannot follow: `Fallback` hands everything to the rung it switched
/// to, so the modern server hello is ignored. The client's login is then
/// encrypted with a cipher the server no longer holds, the server cannot
/// decrypt it, the window never shuts and nothing times out for 30 seconds.
///
/// It takes reordering on the order of the round trip, which is why the sweep
/// only saw it at 320 ms of jitter. It is not a corner the code handles; it is
/// a corner the code has not met.
#[test]
fn a_request_overtaking_the_hello_leaves_the_ends_on_different_ciphers() {
    let one_way = 50;
    let mut server = opensec_server(Some(ServerKey::generate(&entropy(99))));
    let hs: Box<dyn Handshake> = Box::new(Fallback::new(
        Box::new(OpenSecClientHandshake::new(&entropy(1), None)),
        Box::new(VieClientHandshake::new(5)),
        STAGGER_MS,
    ));
    let mut client = Connection::client(Config::client(), hs, 0);
    let run = drive_link(
        &mut client,
        &mut server,
        Link::clean(one_way),
        Inject {
            drop_nth: None,
            dup_legacy_after_ms: None,
            // Hold the hello for 300 ms, so it lands at 350: after the legacy
            // request the client sends at 250 (which lands at 300) and after
            // the answer to it, but before the login would have shut the
            // window at 400.
            delay_nth_ms: Some((0, 300)),
        },
        2_000,
        true,
    );
    assert_eq!(
        run.client_kind,
        Some(CipherKind::Vie),
        "the client committed to the rung it switched to: {run:?}"
    );
    assert_eq!(
        run.server_kind,
        Some(CipherKind::OpenSec),
        "the late hello re-keyed the server away from it: {run:?}"
    );
    assert_eq!(
        run.window.closed, None,
        "and so the login never arrives in a form the server can read, which \
         leaves the window open rather than closing it"
    );
    assert_eq!(
        run.client_failure, None,
        "neither end reports anything for the whole two seconds"
    );
}
