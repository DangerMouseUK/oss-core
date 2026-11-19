//! Stepping down between mechanisms, against a server that keeps a
//! connection's first handshake until it is closed.
//!
//! A client that can speak several mechanisms tries them in turn from one
//! address. If the server answered an attempt the client then gave up on, the
//! server holds a connection for that address. Some servers keep such a
//! connection as it was first opened when a new connection request arrives from
//! the same address: they answer the request, but go on reading with what they
//! had, so whatever the client sends next is not heard and the client waits on
//! its login for good. That was seen on a live zone in November 2026.
//!
//! The zone here does exactly that, and a dummy first rung gets an answer it
//! cannot use. On today's rule the client either reaches the server from a new
//! local endpoint (the driver rebinds when [`Connection::take_fresh_endpoint`]
//! says so), or closes what the abandoned rung opened before the next rung
//! starts ([`Handshake::abandon`]). Either way the next rung is heard. Without
//! both, which is how stepping down worked before, it is not.

use std::collections::BTreeMap;

use oss_net::{
    Config, Connection, Event, Fallback, Handshake, Server, Step, VieAcceptor, VieClientHandshake,
    cipher::parse_connect, vie,
};

/// What the client sends once connected; the zone must read it intact.
const SENT: &[u8] = b"\x24 a login the zone must read";

/// The dummy rung's key: a connection request the zone answers.
const DUMMY_KEY: u32 = 0x8000_1111;
/// The next rung's key.
const NEXT_KEY: u32 = 0x8000_2222;

/// How long the rungs wait for an answer before stepping down on the clock.
const STEP_AFTER_MS: u64 = 1500;

/// A first rung whose connection request the zone answers with something this
/// rung cannot use. With `recognises`, it knows the answer for what it is: it
/// steps down at once and, when left, closes the connection the answer
/// opened. Without, it ignores the answer and is stepped down from on the
/// clock with nothing closed, which is how every rung behaved before the
/// stepping hooks existed.
struct AnsweredElsewhere {
    recognises: bool,
    answered: bool,
    last_sent: Option<u64>,
}

impl AnsweredElsewhere {
    fn new(recognises: bool) -> Self {
        Self {
            recognises,
            answered: false,
            last_sent: None,
        }
    }
}

impl Handshake for AnsweredElsewhere {
    fn on_datagram(&mut self, _now: u64, data: &[u8], _out: &mut Vec<Vec<u8>>) -> Step {
        let answer = vie::server_key_for(DUMMY_KEY).to_le_bytes();
        if self.recognises && data.len() == 6 && data[..2] == [0, 2] && data[2..] == answer {
            self.answered = true;
            return Step::StepDown("answered in a mechanism this rung does not speak");
        }
        Step::Pending
    }

    fn poll(&mut self, now: u64, out: &mut Vec<Vec<u8>>) -> Step {
        if self.last_sent.is_none_or(|t| now.saturating_sub(t) >= 1000) {
            let mut req = vec![0, 1];
            req.extend_from_slice(&DUMMY_KEY.to_le_bytes());
            req.extend_from_slice(&[1, 0]);
            out.push(req);
            self.last_sent = Some(now);
        }
        Step::Pending
    }

    fn abandon(&mut self, _now: u64, out: &mut Vec<Vec<u8>>) {
        if self.answered {
            // The connection the answer opened uses SubSpace's cipher, which
            // leaves a two-byte core packet as it is.
            out.push(vec![0, 7]);
            out.push(vec![0, 7]);
        }
    }
}

/// A zone that keeps a connection's first handshake until it is closed: a
/// connection request from an address it holds an open connection for is
/// answered as a new one would be, and goes no further.
///
/// With `goodbye`, once a connection the client closed has gone, the zone
/// sends that address a plain `00 07` of its own, some time later, as some
/// servers do. A client that read it as a refusal of its next attempt would
/// fail there.
struct KeepFirstZone {
    server: Server<u32>,
    goodbye: Option<u64>,
    goodbyes_due: BTreeMap<u64, u32>,
    heard: bool,
}

impl KeepFirstZone {
    fn new(goodbye: Option<u64>) -> Self {
        let mut server = Server::new(Config::server());
        server.add_acceptor(Box::new(VieAcceptor::default()));
        Self {
            server,
            goodbye,
            goodbyes_due: BTreeMap::new(),
            heard: false,
        }
    }

    /// Takes a datagram from `from`; anything to send back goes to `replies`.
    fn receive(&mut self, now: u64, from: u32, data: &[u8], replies: &mut Vec<(u32, Vec<u8>)>) {
        let held = self
            .server
            .connection(&from)
            .is_some_and(|c| !c.is_closed());
        if held && let Some((key, _)) = parse_connect(data) {
            let mut answer = vec![0, 2];
            answer.extend_from_slice(&vie::server_key_for(key).to_le_bytes());
            replies.push((from, answer));
            return;
        }
        self.server.handle_datagram(now, from, data);
        let let_go = !self
            .server
            .connection(&from)
            .is_some_and(|c| !c.is_closed());
        if held
            && let_go
            && let Some(after) = self.goodbye
        {
            self.goodbyes_due.insert(now + after, from);
        }
    }

    fn tick(&mut self, now: u64, replies: &mut Vec<(u32, Vec<u8>)>) {
        self.server.tick(now);
        while let Some((_, ev)) = self.server.poll_event() {
            if let Event::Packet(p) = ev
                && p == SENT
            {
                self.heard = true;
            }
        }
        while let Some(r) = self.server.poll_transmit() {
            replies.push(r);
        }
        let due: Vec<u64> = self.goodbyes_due.range(..=now).map(|(t, _)| *t).collect();
        for t in due {
            if let Some(to) = self.goodbyes_due.remove(&t) {
                replies.push((to, vec![0, 7]));
            }
        }
    }
}

/// How the client's driver treats a request for a fresh endpoint.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Driver {
    /// Rebinds: the zone sees the next rung from a new address.
    Rebinds,
    /// Never asks: everything goes from one address.
    Stays,
}

/// Runs a client whose first rung is answered elsewhere, then VIE, against
/// the zone, for up to 10 s. Returns whether the zone read what the client
/// sent once connected, and why the client closed, if it did.
fn run(recognises: bool, driver: Driver, goodbye: Option<u64>) -> (bool, Option<String>) {
    let hs = Fallback::new(
        Box::new(AnsweredElsewhere::new(recognises)),
        Box::new(VieClientHandshake::with_key(NEXT_KEY, 1)),
        STEP_AFTER_MS,
    );
    let mut client = Connection::client(Config::client(), Box::new(hs), 0);
    let mut zone = KeepFirstZone::new(goodbye);
    let mut addr = 1u32;
    let mut sent = false;
    let mut failed = None;
    let mut now = 0;
    // (due, to the zone, from/to address, bytes), 10 ms each way.
    let mut wire: Vec<(u64, bool, u32, Vec<u8>)> = Vec::new();
    while now < 10_000 && !zone.heard {
        now += 1;
        let (due, later): (Vec<_>, Vec<_>) = wire.into_iter().partition(|(t, ..)| *t <= now);
        wire = later;
        let mut replies = Vec::new();
        for (_, to_zone, a, d) in due {
            if to_zone {
                zone.receive(now, a, &d, &mut replies);
            } else if a == addr {
                // A datagram for an address the client has left is lost.
                client.handle_datagram(now, &d);
            }
        }
        client.tick(now);
        while let Some(ev) = client.poll_event() {
            match ev {
                Event::Connected if !sent => {
                    client.send(SENT, true);
                    sent = true;
                }
                Event::Disconnected(r) => failed = Some(format!("{r:?}")),
                _ => {}
            }
        }
        while let Some(d) = client.poll_transmit() {
            wire.push((now + 10, true, addr, d));
        }
        if driver == Driver::Rebinds && client.take_fresh_endpoint() {
            addr += 1;
        }
        zone.tick(now, &mut replies);
        for (a, d) in replies {
            wire.push((now + 10, false, a, d));
        }
        if failed.is_some() {
            break;
        }
    }
    (zone.heard, failed)
}

/// The failure this guards against: the first rung's answer is ignored, the
/// step down is on the clock, nothing is closed and nothing moves, so the next
/// rung is answered by a zone still holding the first connection, and what the
/// client sends is not heard. The client does not fail; it waits.
#[test]
fn without_a_close_or_a_fresh_endpoint_the_next_rung_is_not_heard() {
    assert_eq!(run(false, Driver::Stays, None), (false, None));
}

/// A driver that rebinds is enough on its own: the next rung reaches the zone
/// from an address it holds nothing for, even from a rung that closed nothing.
#[test]
fn a_fresh_endpoint_is_heard() {
    assert_eq!(run(false, Driver::Rebinds, None), (true, None));
    assert_eq!(run(true, Driver::Rebinds, None), (true, None));
}

/// A rung that knows the answer for what it is steps down at once and closes
/// the connection the answer opened, so even a driver that never rebinds is
/// heard, after the pause the close earns.
#[test]
fn a_closed_attempt_is_heard_from_the_same_endpoint() {
    assert_eq!(run(true, Driver::Stays, None), (true, None));
}

/// A zone that sends its own `00 07` when it has finished with the closed
/// connection, before or after the next rung starts: that is the old
/// connection's goodbye, and the next rung is not refused by it.
#[test]
fn the_old_connections_goodbye_is_not_a_refusal() {
    for after in [100, 900, 1300] {
        assert_eq!(
            run(true, Driver::Stays, Some(after)),
            (true, None),
            "goodbye {after} ms after the close"
        );
    }
}

/// A rung that steps down on an answer does it without waiting out the clock.
#[test]
fn a_recognised_answer_steps_down_at_once() {
    let mut hs = Fallback::new(
        Box::new(AnsweredElsewhere::new(true)),
        Box::new(VieClientHandshake::with_key(NEXT_KEY, 1)),
        STEP_AFTER_MS,
    );
    let mut out = Vec::new();
    assert!(matches!(hs.poll(0, &mut out), Step::Pending));
    out.clear();
    let mut answer = vec![0, 2];
    answer.extend_from_slice(&vie::server_key_for(DUMMY_KEY).to_le_bytes());
    assert!(matches!(
        hs.on_datagram(20, &answer, &mut out),
        Step::Pending
    ));
    assert!(
        hs.on_secondary(),
        "stepped down at 20 ms, not {STEP_AFTER_MS}"
    );
    assert_eq!(out, vec![vec![0, 7], vec![0, 7]], "and closed what it left");
    assert!(hs.take_fresh_endpoint(), "asking for a fresh endpoint");
    assert!(!hs.take_fresh_endpoint(), "once");
}

/// A rung the server has answered is not stepped down from on the clock, and a
/// step down with nothing below it ends the connection rather than hanging.
#[test]
fn an_answered_rung_keeps_its_place_and_a_last_step_down_fails() {
    struct Talking;
    impl Handshake for Talking {
        fn on_datagram(&mut self, _: u64, _: &[u8], _: &mut Vec<Vec<u8>>) -> Step {
            Step::Pending
        }
        fn poll(&mut self, _: u64, _: &mut Vec<Vec<u8>>) -> Step {
            Step::Pending
        }
        fn answered(&self) -> bool {
            true
        }
    }
    let mut hs = Fallback::new(
        Box::new(Talking),
        Box::new(VieClientHandshake::with_key(NEXT_KEY, 1)),
        STEP_AFTER_MS,
    );
    let mut out = Vec::new();
    for t in [0, STEP_AFTER_MS, 10 * STEP_AFTER_MS] {
        assert!(matches!(hs.poll(t, &mut out), Step::Pending));
    }
    assert!(
        !hs.on_secondary(),
        "the clock does not move an answered rung"
    );

    let mut client =
        Connection::client(Config::client(), Box::new(AnsweredElsewhere::new(true)), 0);
    while client.poll_transmit().is_some() {}
    let mut answer = vec![0, 2];
    answer.extend_from_slice(&vie::server_key_for(DUMMY_KEY).to_le_bytes());
    client.handle_datagram(20, &answer);
    assert!(client.is_closed(), "nothing below it, so it ends");
}

/// Our own server: a connection the client has closed is let go at once, so
/// the client's next request from the same address opens a new connection
/// without waiting for the server's next tick.
#[test]
fn our_server_lets_a_closed_connection_go_at_once() {
    let mut server: Server<u32> = Server::new(Config::server());
    server.add_acceptor(Box::new(VieAcceptor::default()));
    let request = |key: u32| {
        let mut r = vec![0, 1];
        r.extend_from_slice(&key.to_le_bytes());
        r.extend_from_slice(&[1, 0]);
        r
    };
    server.handle_datagram(0, 7, &request(DUMMY_KEY));
    assert!(server.connection(&7).is_some_and(Connection::is_connected));
    server.handle_datagram(10, 7, &[0, 7]);
    assert!(server.connection(&7).is_none(), "gone without a tick");
    server.handle_datagram(20, 7, &request(NEXT_KEY));
    while server.poll_transmit().is_some() {}
    let events: Vec<Event> = std::iter::from_fn(|| server.poll_event().map(|(_, e)| e)).collect();
    assert!(
        matches!(
            events[..],
            [Event::Connected, Event::Disconnected(_), Event::Connected]
        ),
        "{events:?}"
    );
}
