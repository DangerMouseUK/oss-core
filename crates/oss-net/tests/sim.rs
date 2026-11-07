//! End-to-end simulations of a client and a server over a lossy, reordering,
//! duplicating link.

use oss_net::{
    Config, Connection, DisconnectReason, Event, NullAcceptor, Server, VieAcceptor,
    VieClientHandshake, ticks,
};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

/// One direction of the link: datagrams with delivery times.
#[derive(Default)]
struct Link {
    q: Vec<(u64, Vec<u8>)>,
}

#[derive(Clone, Copy)]
struct Net {
    loss: u64,
    dup: u64,
    min_delay: u64,
    jitter: u64,
}

impl Link {
    fn push(&mut self, rng: &mut Rng, net: Net, now: u64, d: Vec<u8>) {
        if rng.chance(net.loss) {
            return;
        }
        let copies = if rng.chance(net.dup) { 2 } else { 1 };
        for _ in 0..copies {
            let delay = net.min_delay + rng.next() % (net.jitter + 1);
            self.q.push((now + delay, d.clone()));
        }
    }
    fn due(&mut self, now: u64) -> Vec<Vec<u8>> {
        let (ready, rest): (Vec<_>, Vec<_>) = self.q.drain(..).partition(|(t, _)| *t <= now);
        self.q = rest;
        let mut ready = ready;
        ready.sort_by_key(|(t, _)| *t);
        ready.into_iter().map(|(_, d)| d).collect()
    }
}

const ADDR: u32 = 7;

struct Sim {
    rng: Rng,
    net: Net,
    now: u64,
    client_clock_skew: u64,
    client: Connection,
    server: Server<u32>,
    c2s: Link,
    s2c: Link,
    client_events: Vec<Event>,
    server_events: Vec<Event>,
}

impl Sim {
    fn new(seed: u64, net: Net, vie: bool) -> Self {
        let mut server = Server::new(Config::server());
        if vie {
            server.add_acceptor(Box::new(VieAcceptor::default()));
        } else {
            server.add_acceptor(Box::new(NullAcceptor));
        }
        let skew = 1_234_560;
        let hs = if vie {
            VieClientHandshake::new(seed as u32)
        } else {
            VieClientHandshake::unencrypted()
        };
        let client = Connection::client(Config::client(), Box::new(hs), skew);
        Self {
            rng: Rng(seed | 1),
            net,
            now: 0,
            client_clock_skew: skew,
            client,
            server,
            c2s: Link::default(),
            s2c: Link::default(),
            client_events: Vec::new(),
            server_events: Vec::new(),
        }
    }

    fn client_now(&self) -> u64 {
        self.now + self.client_clock_skew
    }

    fn step(&mut self) {
        self.now += 10;
        let cn = self.client_now();
        for d in self.s2c.due(self.now) {
            self.client.handle_datagram(cn, &d);
        }
        for d in self.c2s.due(self.now) {
            self.server.handle_datagram(self.now, ADDR, &d);
        }
        self.client.tick(cn);
        self.server.tick(self.now);
        while let Some(d) = self.client.poll_transmit() {
            self.c2s.push(&mut self.rng, self.net, self.now, d);
        }
        while let Some((_, d)) = self.server.poll_transmit() {
            self.s2c.push(&mut self.rng, self.net, self.now, d);
        }
        while let Some(e) = self.client.poll_event() {
            self.client_events.push(e);
        }
        while let Some((_, e)) = self.server.poll_event() {
            self.server_events.push(e);
        }
    }

    fn run_until(&mut self, limit_ms: u64, mut done: impl FnMut(&Sim) -> bool) {
        let end = self.now + limit_ms;
        while self.now < end {
            self.step();
            if done(self) {
                return;
            }
        }
        let got: Vec<u32> = packets(&self.client_events)
            .iter()
            .filter(|p| p[0] >= 0x40)
            .map(|p| index(p))
            .collect();
        let missing: Vec<u32> = (0..300).filter(|i| !got.contains(i)).collect();
        eprintln!(
            "client missing {missing:?}; got {} first {:?}",
            got.len(),
            &got[..got.len().min(5)]
        );
        let disc: Vec<_> = self
            .client_events
            .iter()
            .chain(&self.server_events)
            .filter(|e| matches!(e, Event::Disconnected(_)))
            .collect();
        panic!(
            "simulation did not finish in {limit_ms} ms; client packets {}, server packets {},              disconnects {disc:?}, client {:?}",
            packets(&self.client_events).len(),
            packets(&self.server_events).len(),
            self.client
        );
    }

    fn connect(&mut self) {
        self.run_until(20_000, |s| s.client.is_connected() && s.server.len() == 1);
    }
}

fn packets(events: &[Event]) -> Vec<&Vec<u8>> {
    events
        .iter()
        .filter_map(|e| {
            if let Event::Packet(p) = e {
                Some(p)
            } else {
                None
            }
        })
        .collect()
}

/// A recognisable game packet: non-zero type, index, then filler up to `len`.
fn make(i: u32, len: usize) -> Vec<u8> {
    let mut p = vec![0x40 + (i % 32) as u8];
    p.extend_from_slice(&i.to_le_bytes());
    while p.len() < len {
        p.push((p.len() as u32 ^ i) as u8);
    }
    p
}

fn index(p: &[u8]) -> u32 {
    u32::from_le_bytes([p[1], p[2], p[3], p[4]])
}

fn sizes(rng: &mut Rng, n: u32) -> Vec<usize> {
    (0..n)
        .map(|i| match i % 10 {
            0 => 600 + (rng.next() % 3000) as usize, // big data
            1 => 250 + (rng.next() % 260) as usize,  // too big to cluster
            _ => 5 + (rng.next() % 60) as usize,
        })
        .collect()
}

#[test]
fn reliable_delivery_over_bad_link() {
    for (seed, vie) in [(1u64, true), (2, false), (3, true), (4, true)] {
        let net = Net {
            loss: 12,
            dup: 6,
            min_delay: 5,
            jitter: 120,
        };
        let mut sim = Sim::new(seed, net, vie);
        sim.connect();
        assert_eq!(
            sim.client.cipher_name(),
            Some(if vie { "vie" } else { "none" })
        );
        let n = 300;
        let up = sizes(&mut sim.rng, n);
        let down = sizes(&mut sim.rng, n);
        for i in 0..n {
            sim.client.send(&make(i, up[i as usize]), true);
            sim.server.send(&ADDR, &make(i, down[i as usize]), true);
            // Unreliable chatter too; it may be lost.
            sim.client.send(&[0x03, 1, 2, 3], false);
            if i % 10 == 0 {
                sim.step();
            }
        }
        sim.run_until(600_000, |s| {
            packets(&s.server_events)
                .iter()
                .filter(|p| p[0] >= 0x40)
                .count()
                == n as usize
                && packets(&s.client_events)
                    .iter()
                    .filter(|p| p[0] >= 0x40)
                    .count()
                    == n as usize
        });
        for (events, sz) in [(&sim.server_events, &up), (&sim.client_events, &down)] {
            let got: Vec<_> = packets(events)
                .into_iter()
                .filter(|p| p[0] >= 0x40)
                .collect();
            for (i, p) in got.iter().enumerate() {
                assert_eq!(index(p), i as u32, "out of order (seed {seed})");
                assert_eq!(**p, make(i as u32, sz[i]));
            }
        }
        let st = sim.client.stats();
        assert!(st.retransmits > 0 && st.duplicates > 0, "{st:?}");
        assert!(
            !sim.client_events
                .iter()
                .any(|e| matches!(e, Event::Disconnected(_)))
        );
    }
}

#[test]
fn sized_transfer_with_loss() {
    let net = Net {
        loss: 8,
        dup: 3,
        min_delay: 10,
        jitter: 60,
    };
    let mut sim = Sim::new(11, net, true);
    sim.connect();
    let mut file = vec![0x2A];
    file.extend((0..150_000u32).map(|i| (i * 7 + i / 300) as u8));
    let id = sim
        .server
        .connection_mut(&ADDR)
        .unwrap()
        .send_sized(file.clone());
    // Keep other traffic flowing during the transfer.
    for i in 0..50 {
        sim.server.send(&ADDR, &make(i, 20), true);
    }
    sim.run_until(600_000, |s| s.server_events.contains(&Event::SizedSent(id)));
    sim.run_until(10_000, |s| {
        packets(&s.client_events).iter().any(|p| p[0] == 0x2A)
    });
    let got = packets(&sim.client_events)
        .into_iter()
        .find(|p| p[0] == 0x2A)
        .unwrap();
    assert_eq!(*got, file);
    let progress: Vec<_> = sim
        .client_events
        .iter()
        .filter_map(|e| {
            if let Event::SizedProgress { received, total } = e {
                Some((*received, *total))
            } else {
                None
            }
        })
        .collect();
    assert!(progress.len() >= 150_001 / 480);
    assert!(
        progress
            .windows(2)
            .all(|w| w[0].0 < w[1].0 && w[0].1 == w[1].1)
    );
    // The interleaved small packets all arrived too.
    assert_eq!(
        packets(&sim.client_events)
            .iter()
            .filter(|p| p[0] >= 0x40)
            .count(),
        50
    );
}

#[test]
fn sized_transfer_cancelled_by_receiver() {
    let net = Net {
        loss: 0,
        dup: 0,
        min_delay: 20,
        jitter: 0,
    };
    let mut sim = Sim::new(5, net, true);
    sim.connect();
    let mut file = vec![0x2A];
    file.resize(500_000, 9);
    let id = sim.server.connection_mut(&ADDR).unwrap().send_sized(file);
    sim.run_until(30_000, |s| {
        s.client_events
            .iter()
            .any(|e| matches!(e, Event::SizedProgress { received, .. } if *received > 20_000))
    });
    sim.client.cancel_incoming_sized();
    sim.run_until(30_000, |s| {
        s.server_events.contains(&Event::SizedCancelled(id))
    });
    // Let in-flight chunks drain; nothing completes and the link stays healthy.
    for _ in 0..500 {
        sim.step();
    }
    assert!(!packets(&sim.client_events).iter().any(|p| p[0] == 0x2A));
    assert!(sim.client_events.contains(&Event::SizedIncomingCancelled));
    sim.client.send(&make(1, 10), true);
    sim.run_until(10_000, |s| {
        packets(&s.server_events).iter().any(|p| p[0] >= 0x40)
    });
}

#[test]
fn time_sync_estimates_server_clock() {
    let net = Net {
        loss: 0,
        dup: 0,
        min_delay: 40,
        jitter: 0,
    };
    let mut sim = Sim::new(9, net, true);
    sim.connect();
    sim.run_until(20_000, |s| s.client.sync_rtt_ticks().is_some());
    let est = sim.client.server_ticks(sim.client_now()) as i64;
    let actual = ticks(sim.now) as i64;
    // One-way delay is 4 ticks; estimates within a few ticks are expected.
    assert!((est - actual).abs() <= 6, "estimate {est}, actual {actual}");
    let peer = sim.server.connection(&ADDR).unwrap().peer_counts();
    assert!(peer.is_some());
}

#[test]
fn disconnects() {
    let net = Net {
        loss: 0,
        dup: 0,
        min_delay: 5,
        jitter: 0,
    };
    // Client hangs up.
    let mut sim = Sim::new(21, net, true);
    sim.connect();
    sim.client.disconnect();
    assert!(sim.client.is_closed());
    sim.run_until(1_000, |s| {
        s.server_events
            .contains(&Event::Disconnected(DisconnectReason::Remote))
    });
    assert!(sim.server.is_empty());

    // Server kicks.
    let mut sim = Sim::new(22, net, true);
    sim.connect();
    sim.server.disconnect(&ADDR);
    sim.run_until(1_000, |s| {
        s.client_events
            .contains(&Event::Disconnected(DisconnectReason::Remote))
    });

    // Link dies: both sides time out.
    let dead = Net {
        loss: 100,
        dup: 0,
        min_delay: 5,
        jitter: 0,
    };
    let mut sim = Sim::new(23, net, true);
    sim.connect();
    sim.net = dead;
    sim.run_until(40_000, |s| s.client.is_closed() && s.server.is_empty());
    assert!(sim.client_events.iter().any(|e| matches!(
        e,
        Event::Disconnected(DisconnectReason::Timeout | DisconnectReason::ReliableRetries)
    )));
}

#[test]
fn handshake_failures() {
    // No server answers: the client gives up.
    let mut c = Connection::client(
        Config::client(),
        Box::new(VieClientHandshake::new(1).timeout(2_000)),
        0,
    );
    let mut sent = 0;
    for t in (0..=3_000).step_by(10) {
        c.tick(t);
        while c.poll_transmit().is_some() {
            sent += 1;
        }
    }
    assert!(c.is_closed());
    assert!(sent >= 2, "00 01 is resent");
    assert!(matches!(
        c.poll_event(),
        Some(Event::Disconnected(DisconnectReason::HandshakeFailed(_)))
    ));

    // Server full: 00 07 answer.
    let mut server: Server<u32> = Server::new(Config::server());
    server.add_acceptor(Box::new(VieAcceptor::default()));
    server.max_connections = 0;
    let mut c = Connection::client(Config::client(), Box::new(VieClientHandshake::new(1)), 0);
    let req = c.poll_transmit().unwrap();
    server.handle_datagram(0, 1, &req);
    let (_, reply) = server.poll_transmit().unwrap();
    assert_eq!(reply, [0, 7]);
    c.handle_datagram(0, &reply);
    assert!(c.is_closed());
}

#[test]
fn repeated_connect_request() {
    let net = Net {
        loss: 0,
        dup: 0,
        min_delay: 5,
        jitter: 0,
    };
    let mut sim = Sim::new(31, net, true);
    sim.connect();
    // Before any session traffic, a repeated request simply re-keys.
    let mut hs = Connection::client(Config::client(), Box::new(VieClientHandshake::new(77)), 0);
    let req = hs.poll_transmit().unwrap();
    sim.server.handle_datagram(sim.now, ADDR, &req);
    assert_eq!(sim.server.len(), 1);
    // After session traffic, it ends the old connection.
    let mut sim = Sim::new(32, net, true);
    sim.connect();
    sim.client.send(&make(0, 10), true);
    sim.run_until(1_000, |s| !packets(&s.server_events).is_empty());
    sim.server.handle_datagram(sim.now, ADDR, &req);
    assert!(sim.server.is_empty());
    assert!(
        sim.server_events
            .iter()
            .chain(std::iter::from_fn(|| None))
            .count()
            > 0
    );
}

#[test]
fn garbage_never_panics() {
    let mut server: Server<u32> = Server::new(Config::server());
    server.add_acceptor(Box::new(VieAcceptor::default()));
    let mut c = Connection::client(Config::client(), Box::new(VieClientHandshake::new(3)), 0);
    let req = c.poll_transmit().unwrap();
    server.handle_datagram(0, 1, &req);
    let (_, resp) = server.poll_transmit().unwrap();
    c.handle_datagram(0, &resp);
    assert!(c.is_connected());
    let mut rng = Rng(77);
    for i in 0..100_000u64 {
        let len = (rng.next() % 40) as usize + if i % 100 == 0 { 600 } else { 0 };
        let mut d: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        if i % 2 == 0 && d.len() > 1 {
            d[0] = 0;
            d[1] = (rng.next() % 0x16) as u8;
        }
        if i % 3 == 0 && d.len() > 3 {
            // Plausible cluster.
            d[0] = 0;
            d[1] = 0x0E;
        }
        c.handle_datagram(i, &d);
        server.handle_datagram(i, 1, &d);
        if i % 50 == 0 {
            c.tick(i);
            server.tick(i);
            while c.poll_transmit().is_some() {}
            while server.poll_transmit().is_some() {}
        }
    }
}
