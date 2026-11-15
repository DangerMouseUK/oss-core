//! Hot-path benchmarks: VIE and OpenSec record encryption, and a full reliable
//! round trip (send, pack, encrypt, decrypt, deliver, ack) between a client and
//! a server.
//!
//! Run with `cargo bench -p oss-net`.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use oss_net::{Config, Connection, Event, Server, VieAcceptor, VieCipher, VieClientHandshake};

fn vie(c: &mut Criterion) {
    let cipher = VieCipher::new(0x1234_5678).unwrap();
    let mut g = c.benchmark_group("vie");
    for len in [22usize, 128, 512] {
        let mut buf = vec![0x03u8; len];
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_function(format!("encrypt_{len}"), |b| {
            b.iter(|| cipher.encrypt(black_box(&mut buf)))
        });
        g.bench_function(format!("decrypt_{len}"), |b| {
            b.iter(|| cipher.decrypt(black_box(&mut buf)))
        });
    }
    g.finish();
}

#[cfg(feature = "opensec")]
/// OpenSec records at the sizes a zone sends: a lone position (16-22 bytes), a
/// small cluster, a half-full and a full datagram.
fn opensec(c: &mut Criterion) {
    use oss_net::Cipher;
    use oss_net::opensec::{OpenSecCipher, SessionKeys};
    let keys = SessionKeys {
        transcript: [1; 32],
        c2s: [2; 32],
        s2c: [3; 32],
        client_identity: None,
    };
    let mut g = c.benchmark_group("opensec");
    for len in [16usize, 64, 256, 491] {
        let plain = vec![0x28u8; len];
        let mut sender = OpenSecCipher::new(&keys, true, None);
        let mut receiver = OpenSecCipher::new(&keys, false, None);
        let mut buf = Vec::with_capacity(576);
        g.throughput(Throughput::Bytes(len as u64));
        g.bench_function(format!("seal_{len}"), |b| {
            b.iter(|| {
                buf.clear();
                buf.extend_from_slice(&plain);
                sender.encrypt(black_box(&mut buf));
            })
        });
        g.bench_function(format!("seal_open_{len}"), |b| {
            b.iter(|| {
                buf.clear();
                buf.extend_from_slice(&plain);
                sender.encrypt(&mut buf);
                assert!(receiver.decrypt(black_box(&mut buf)));
            })
        });
    }
    g.finish();
}

const ADDR: u32 = 1;

fn connected_pair() -> (Connection, Server<u32>) {
    let mut server = Server::new(Config::server());
    server.add_acceptor(Box::new(VieAcceptor::default()));
    let mut client = Connection::client(Config::client(), Box::new(VieClientHandshake::new(1)), 0);
    for now in [0, 10] {
        while let Some(d) = client.poll_transmit() {
            server.handle_datagram(now, ADDR, &d);
        }
        while let Some((_, d)) = server.poll_transmit() {
            client.handle_datagram(now, &d);
        }
        client.tick(now);
        server.tick(now);
    }
    while client.poll_event().is_some() {}
    while server.poll_event().is_some() {}
    assert!(client.is_connected());
    (client, server)
}

/// One reliable 64-byte packet client -> server, delivered and acknowledged,
/// with all buffers recycled (the steady-state, allocation-free path).
fn reliable_round_trip(c: &mut Criterion) {
    let (mut client, mut server) = connected_pair();
    let payload = [0x06u8; 64];
    let mut now = 20u64;
    let mut g = c.benchmark_group("reliable");
    g.throughput(Throughput::Elements(1));
    g.bench_function("round_trip_64b", |b| {
        b.iter(|| {
            now += 1;
            client.send(black_box(&payload), true);
            client.flush(now);
            while let Some(d) = client.poll_transmit() {
                server.handle_datagram(now, ADDR, &d);
                client.recycle(d);
            }
            while let Some((_, e)) = server.poll_event() {
                if let Event::Packet(p) = e {
                    server.recycle(p);
                }
            }
            server.tick(now);
            while let Some((_, d)) = server.poll_transmit() {
                client.handle_datagram(now, &d);
                server.recycle(d);
            }
        })
    });
    // Many small packets clustered per flush (a busy server pass). Time stays
    // fixed so the one-way traffic never trips the no-data timeout.
    let (mut client, mut server) = connected_pair();
    let now = 20u64;
    g.throughput(Throughput::Elements(20));
    g.bench_function("cluster_20x22b", |b| {
        let pos = [0x28u8; 22];
        b.iter(|| {
            for _ in 0..20 {
                server.send(&ADDR, black_box(&pos), false);
            }
            server.tick(now);
            while let Some((_, d)) = server.poll_transmit() {
                client.handle_datagram(now, &d);
                server.recycle(d);
            }
            let mut got = 0;
            while let Some(e) = client.poll_event() {
                if let Event::Packet(p) = e {
                    got += 1;
                    client.recycle(p);
                }
            }
            assert_eq!(got, 20);
        })
    });
    g.finish();
}

#[cfg(feature = "opensec")]
/// The re-key step. A fresh `00 01` from an address whose connection has not
/// started its session re-runs the whole acceptor chain and swaps the cipher
/// (`Server::handle_datagram` -> `Connection::set_cipher`), keeping sequence
/// numbers and queues. The cost is almost entirely the acceptor's: OpenSec
/// generates an ephemeral X25519 key and does one Diffie-Hellman per selected
/// capability, VIE builds a 520-byte table. Both directions are measured
/// because they differ by two orders of magnitude.
fn rekey(c: &mut Criterion) {
    use std::sync::{Arc, Mutex};

    use oss_net::opensec::{Entropy, OpenSecAcceptor, OpenSecClientHandshake, ServerKey};
    use oss_net::{Acceptor, CipherKind};

    /// Deterministic entropy, so a run is reproducible; it still yields a fresh
    /// ephemeral per call, which is what makes each iteration do the real work.
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

    /// The datagram a client's first tick puts on the wire.
    fn first_datagram(hs: Box<dyn oss_net::Handshake>) -> Vec<u8> {
        let mut c = Connection::client(Config::client(), hs, 0);
        c.poll_transmit().expect("the handshake emits on tick 0")
    }

    fn opensec_hello(seed: u64) -> Vec<u8> {
        first_datagram(Box::new(OpenSecClientHandshake::new(&entropy(seed), None)))
    }

    fn vie_request(key: u32) -> Vec<u8> {
        first_datagram(Box::new(VieClientHandshake::new(key)))
    }

    /// A server offering both mechanisms, with one connection already
    /// established from `first` and its session not yet started: the state in
    /// which a re-key is possible.
    fn in_window(key: Option<ServerKey>, first: &[u8]) -> Server<u32> {
        let mut s = Server::new(Config::server());
        s.add_acceptor(Box::new(OpenSecAcceptor::new(key, entropy(7))));
        s.add_acceptor(Box::new(VieAcceptor::default()));
        s.handle_datagram(0, ADDR, first);
        while s.poll_transmit().is_some() {}
        while s.poll_event().is_some() {}
        let conn = s.connection(&ADDR).expect("the first request is accepted");
        assert!(conn.is_connected() && !conn.session_started());
        s
    }

    let server_key = ServerKey::generate(&entropy(99));
    let hello = opensec_hello(1);
    let vie_one = vie_request(1);
    let vie_two = vie_request(2);

    let mut g = c.benchmark_group("rekey");
    g.throughput(Throughput::Elements(1));

    // The acceptors on their own, so the cost can be attributed.
    let opensec_acceptor = OpenSecAcceptor::new(Some(server_key.clone()), entropy(11));
    let vie_acceptor = VieAcceptor::default();
    let mut out = Vec::new();
    g.bench_function("accept_opensec_hello", |b| {
        b.iter(|| {
            out.clear();
            let a = opensec_acceptor.accept(0, black_box(&hello), &mut out);
            assert!(matches!(a, Some(oss_net::Accept::Established(_))));
        })
    });
    g.bench_function("accept_vie_request", |b| {
        b.iter(|| {
            out.clear();
            let a = vie_acceptor.accept(0, black_box(&vie_one), &mut out);
            assert!(matches!(a, Some(oss_net::Accept::Established(_))));
        })
    });

    // VIE connection, OpenSec request: the expensive direction, because the
    // OpenSec acceptor claims the hello and does the key agreement.
    let mut server = in_window(Some(server_key.clone()), &vie_one);
    g.bench_function("vie_to_opensec", |b| {
        b.iter(|| {
            server.handle_datagram(0, ADDR, black_box(&hello));
            while let Some((_, d)) = server.poll_transmit() {
                server.recycle(d);
            }
        })
    });
    assert_eq!(
        server.connection(&ADDR).unwrap().cipher_kind(),
        Some(CipherKind::OpenSec)
    );

    // OpenSec connection, VIE request: the cheap direction. The OpenSec
    // acceptor rejects an 8-byte request on sight and VIE builds its table.
    let mut server = in_window(Some(server_key.clone()), &hello);
    g.bench_function("opensec_to_vie", |b| {
        b.iter(|| {
            server.handle_datagram(0, ADDR, black_box(&vie_one));
            while let Some((_, d)) = server.poll_transmit() {
                server.recycle(d);
            }
        })
    });
    assert_eq!(
        server.connection(&ADDR).unwrap().cipher_kind(),
        Some(CipherKind::Vie)
    );

    // Same mechanism, different client key: the legacy case this branch exists
    // for (a lost `00 02`, a client restart before login).
    let mut server = in_window(Some(server_key), &vie_one);
    g.bench_function("vie_to_vie", |b| {
        b.iter(|| {
            server.handle_datagram(0, ADDR, black_box(&vie_two));
            while let Some((_, d)) = server.poll_transmit() {
                server.recycle(d);
            }
        })
    });
    assert_eq!(
        server.connection(&ADDR).unwrap().cipher_kind(),
        Some(CipherKind::Vie)
    );

    g.finish();
}

#[cfg(feature = "opensec")]
criterion_group!(benches, vie, opensec, rekey, reliable_round_trip);
#[cfg(not(feature = "opensec"))]
criterion_group!(benches, vie, reliable_round_trip);
criterion_main!(benches);
