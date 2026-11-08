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

/// OpenSec records at the sizes a zone sends: a lone position (16-22 bytes), a
/// small cluster, a half-full and a full datagram.
fn opensec(c: &mut Criterion) {
    use oss_net::Cipher;
    use oss_net::opensec::{OpenSecCipher, SessionKeys};
    let keys = SessionKeys {
        transcript: [1; 32],
        c2s: [2; 32],
        s2c: [3; 32],
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

criterion_group!(benches, vie, opensec, reliable_round_trip);
criterion_main!(benches);
