#![no_main]
//! The server role: up to four peers send arbitrary datagrams (unencrypted
//! sessions are accepted, so the fuzzer reaches the reliable, cluster, big and
//! sized-transfer code), interleaved with sends, disconnects and ticks.

use libfuzzer_sys::fuzz_target;
use oss_core_fuzz::steps;
use oss_net::{Config, NullAcceptor, Priority, SendFlags, Server, VieAcceptor};

fn drain(server: &mut Server<u8>, limit: usize) {
    while let Some((_, d)) = server.poll_transmit() {
        assert!(d.len() <= limit, "datagram of {} bytes", d.len());
        server.recycle(d);
    }
    while server.poll_event().is_some() {}
}

fuzz_target!(|data: &[u8]| {
    let cfg = Config::server();
    let limit = cfg.max_send;
    let mut server = Server::new(cfg);
    server.add_acceptor(Box::new(NullAcceptor));
    server.add_acceptor(Box::new(VieAcceptor::default()));
    let mut now = 0u64;
    for step in steps(data) {
        now += step.advance;
        let peer = step.peer;
        match step.action {
            0..=7 => server.handle_datagram(now, peer, step.data),
            8 => {
                server.send(&peer, step.data, true);
            }
            9 => {
                server.send(&peer, step.data, false);
            }
            10 => {
                // A big reliable packet built from the step's bytes.
                let big: Vec<u8> = step
                    .data
                    .iter()
                    .copied()
                    .cycle()
                    .take(step.data.len() * 7)
                    .collect();
                if !big.is_empty() {
                    server.send(&peer, &big, true);
                }
            }
            11 => {
                let flags = SendFlags {
                    reliable: false,
                    priority: Priority::Low,
                    droppable: true,
                };
                server.send_with(&peer, step.data, flags);
            }
            12 => {
                if let Some(c) = server.connection_mut(&peer) {
                    c.send_sized(step.data.repeat(40));
                }
            }
            13 => server.disconnect(&peer),
            _ => server.tick(now),
        }
        server.tick(now);
        drain(&mut server, limit);
    }
    // Let every timer fire.
    for _ in 0..40 {
        now += 1_000;
        server.tick(now);
        drain(&mut server, limit);
    }
});
