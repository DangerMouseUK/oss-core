#![no_main]
//! The client role: a connection that has completed an unencrypted handshake
//! receives arbitrary datagrams, interleaved with sends and ticks.

use libfuzzer_sys::fuzz_target;
use oss_core_fuzz::steps;
use oss_net::{Config, Connection, VieClientHandshake};

fn drain(client: &mut Connection, limit: usize) {
    while let Some(d) = client.poll_transmit() {
        assert!(d.len() <= limit, "datagram of {} bytes", d.len());
        client.recycle(d);
    }
    while client.poll_event().is_some() {}
}

fuzz_target!(|data: &[u8]| {
    let cfg = Config::client();
    let limit = cfg.max_send;
    let mut client = Connection::client(cfg, Box::new(VieClientHandshake::new(7)), 0);
    client.tick(0);
    let request = client.poll_transmit().expect("connection request");
    // Echoing the client key selects no encryption.
    let mut reply = vec![0, 2];
    reply.extend_from_slice(&request[2..6]);
    client.handle_datagram(0, &reply);
    assert!(client.is_connected());
    drain(&mut client, limit);

    let mut now = 0u64;
    for step in steps(data) {
        now += step.advance;
        match step.action {
            0..=9 => client.handle_datagram(now, step.data),
            10 => client.send(step.data, true),
            11 => client.send(step.data, false),
            12 => {
                let big = step.data.repeat(7);
                if !big.is_empty() {
                    client.send(&big, true);
                }
            }
            13 => client.cancel_incoming_sized(),
            14 => client.disconnect(),
            _ => {}
        }
        client.tick(now);
        drain(&mut client, limit);
    }
    for _ in 0..40 {
        now += 1_000;
        client.tick(now);
        drain(&mut client, limit);
    }
});
