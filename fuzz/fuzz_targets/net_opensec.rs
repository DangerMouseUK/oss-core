#![no_main]
//! OpenSec. The first byte picks a scenario:
//!
//! * records: a sender seals 100 datagrams; the fuzzer delivers them in
//!   any order, duplicated, truncated or bit-flipped, mixed with garbage. The
//!   receiver must accept exactly what a reference replay window accepts, and
//!   return the original plaintext.
//! * server: arbitrary datagrams to a server with the OpenSec acceptor.
//! * client: arbitrary datagrams to a client running the OpenSec handshake.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use libfuzzer_sys::fuzz_target;
use oss_core_fuzz::steps;
use oss_net::opensec::{
    Entropy, OpenSecAcceptor, OpenSecCipher, OpenSecClientHandshake, ServerKey, SessionKeys,
};
use oss_net::{Cipher, Config, Connection, Server};

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

fn records(data: &[u8]) {
    let keys = SessionKeys {
        transcript: [1; 32],
        c2s: [2; 32],
        s2c: [3; 32],
        client_identity: None,
    };
    let mut sender = OpenSecCipher::new(&keys, false, None);
    let mut receiver = OpenSecCipher::new(&keys, true, None);
    let mut sealed = Vec::new();
    for i in 0..100u32 {
        let mut d = i.to_le_bytes().repeat(1 + i as usize % 5);
        sender.encrypt(&mut d);
        sealed.push(d);
    }
    // Reference window: counters are index + 1.
    let mut accepted = HashSet::new();
    let mut highest = 0u64;
    for pair in data.chunks(2) {
        let (op, arg) = (pair[0], *pair.get(1).unwrap_or(&0));
        let idx = usize::from(arg) % sealed.len();
        let mut d = sealed[idx].clone();
        match op % 4 {
            0 | 1 => {
                let counter = idx as u64 + 1;
                let fresh =
                    !accepted.contains(&counter) && (counter > highest || highest - counter < 64);
                let ok = receiver.decrypt(&mut d);
                assert_eq!(ok, fresh, "counter {counter}, highest {highest}");
                if ok {
                    assert_eq!(d, (idx as u32).to_le_bytes().repeat(1 + idx % 5));
                    accepted.insert(counter);
                    highest = highest.max(counter);
                }
            }
            2 => {
                // Any single-bit change must be rejected.
                let bit = usize::from(op >> 2) % (d.len() * 8);
                d[bit / 8] ^= 1 << (bit % 8);
                assert!(!receiver.decrypt(&mut d));
            }
            _ => {
                d.truncate(usize::from(op >> 2) % d.len());
                assert!(!receiver.decrypt(&mut d));
            }
        }
    }
}

fn server(data: &[u8]) {
    let key = ServerKey::generate(&entropy(5));
    let mut server: Server<u8> = Server::new(Config::server());
    server.add_acceptor(Box::new(OpenSecAcceptor::new(Some(key), entropy(9))));
    let mut now = 0;
    for step in steps(data) {
        now += step.advance;
        server.handle_datagram(now, step.peer, step.data);
        if step.action == 15 {
            server.send(&step.peer, step.data, true);
        }
        server.tick(now);
        while server.poll_transmit().is_some() {}
        while server.poll_event().is_some() {}
    }
}

fn client(data: &[u8]) {
    let hs = OpenSecClientHandshake::new(&entropy(3), None);
    let mut client = Connection::client(Config::client(), Box::new(hs), 0);
    let mut now = 0;
    for step in steps(data) {
        now += step.advance;
        client.handle_datagram(now, step.data);
        client.tick(now);
        while client.poll_transmit().is_some() {}
        while client.poll_event().is_some() {}
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, data)) = data.split_first() else {
        return;
    };
    match which % 3 {
        0 => records(data),
        1 => server(data),
        _ => client(data),
    }
});
