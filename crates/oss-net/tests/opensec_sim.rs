//! OpenSec end to end: connections through `Server`, lossy links, fallback to
//! VIE for servers without OpenSec, and pinning.

#![cfg(feature = "opensec")]

use std::sync::{Arc, Mutex};

use oss_net::opensec::{Entropy, OpenSecAcceptor, OpenSecClientHandshake, ServerKey};
use oss_net::{
    CipherKind, Config, Connection, DisconnectReason, Event, Fallback, Handshake, Server,
    VieAcceptor, VieClientHandshake,
};

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

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

const ADDR: u32 = 3;

/// Runs client and server over a link losing `loss`% of datagrams in each
/// direction (with some duplication), for up to `ms`, until `done`.
fn run(
    client: &mut Connection,
    server: &mut Server<u32>,
    loss: u64,
    ms: u64,
    mut done: impl FnMut(&Connection, &Server<u32>, &[Event], &[Event]) -> bool,
) -> (Vec<Event>, Vec<Event>) {
    let mut rng = Rng(0xABCD_EF01);
    let (mut ce, mut se) = (Vec::new(), Vec::new());
    let mut now = 0;
    while now < ms {
        now += 10;
        client.tick(now);
        server.tick(now);
        while let Some(d) = client.poll_transmit() {
            for _ in 0..if rng.next() % 100 < 3 { 2 } else { 1 } {
                if rng.next() % 100 >= loss {
                    server.handle_datagram(now, ADDR, &d);
                }
            }
        }
        while let Some((_, d)) = server.poll_transmit() {
            if rng.next() % 100 >= loss {
                client.handle_datagram(now, &d);
            }
        }
        while let Some(e) = client.poll_event() {
            ce.push(e);
        }
        while let Some((_, e)) = server.poll_event() {
            se.push(e);
        }
        if done(client, server, &ce, &se) {
            return (ce, se);
        }
    }
    panic!("did not finish in {ms} ms: client {client:?}");
}

fn count(events: &[Event], marker: u8) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, Event::Packet(p) if p[0] == marker))
        .count()
}

fn opensec_server(key: Option<ServerKey>) -> Server<u32> {
    let mut s = Server::new(Config::server());
    s.add_acceptor(Box::new(OpenSecAcceptor::new(key, entropy(7))));
    s.add_acceptor(Box::new(VieAcceptor::default()));
    s
}

#[test]
fn opensec_session_over_lossy_link() {
    let key = ServerKey::generate(&entropy(99));
    let mut server = opensec_server(Some(key.clone()));
    let hs = OpenSecClientHandshake::new(&entropy(1), Some(key.public()));
    let mut client = Connection::client(Config::client(), Box::new(hs), 0);
    run(&mut client, &mut server, 15, 20_000, |c, s, _, _| {
        c.is_connected() && s.len() == 1
    });
    assert_eq!(client.cipher_kind(), Some(CipherKind::OpenSec));
    assert_eq!(client.peer_key(), Some(key.public()));
    assert_eq!(
        server.connection(&ADDR).unwrap().cipher_kind(),
        Some(CipherKind::OpenSec)
    );

    // Mixed traffic, including packets that fill a datagram and big ones: the
    // 21-byte overhead must still fit.
    for i in 0..200u32 {
        let len = [5usize, 400, 485, 486, 506, 1500][i as usize % 6];
        let mut p = vec![0x40u8; len];
        p[1..5].copy_from_slice(&i.to_le_bytes());
        client.send(&p, true);
        server.send(&ADDR, &p, true);
    }
    let (ce, se) = run(&mut client, &mut server, 10, 600_000, |_, _, ce, se| {
        count(ce, 0x40) == 200 && count(se, 0x40) == 200
    });
    for events in [&ce, &se] {
        let idx: Vec<u32> = events
            .iter()
            .filter_map(|e| match e {
                Event::Packet(p) if p[0] == 0x40 => {
                    Some(u32::from_le_bytes(p[1..5].try_into().unwrap()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(idx, (0..200).collect::<Vec<_>>(), "in order, exactly once");
    }
    assert!(client.stats().bytes_sent > 0);
}

#[test]
fn fallback_to_vie_for_legacy_servers() {
    // A server that only knows VIE ignores the OpenSec hello.
    let mut server = Server::new(Config::server());
    server.add_acceptor(Box::new(VieAcceptor::default()));
    let hs: Box<dyn Handshake> = Box::new(Fallback::new(
        Box::new(OpenSecClientHandshake::new(&entropy(2), None)),
        Box::new(VieClientHandshake::new(5)),
        1_000,
    ));
    let mut client = Connection::client(Config::client(), hs, 0);
    run(&mut client, &mut server, 0, 5_000, |c, s, _, _| {
        c.is_connected() && s.len() == 1
    });
    assert_eq!(client.cipher_kind(), Some(CipherKind::Vie));

    // Against an OpenSec server the same client setup uses OpenSec.
    let mut server = opensec_server(None);
    let hs: Box<dyn Handshake> = Box::new(Fallback::new(
        Box::new(OpenSecClientHandshake::new(&entropy(3), None)),
        Box::new(VieClientHandshake::new(5)),
        1_000,
    ));
    let mut client = Connection::client(Config::client(), hs, 0);
    run(&mut client, &mut server, 0, 5_000, |c, s, _, _| {
        c.is_connected() && s.len() == 1
    });
    assert_eq!(client.cipher_kind(), Some(CipherKind::OpenSec));
    assert_eq!(client.peer_key(), None);
}

#[test]
fn wrong_pinned_key_fails_without_downgrade() {
    let mut server = opensec_server(Some(ServerKey::generate(&entropy(4))));
    let hs: Box<dyn Handshake> = Box::new(Fallback::new(
        Box::new(OpenSecClientHandshake::new(&entropy(5), Some([9; 32]))),
        Box::new(VieClientHandshake::new(5)),
        1_000,
    ));
    let mut client = Connection::client(Config::client(), hs, 0);
    let (ce, _) = run(&mut client, &mut server, 0, 5_000, |c, _, _, _| {
        c.is_closed()
    });
    assert!(
        ce.iter()
            .any(|e| matches!(e, Event::Disconnected(DisconnectReason::HandshakeFailed(_))))
    );
    assert_eq!(client.cipher_kind(), None);
}
