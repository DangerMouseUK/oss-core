//! Unreliable priorities, urgent sends and the droppable budget.

use oss_net::{
    Config, Connection, Event, Priority, SendFlags, Server, VieAcceptor, VieClientHandshake,
};

const ADDR: u32 = 1;

fn pair(server_cfg: Config) -> (Connection, Server<u32>) {
    let mut server = Server::new(server_cfg);
    server.add_acceptor(Box::new(VieAcceptor::default()));
    let mut client = Connection::client(Config::client(), Box::new(VieClientHandshake::new(5)), 0);
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

/// Delivers everything the server has queued and returns the packets the
/// client received, in order.
fn deliver(client: &mut Connection, server: &mut Server<u32>, now: u64) -> Vec<Vec<u8>> {
    server.tick(now);
    while let Some((_, d)) = server.poll_transmit() {
        client.handle_datagram(now, &d);
    }
    let mut got = Vec::new();
    while let Some(e) = client.poll_event() {
        if let Event::Packet(p) = e {
            got.push(p);
        }
    }
    got
}

fn flags(priority: Priority, droppable: bool) -> SendFlags {
    SendFlags {
        reliable: false,
        priority,
        droppable,
    }
}

#[test]
fn priority_order() {
    let (mut client, mut server) = pair(Config::server());
    server.send_with(&ADDR, &[0x30, 1], flags(Priority::Low, false));
    server.send_with(&ADDR, &[0x30, 2], flags(Priority::Normal, false));
    server.send_with(&ADDR, &[0x30, 3], flags(Priority::High, false));
    let got = deliver(&mut client, &mut server, 20);
    let order: Vec<u8> = got.iter().filter(|p| p[0] == 0x30).map(|p| p[1]).collect();
    assert_eq!(order, [3, 2, 1]);
}

#[test]
fn urgent_bypasses_queue() {
    let (mut client, mut server) = pair(Config::server());
    let conn = server.connection_mut(&ADDR).unwrap();
    conn.send_with(&[0x31, 1], flags(Priority::Normal, false));
    conn.send_with(&[0x31, 2], flags(Priority::Urgent, false));
    // The urgent packet is already a datagram; the normal one waits for flush.
    let d = conn.poll_transmit().unwrap();
    client.handle_datagram(20, &d);
    assert!(matches!(client.poll_event(), Some(Event::Packet(p)) if p == [0x31, 2]));
    let got = deliver(&mut client, &mut server, 20);
    assert!(got.iter().any(|p| p[..] == [0x31, 1]));
}

#[test]
fn budget_drops_droppable_and_defers_the_rest() {
    let cfg = Config {
        unreliable_budget: Some(100),
        ..Config::server()
    };
    let (mut client, mut server) = pair(cfg);
    let big = [0x32u8; 40];
    // 3 x 40 bytes droppable at normal priority, 2 x 40 non-droppable at low.
    for _ in 0..3 {
        server.send_with(&ADDR, &big, flags(Priority::Normal, true));
    }
    let mut keep = [0x33u8; 40];
    for i in 0..2 {
        keep[1] = i;
        server.send_with(&ADDR, &keep, flags(Priority::Low, false));
    }
    let first = deliver(&mut client, &mut server, 20);
    // Budget 100: two droppables fit, the third is dropped, the low-priority
    // packets wait.
    assert_eq!(first.iter().filter(|p| p[0] == 0x32).count(), 2);
    assert_eq!(first.iter().filter(|p| p[0] == 0x33).count(), 0);
    assert_eq!(
        server.connection(&ADDR).unwrap().stats().dropped_outgoing,
        1
    );
    // Next flushes deliver the deferred packets in order.
    let mut later = deliver(&mut client, &mut server, 30);
    later.extend(deliver(&mut client, &mut server, 40));
    let kept: Vec<u8> = later
        .iter()
        .filter(|p| p[0] == 0x33)
        .map(|p| p[1])
        .collect();
    assert_eq!(kept, [0, 1]);
}
