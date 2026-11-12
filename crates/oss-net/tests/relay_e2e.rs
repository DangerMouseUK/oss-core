//! The WebSocket relay end to end, over loopback: a client `Connection` whose
//! datagrams travel as `oss-relay.1` frames in real WebSocket messages, to a
//! relay that feeds them into an oss-net `Server` and sends the replies back.
//! The zone echoes every packet, so the client checks reliable delivery, a big
//! packet split across datagrams, and the handshake through the relay, with VIE
//! and with OpenSec.

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use oss_net::relay::{CloseReason, Frame, MAX_DATAGRAM, SUBPROTOCOL, VERSION};
use oss_net::{Config, Connection, Event, Handshake, Server, VieAcceptor, VieClientHandshake};
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::server::{Request, Response};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

fn ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// Waits for one binary message, giving up rather than spinning for ever if the
/// peer never sends one: `read_binary` reports a closed connection as "nothing
/// yet", so without a deadline a failed handshake hangs the test instead of
/// failing it.
fn await_binary<S: std::io::Read + std::io::Write>(ws: &mut WebSocket<S>, what: &str) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Some(b) = read_binary(ws) {
            return b;
        }
    }
    panic!("no {what} arrived within 20s");
}

fn frame(f: &Frame<'_>) -> Message {
    let mut b = Vec::new();
    f.encode(&mut b).unwrap();
    Message::Binary(b.into())
}

/// Reads one binary message if one is ready (the socket has a short timeout).
fn read_binary<S: std::io::Read + std::io::Write>(ws: &mut WebSocket<S>) -> Option<Vec<u8>> {
    match ws.read() {
        Ok(Message::Binary(b)) => Some(b.to_vec()),
        Ok(_) => None,
        // Nothing has arrived yet. On Windows that includes OS error 997, which
        // reports a read that is still running and is not a failure.
        Err(tungstenite::Error::Io(e)) if oss_net::would_block(&e) => None,
        Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => None,
        Err(e) => panic!("websocket: {e}"),
    }
}

/// The relay and the zone behind it, for one WebSocket session.
// The handshake callback's error type is fixed by tungstenite.
#[allow(clippy::result_large_err)]
fn relay_zone(listener: TcpListener, opensec: bool, stop: Arc<AtomicBool>) {
    let (stream, _) = listener.accept().unwrap();
    let mut ws = tungstenite::accept_hdr(stream, |req: &Request, mut resp: Response| {
        let offered = req
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|p| p.trim() == SUBPROTOCOL));
        assert!(offered, "the client must offer {SUBPROTOCOL}");
        resp.headers_mut()
            .insert("Sec-WebSocket-Protocol", SUBPROTOCOL.parse().unwrap());
        Ok(resp)
    })
    .unwrap();
    ws.get_mut()
        .set_read_timeout(Some(Duration::from_millis(2)))
        .unwrap();

    // Hello, then Welcome.
    let hello = await_binary(&mut ws, "Hello");
    assert!(matches!(
        Frame::decode(&hello),
        Ok(Frame::Hello {
            version: VERSION,
            ..
        })
    ));
    ws.send(frame(&Frame::Welcome {
        version: VERSION,
        max_datagram: MAX_DATAGRAM as u16,
        idle_timeout_ms: 60_000,
    }))
    .unwrap();

    let mut server: Server<u8> = Server::new(Config::server());
    if opensec {
        server.add_acceptor(Box::new(oss_net::opensec::OpenSecAcceptor::new(
            None,
            oss_net::opensec::os_entropy(),
        )));
    }
    server.add_acceptor(Box::new(VieAcceptor::default()));
    let start = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        while let Some(b) = read_binary(&mut ws) {
            match Frame::decode(&b) {
                Ok(Frame::Datagram(d)) => server.handle_datagram(ms(start), 0, d),
                Ok(Frame::Close { .. }) => return,
                other => panic!("unexpected frame {other:?}"),
            }
        }
        server.tick(ms(start));
        // The zone echoes every game packet back, reliably.
        while let Some((peer, e)) = server.poll_event() {
            if let Event::Packet(p) = e {
                server.send(&peer, &p, true);
                server.recycle(p);
            }
        }
        while let Some((_, d)) = server.poll_transmit() {
            ws.send(frame(&Frame::Datagram(&d))).unwrap();
            server.recycle(d);
        }
    }
}

fn run(opensec: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let relay = {
        let stop = stop.clone();
        thread::spawn(move || relay_zone(listener, opensec, stop))
    };

    // The browser side, here native: WebSocket with the subprotocol.
    let mut req = format!("ws://{addr}").into_client_request().unwrap();
    req.headers_mut()
        .insert("Sec-WebSocket-Protocol", SUBPROTOCOL.parse().unwrap());
    let (mut ws, resp) = tungstenite::connect(req).unwrap();
    assert_eq!(
        resp.headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok()),
        Some(SUBPROTOCOL)
    );
    if let MaybeTlsStream::Plain(s) = ws.get_mut() {
        s.set_read_timeout(Some(Duration::from_millis(2))).unwrap();
    }
    ws.send(frame(&Frame::Hello {
        version: VERSION,
        zone: "",
    }))
    .unwrap();
    let welcome = await_binary(&mut ws, "Welcome");
    assert!(matches!(
        Frame::decode(&welcome),
        Ok(Frame::Welcome {
            version: VERSION,
            ..
        })
    ));

    let handshake: Box<dyn Handshake> = if opensec {
        Box::new(oss_net::opensec::OpenSecClientHandshake::new(
            &oss_net::opensec::os_entropy(),
            None,
        ))
    } else {
        Box::new(VieClientHandshake::new(42))
    };
    let start = Instant::now();
    let mut conn = Connection::client(Config::client(), handshake, 0);
    let mut sent = false;
    let mut echoed = Vec::new();
    // 50 small packets and one big one (split across datagrams by the big-data
    // layer), all echoed back in order.
    let mut expected: Vec<Vec<u8>> = (0..50u8).map(|i| vec![0x40, i, i, i]).collect();
    // A game packet starts with a non-zero type byte.
    let mut big: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
    big[0] = 0x41;
    expected.push(big);
    while echoed.len() < expected.len() && start.elapsed() < Duration::from_secs(20) {
        while let Some(b) = read_binary(&mut ws) {
            let Ok(Frame::Datagram(d)) = Frame::decode(&b) else {
                panic!("unexpected frame from the relay");
            };
            conn.handle_datagram(ms(start), d);
        }
        conn.tick(ms(start));
        if conn.is_connected() && !sent {
            for p in &expected {
                conn.send(p, true);
            }
            sent = true;
        }
        while let Some(d) = conn.poll_transmit() {
            assert!(d.len() <= MAX_DATAGRAM);
            ws.send(frame(&Frame::Datagram(&d))).unwrap();
            conn.recycle(d);
        }
        while let Some(e) = conn.poll_event() {
            if let Event::Packet(p) = e {
                echoed.push(p);
            }
        }
    }
    assert_eq!(
        echoed, expected,
        "every packet echoed through the relay, in order"
    );
    let kind = conn.cipher_kind();
    assert_eq!(
        kind,
        Some(if opensec {
            oss_net::CipherKind::OpenSec
        } else {
            oss_net::CipherKind::Vie
        })
    );

    conn.disconnect();
    while let Some(d) = conn.poll_transmit() {
        ws.send(frame(&Frame::Datagram(&d))).unwrap();
    }
    ws.send(frame(&Frame::Close {
        reason: CloseReason::Normal,
        message: "bye",
    }))
    .unwrap();
    stop.store(true, Ordering::Relaxed);
    relay.join().unwrap();
}

#[test]
fn vie_session_through_the_websocket_relay() {
    run(false);
}

#[test]
fn opensec_session_through_the_websocket_relay() {
    run(true);
}
