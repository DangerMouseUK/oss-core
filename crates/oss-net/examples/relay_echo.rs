//! A WebSocket relay (`oss-relay.1`) in front of a tiny echo zone, for trying
//! clients that connect through the relay, such as `examples/browser.rs`.
//!
//! ```sh
//! cargo run -p oss-net --example relay_echo -- 127.0.0.1:5700
//! ```
//!
//! Each WebSocket session gets its own `oss-net` `Server` (OpenSec and VIE),
//! which echoes every game packet back reliably. The protocol is in
//! `docs/protocol/websocket-relay.md`.

use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use oss_net::opensec::{OpenSecAcceptor, os_entropy};
use oss_net::relay::{CloseReason, Frame, MAX_DATAGRAM, SUBPROTOCOL, VERSION};
use oss_net::{Config, Event, Server, VieAcceptor};
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::{Message, WebSocket};

fn send(ws: &mut WebSocket<std::net::TcpStream>, f: &Frame<'_>) -> tungstenite::Result<()> {
    let mut b = Vec::new();
    f.encode(&mut b).expect("valid frame");
    ws.send(Message::Binary(b.into()))
}

// The handshake callback's error type is fixed by tungstenite.
#[allow(clippy::result_large_err)]
fn session(stream: std::net::TcpStream) -> tungstenite::Result<()> {
    let peer = stream.peer_addr().ok();
    let mut ws = tungstenite::accept_hdr(stream, |req: &Request, mut resp: Response| {
        let offered = req
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|p| p.trim() == SUBPROTOCOL));
        if !offered {
            let mut e = ErrorResponse::new(Some(format!("subprotocol {SUBPROTOCOL} required")));
            *e.status_mut() = tungstenite::http::StatusCode::BAD_REQUEST;
            return Err(e);
        }
        resp.headers_mut()
            .insert("Sec-WebSocket-Protocol", SUBPROTOCOL.parse().unwrap());
        Ok(resp)
    })
    .map_err(|e| match e {
        tungstenite::HandshakeError::Failure(e) => e,
        tungstenite::HandshakeError::Interrupted(_) => tungstenite::Error::ConnectionClosed,
    })?;
    ws.get_mut()
        .set_read_timeout(Some(Duration::from_millis(2)))?;
    println!("session from {peer:?}");

    let mut server: Server<u8> = Server::new(Config::server());
    server.add_acceptor(Box::new(OpenSecAcceptor::new(None, os_entropy())));
    server.add_acceptor(Box::new(VieAcceptor::default()));
    let start = Instant::now();
    let mut welcomed = false;
    loop {
        let now = start.elapsed().as_millis() as u64;
        loop {
            match ws.read() {
                Ok(Message::Binary(b)) => match Frame::decode(&b) {
                    Ok(Frame::Hello { .. }) if !welcomed => {
                        welcomed = true;
                        send(
                            &mut ws,
                            &Frame::Welcome {
                                version: VERSION,
                                max_datagram: MAX_DATAGRAM as u16,
                                idle_timeout_ms: 60_000,
                            },
                        )?;
                    }
                    Ok(Frame::Datagram(d)) if welcomed => server.handle_datagram(now, 0, d),
                    Ok(Frame::Close { .. }) => {
                        println!("session from {peer:?} closed");
                        return Ok(());
                    }
                    _ => {
                        send(
                            &mut ws,
                            &Frame::Close {
                                reason: CloseReason::ProtocolError,
                                message: "unexpected frame",
                            },
                        )?;
                        return Ok(());
                    }
                },
                Ok(Message::Close(_)) => return Ok(()),
                Ok(_) => {}
                Err(tungstenite::Error::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        server.tick(now);
        while let Some((peer, e)) = server.poll_event() {
            match e {
                Event::Packet(p) => {
                    server.send(&peer, &p, true);
                    server.recycle(p);
                }
                Event::Connected => {
                    let kind = server.connection(&peer).and_then(|c| c.cipher_kind());
                    println!("  connected, encryption {kind:?}");
                }
                _ => {}
            }
        }
        while let Some((_, d)) = server.poll_transmit() {
            send(&mut ws, &Frame::Datagram(&d))?;
            server.recycle(d);
        }
    }
}

fn main() -> std::io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:5700".into());
    let listener = TcpListener::bind(&addr)?;
    println!("relay listening on ws://{addr} (subprotocol {SUBPROTOCOL})");
    for stream in listener.incoming() {
        let stream = stream?;
        thread::spawn(move || {
            if let Err(e) = session(stream) {
                println!("session ended: {e}");
            }
        });
    }
    Ok(())
}
