//! A blocking UDP loop around [`Session`].

use std::io;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use oss_net::DisconnectReason;

use crate::{BotConfig, BotEvent, Session};

/// Reacts to a bot's events. Closures `FnMut(&mut Session, BotEvent)` implement
/// it too.
pub trait Handler {
    /// Called for every event, in order.
    fn on_event(&mut self, bot: &mut Session, event: BotEvent);

    /// Called about every 10 ms, for timers and movement.
    fn on_tick(&mut self, _bot: &mut Session, _now_ms: u64) {}
}

impl<F: FnMut(&mut Session, BotEvent)> Handler for F {
    fn on_event(&mut self, bot: &mut Session, event: BotEvent) {
        self(bot, event)
    }
}

/// Connects to `server`, logs in and runs `handler` until the connection
/// closes. Returns why it closed.
pub fn run(
    server: impl ToSocketAddrs,
    config: BotConfig,
    handler: &mut impl Handler,
) -> io::Result<DisconnectReason> {
    let addr = server
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address for server"))?;
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(10)))?;

    let start = Instant::now();
    let now = || start.elapsed().as_millis() as u64;
    let mut bot = Session::new(config, now());
    let mut buf = [0u8; 2048];
    loop {
        match socket.recv(&mut buf) {
            Ok(n) => bot.handle_datagram(now(), &buf[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::ConnectionReset
                ) => {}
            Err(e) => return Err(e),
        }
        let t = now();
        bot.tick(t);
        handler.on_tick(&mut bot, t);
        while let Some(event) = bot.poll_event() {
            if let BotEvent::Disconnected(reason) = event {
                handler.on_event(&mut bot, BotEvent::Disconnected(reason));
                flush(&socket, &mut bot);
                return Ok(reason);
            }
            handler.on_event(&mut bot, event);
        }
        flush(&socket, &mut bot);
    }
}

fn flush(socket: &UdpSocket, bot: &mut Session) {
    while let Some(d) = bot.poll_transmit() {
        // A lost datagram is the transport's problem; errors here are transient.
        let _ = socket.send(&d);
        bot.recycle(d);
    }
}
