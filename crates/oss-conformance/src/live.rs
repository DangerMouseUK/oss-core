//! Live checks over UDP: the suite plays a client against a server under test,
//! or a zone that a client under test connects to.
//!
//! Each check is described in `docs/conformance.md`. The transport-level server
//! checks use hand-built datagrams; everything after the handshake uses
//! `oss-net`'s connection, which is itself verified against the reference
//! vectors.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use oss_formats::Level;
use oss_net::opensec::{OpenSecAcceptor, os_entropy};
use oss_net::{
    Config, Connection, Event, Server, VieAcceptor, VieCipher, VieClientHandshake,
    vie::server_key_for,
};
use oss_proto::c2s::{self, GoArena, Login, MapRequest, SecurityResponse, arena_type};
use oss_proto::checksum::{crc32, map_checksum, settings_checksum, vie_exe_checksum};
use oss_proto::common::PlayerData;
use oss_proto::s2c::{self, MapFilename, login_code};
use oss_proto::wire::FixedStr;
use oss_proto::{C2SPacket, C2SPosition, CorePacket, S2CPacket};

use crate::report::Report;
use crate::vectors::{MAPS, unhex};

/// The settings packet the suite's zone sends (from the reference server).
fn reference_settings() -> Vec<u8> {
    let text = crate::vectors::FILES
        .iter()
        .find(|(n, _)| *n == "clientset-asss-public.txt")
        .map(|(_, t)| *t)
        .unwrap_or("");
    text.lines()
        .find_map(|l| l.strip_prefix("packet "))
        .and_then(|h| unhex(h.trim()))
        .unwrap_or_default()
}

/// The map the suite's zone serves: one of the project's seeded synthetic maps
/// (no third-party data), whose checksums are in the vectors.
const SERVED_MAP: &str = "synth-a-plain.lvl";

fn served_map() -> &'static [u8] {
    MAPS.iter()
        .find(|(n, _)| *n == SERVED_MAP)
        .map(|(_, b)| *b)
        .unwrap_or(&[])
}

fn seed() -> u32 {
    let mut b = [0u8; 4];
    os_entropy()(&mut b);
    u32::from_le_bytes(b)
}

/// Monotonic milliseconds since `start`.
fn ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

// ---- server under test -------------------------------------------------------------

/// Options for [`check_server`].
#[derive(Clone)]
pub struct ServerOptions {
    /// Login name; a random `conformance-xxxx` name if `None`.
    pub name: Option<String>,
    /// Password.
    pub password: String,
    /// Arena to enter (`None` = any public arena).
    pub arena: Option<String>,
    /// How long to wait for each answer.
    pub timeout: Duration,
}

/// Written by hand so the password never reaches a log; every other field
/// prints as it would from `derive`. See [`oss_proto::wire::Redacted`].
impl std::fmt::Debug for ServerOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerOptions")
            .field("name", &self.name)
            .field("password", &oss_proto::wire::Redacted)
            .field("arena", &self.arena)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            name: None,
            password: "conformance".into(),
            arena: None,
            timeout: Duration::from_secs(5),
        }
    }
}

/// Unwraps clusters and reliables (acking nothing) and returns every packet in
/// a datagram, plus the sequence numbers of reliables it carried.
fn flatten(d: &[u8], out: &mut Vec<Vec<u8>>, reliables: &mut Vec<u32>, depth: u32) {
    if depth > 4 {
        return;
    }
    match CorePacket::decode(d) {
        Ok(CorePacket::Cluster(c)) => {
            for item in c.iter().flatten() {
                flatten(item, out, reliables, depth + 1);
            }
        }
        Ok(CorePacket::Reliable { seq, payload }) => {
            reliables.push(seq);
            flatten(payload, out, reliables, depth + 1);
        }
        _ => out.push(d.to_vec()),
    }
}

/// A raw VIE session for the transport checks.
struct Raw {
    sock: UdpSocket,
    cipher: Option<VieCipher>,
}

impl Raw {
    fn send(&self, mut d: Vec<u8>) -> io::Result<()> {
        if let Some(c) = &self.cipher {
            c.encrypt(&mut d);
        }
        self.sock.send(&d).map(|_| ())
    }

    /// Receives packets until `want` matches one or `timeout` passes; returns
    /// every packet seen. Acknowledges server reliables.
    fn collect(
        &self,
        timeout: Duration,
        mut want: impl FnMut(&[u8]) -> bool,
    ) -> (bool, Vec<Vec<u8>>) {
        let start = Instant::now();
        let mut seen = Vec::new();
        let mut buf = [0u8; 2048];
        while start.elapsed() < timeout {
            let Ok(n) = self.sock.recv(&mut buf) else {
                continue;
            };
            let mut d = buf[..n].to_vec();
            if let Some(c) = &self.cipher {
                c.decrypt(&mut d);
            }
            let (mut pkts, mut rel) = (Vec::new(), Vec::new());
            flatten(&d, &mut pkts, &mut rel, 0);
            for seq in rel {
                let mut ack = vec![0, 4];
                ack.extend_from_slice(&seq.to_le_bytes());
                let _ = self.send(ack);
            }
            let mut hit = false;
            for p in pkts {
                hit |= want(&p);
                seen.push(p);
            }
            if hit {
                return (true, seen);
            }
        }
        (false, seen)
    }
}

fn sync_request(time: u32) -> Vec<u8> {
    let mut p = vec![0, 5];
    p.extend_from_slice(&time.to_le_bytes());
    p.extend_from_slice(&[0; 8]);
    p
}

fn is_sync_response(p: &[u8], time: u32) -> bool {
    matches!(CorePacket::decode(p), Ok(CorePacket::SyncResponse { client_time, .. }) if client_time == time)
}

fn is_ack(p: &[u8], want: u32) -> bool {
    matches!(CorePacket::decode(p), Ok(CorePacket::Ack { seq }) if seq == want)
}

/// Repeats `attempt` until one reports success, or until `timeout` passes.
///
/// Checks whose stimulus is an *unreliable* packet need this: the server has
/// nothing to retransmit, so a single datagram lost on the way out or back --
/// which a loaded machine does -- would fail a check about what the server
/// does with what it receives. The reliable checks need it too: the suite
/// builds its reliables by hand and has no reliable layer of its own, so
/// nothing retransmits them, and the acknowledgements and core answers that
/// come back are unreliable in any case.
///
/// Each attempt is judged on its own and nothing carries over between them,
/// so a check that wants two answers still has to get both out of one
/// stimulus. `attempt` is given its number so it can vary the packet it
/// sends and keep a late answer to an earlier attempt from being counted
/// for a later one.
fn until_answered(
    timeout: Duration,
    mut attempt: impl FnMut(u32) -> io::Result<bool>,
) -> io::Result<bool> {
    let start = Instant::now();
    let mut n = 0;
    loop {
        if attempt(n)? {
            return Ok(true);
        }
        if start.elapsed() >= timeout {
            return Ok(false);
        }
        n += 1;
    }
}

/// Checks a server at `addr`: transport behaviour with hand-built datagrams,
/// then login, arena entry, map download and the security exchange.
pub fn check_server(addr: SocketAddr, opts: &ServerOptions) -> io::Result<Report> {
    let mut r = Report::default();
    if let Some(pop) = ping(addr, opts.timeout)? {
        r.pass("server.ping", format!("ping-port (population {pop})"));
    } else {
        r.fail(
            "server.ping",
            "ping-port",
            format!(
                "no 8-byte answer on port {} (game port + 1), which clients and directories ping",
                addr.port().wrapping_add(1)
            ),
        );
    }
    transport_checks(addr, opts, &mut r)?;
    session_checks(addr, opts, &mut r)?;
    Ok(r)
}

/// Pings the zone on game port + 1: 4 bytes out, 8 back (`u32` population,
/// then the 4 bytes echoed). Returns the population.
fn ping(addr: SocketAddr, timeout: Duration) -> io::Result<Option<u32>> {
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind)?;
    let mut target = addr;
    target.set_port(addr.port().wrapping_add(1));
    sock.set_read_timeout(Some(Duration::from_millis(250)))?;
    let token = seed().to_le_bytes();
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 64];
    while Instant::now() < deadline {
        sock.send_to(&token, target)?;
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if from == target && n == 8 && buf[4..8] == token {
                return Ok(Some(u32::from_le_bytes(buf[..4].try_into().unwrap())));
            }
        }
    }
    Ok(None)
}

fn transport_checks(addr: SocketAddr, opts: &ServerOptions, r: &mut Report) -> io::Result<()> {
    const G: &str = "server.transport";
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(addr)?;
    sock.set_read_timeout(Some(Duration::from_millis(50)))?;
    let mut raw = Raw { sock, cipher: None };

    // Connect: 00 01 key protocol(1), resent each second.
    let key = 0x8000_0000 | seed();
    let mut req = vec![0, 1];
    req.extend_from_slice(&key.to_le_bytes());
    req.extend_from_slice(&1u16.to_le_bytes());
    let start = Instant::now();
    let mut server_key = None;
    while server_key.is_none() && start.elapsed() < opts.timeout {
        raw.sock.send(&req)?;
        let (_, seen) = raw.collect(Duration::from_secs(1), |p| p.len() >= 6 && p[..2] == [0, 2]);
        server_key = seen
            .iter()
            .find(|p| p.len() >= 6 && p[..2] == [0, 2])
            .map(|p| u32::from_le_bytes(p[2..6].try_into().unwrap()));
    }
    let Some(server_key) = server_key else {
        r.fail(G, "connect", "no 00 02 answer to a VIE connection request");
        r.skip(G, "remaining transport checks", "not connected");
        return Ok(());
    };
    r.pass(G, "connect");

    // The same request again before any session traffic (as if the 00 02 was
    // lost): the server must answer again, with the same key.
    raw.sock.send(&req)?;
    let (_, seen) = raw.collect(opts.timeout, |p| p.len() >= 6 && p[..2] == [0, 2]);
    let again = seen
        .iter()
        .find(|p| p.len() >= 6 && p[..2] == [0, 2])
        .map(|p| u32::from_le_bytes(p[2..6].try_into().unwrap()));
    r.check(
        G,
        "connect-repeat",
        again == Some(server_key),
        format!("a repeated 00 01 got {again:08x?}, expected another 00 02 with {server_key:08x}"),
    );

    if server_key == key {
        r.pass(G, "connect-key (no encryption)");
    } else {
        r.check(
            G,
            "connect-key",
            server_key == server_key_for(key),
            format!("client key {key:08x}: expected server key {:08x} (or {key:08x} for none), got {server_key:08x}", server_key_for(key)),
        );
        raw.cipher = VieCipher::new(server_key);
    }

    // Time sync.
    let (ok, _) = {
        raw.send(sync_request(1111))?;
        raw.collect(opts.timeout, |p| is_sync_response(p, 1111))
    };
    r.check(G, "sync", ok, "no 00 06 echoing the 00 05 time");

    // The server's clock in sync responses runs forward at 100 ticks a second.
    let server_time = |raw: &Raw, t: u32| -> io::Result<Option<u32>> {
        raw.send(sync_request(t))?;
        let (_, seen) = raw.collect(opts.timeout, |p| is_sync_response(p, t));
        Ok(seen.iter().find_map(|p| match CorePacket::decode(p) {
            Ok(CorePacket::SyncResponse {
                client_time,
                server_time,
            }) if client_time == t => Some(server_time),
            _ => None,
        }))
    };
    let first = server_time(&raw, 1201)?;
    std::thread::sleep(Duration::from_millis(500));
    let second = server_time(&raw, 1202)?;
    match (first, second) {
        (Some(a), Some(b)) => {
            let d = b.wrapping_sub(a) as i32;
            r.check(
                G,
                "sync-clock",
                (25..=200).contains(&d),
                format!("server time moved {d} ticks over 0.5 s (expected about 50)"),
            );
        }
        _ => r.fail(G, "sync-clock", "no answer to a time sync request"),
    }

    // A reliable packet carrying a sync request: acked, and its payload handled.
    let mut rel = vec![0, 3];
    rel.extend_from_slice(&0u32.to_le_bytes());
    rel.extend_from_slice(&sync_request(2222));
    raw.send(rel.clone())?;
    let mut acked = false;
    let mut answered = 0;
    let (_, seen) = raw.collect(opts.timeout, |p| {
        acked |= is_ack(p, 0);
        answered += usize::from(is_sync_response(p, 2222));
        acked && answered > 0
    });
    let _ = seen;
    r.check(G, "reliable-ack", acked, "no 00 04 for reliable sequence 0");
    r.check(
        G,
        "reliable-payload",
        answered == 1,
        format!("expected one answer to the payload, got {answered}"),
    );

    // The same reliable again: acked again, payload not handled twice.
    raw.send(rel)?;
    let mut acked = false;
    let mut again = 0;
    raw.collect(Duration::from_millis(1500), |p| {
        acked |= is_ack(p, 0);
        again += usize::from(is_sync_response(p, 2222));
        false
    });
    r.check(
        G,
        "duplicate-reliable-acked",
        acked,
        "a duplicate reliable must be acknowledged again",
    );
    r.check(
        G,
        "duplicate-reliable-ignored",
        again == 0,
        "the duplicate's payload was handled again",
    );

    // A cluster of two sync requests: both answered, and both out of the same
    // cluster. Sync requests are unreliable, so the cluster is resent until one
    // attempt is answered in full; the times move with the attempt number so a
    // late answer to an earlier cluster cannot be read as this one's, and `a`
    // and `b` are judged per attempt so answering one packet per cluster never
    // adds up to a pass.
    let attempt_timeout = opts.timeout.min(Duration::from_secs(1));
    let both = until_answered(opts.timeout, |n| {
        let (first, second) = (3333 + n, 4444 + n);
        let mut cl = vec![0, 0x0E];
        for t in [first, second] {
            let s = sync_request(t);
            cl.push(s.len() as u8);
            cl.extend_from_slice(&s);
        }
        raw.send(cl)?;
        let (mut a, mut b) = (false, false);
        raw.collect(attempt_timeout, |p| {
            a |= is_sync_response(p, first);
            b |= is_sync_response(p, second);
            a && b
        });
        Ok(a && b)
    })?;
    r.check(
        G,
        "cluster",
        both,
        "both packets in a 00 0E cluster must be handled",
    );

    // Reliables that arrive out of order are delivered in order: each attempt
    // sends the higher sequence of a pair first and the lower one 100 ms later,
    // and the answer to the lower one must come back first. The gap is what
    // gives the check its teeth: a server that handled each reliable as it
    // arrived would answer in arrival order and show up as [2, 1].
    //
    // Nothing here is reliable in the other direction -- the acknowledgements
    // and the answers are both unreliable -- and the suite's reliables are
    // hand-built, so nothing retransmits them either. An attempt therefore
    // resends whichever of its pair is still unacknowledged, as a reliable
    // sender would; that is also what fills the hole the loss left in the
    // server's receive window, which everything after it would otherwise queue
    // behind. Once both are acknowledged the pair is through, so an attempt
    // that still has no answers starts a *fresh* pair instead of replaying this
    // one: a duplicate reliable is acknowledged but its payload is not handled
    // twice, so a replay could never produce the answers again. An attempt that
    // does see both answers is judged on them there and then -- a wrong order
    // is a real fault, not something to retry away.
    let reliable = |seq: u32, t: u32| {
        let mut p = vec![0, 3];
        p.extend_from_slice(&seq.to_le_bytes());
        p.extend_from_slice(&sync_request(t));
        p
    };
    let deadline = Instant::now() + opts.timeout;
    let mut next_seq = 1;
    let mut order = Vec::new();
    let mut acked = false;
    let _ = until_answered(opts.timeout, |n| {
        let (lo, hi) = (next_seq, next_seq + 1);
        next_seq += 2;
        let (low_time, high_time) = (7001 + n * 2, 7002 + n * 2);
        raw.send(reliable(hi, high_time))?;
        std::thread::sleep(Duration::from_millis(100));
        raw.send(reliable(lo, low_time))?;
        order.clear();
        let (mut ack_lo, mut ack_hi) = (false, false);
        loop {
            let (complete, _) = raw.collect(Duration::from_millis(250), |p| {
                ack_lo |= is_ack(p, lo);
                ack_hi |= is_ack(p, hi);
                if is_sync_response(p, low_time) {
                    order.push(1);
                }
                if is_sync_response(p, high_time) {
                    order.push(2);
                }
                ack_lo && ack_hi && order.len() >= 2
            });
            acked = ack_lo && ack_hi;
            if complete || acked || Instant::now() >= deadline {
                break;
            }
            if !ack_hi {
                raw.send(reliable(hi, high_time))?;
            }
            if !ack_lo {
                raw.send(reliable(lo, low_time))?;
            }
        }
        Ok(order.len() >= 2)
    })?;
    r.check(
        G,
        "reliable-out-of-order-acked",
        acked,
        "both reliables must be acknowledged",
    );
    r.check(
        G,
        "reliable-order",
        order == [1, 2],
        format!("payloads handled in the order {order:?}, expected [1, 2]"),
    );

    // Core packets the server does not use (00 0D, 00 0F) are ignored; the
    // session carries on.
    raw.send(vec![0, 0x0D])?;
    raw.send(vec![0, 0x0F, 1, 2, 3])?;
    raw.send(sync_request(8888))?;
    let (ok, _) = raw.collect(opts.timeout, |p| is_sync_response(p, 8888));
    r.check(
        G,
        "unknown-core-ignored",
        ok,
        "the session stopped answering after 00 0D / 00 0F",
    );

    // Disconnect: the session ends and later packets are ignored.
    raw.send(vec![0, 7])?;
    std::thread::sleep(Duration::from_millis(300));
    raw.send(sync_request(5555))?;
    let (answered, _) = raw.collect(Duration::from_millis(1500), |p| is_sync_response(p, 5555));
    r.check(
        G,
        "disconnect",
        !answered,
        "the server still answered after 00 07",
    );
    Ok(())
}

/// A client session over oss-net: collects decoded server packets.
struct Session {
    sock: UdpSocket,
    conn: Connection,
    start: Instant,
    packets: Vec<(Vec<u8>, S2CPacket)>,
    closed: bool,
}

impl Session {
    fn pump(&mut self, dur: Duration, mut until: impl FnMut(&S2CPacket) -> bool) -> bool {
        let end = Instant::now() + dur;
        let mut buf = [0u8; 2048];
        while Instant::now() < end {
            if let Ok(n) = self.sock.recv(&mut buf) {
                self.conn.handle_datagram(ms(self.start), &buf[..n]);
            }
            self.conn.tick(ms(self.start));
            while let Some(d) = self.conn.poll_transmit() {
                let _ = self.sock.send(&d);
            }
            let mut hit = false;
            while let Some(e) = self.conn.poll_event() {
                match e {
                    Event::Packet(p) => {
                        if let Ok(pk) = S2CPacket::decode(&p) {
                            hit |= until(&pk);
                            self.packets.push((p, pk));
                        }
                    }
                    Event::Disconnected(_) => self.closed = true,
                    _ => {}
                }
            }
            if hit || self.closed {
                return hit;
            }
        }
        false
    }

    fn send(&mut self, p: impl Into<C2SPacket>) {
        self.conn.send(&p.into().to_bytes(), true);
    }
}

fn session_checks(addr: SocketAddr, opts: &ServerOptions, r: &mut Report) -> io::Result<()> {
    const G: &str = "server.session";
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(addr)?;
    sock.set_read_timeout(Some(Duration::from_millis(5)))?;
    let start = Instant::now();
    let conn = Connection::client(
        Config::client(),
        Box::new(VieClientHandshake::new(seed())),
        0,
    );
    let mut s = Session {
        sock,
        conn,
        start,
        packets: Vec::new(),
        closed: false,
    };
    let deadline = Instant::now() + opts.timeout;
    while !s.conn.is_connected() && Instant::now() < deadline && !s.closed {
        s.pump(Duration::from_millis(50), |_| false);
    }
    if !s.conn.is_connected() {
        r.fail(G, "connect", "VIE session not established");
        return Ok(());
    }
    let name = opts
        .name
        .clone()
        .unwrap_or_else(|| format!("conformance-{:04x}", seed() & 0xFFFF));
    let login = |flags| Login {
        flags,
        name: FixedStr::new(name.as_bytes()),
        password: FixedStr::new(opts.password.as_bytes()),
        machine_id: seed(),
        ..Login::default()
    };
    s.send(login(0));
    let mut code = None;
    for attempt in 0..2 {
        s.pump(opts.timeout, |p| matches!(p, S2CPacket::LoginResponse(_)));
        code = s.packets.iter().rev().find_map(|(_, p)| match p {
            S2CPacket::LoginResponse(l) => Some(l.code),
            _ => None,
        });
        if code == Some(login_code::NEW_USER) && attempt == 0 {
            s.packets.clear();
            s.send(login(1));
            continue;
        }
        break;
    }
    let Some(code) = code else {
        r.fail(G, "login-response", "no S2C 0x0A login response");
        return Ok(());
    };
    r.pass(G, "login-response");
    if !matches!(
        code,
        login_code::OK | login_code::SPEC_ONLY | login_code::NO_SCORES
    ) {
        r.skip(
            G,
            "arena and map checks",
            format!("login refused with code {code} (try --name/--password)"),
        );
        return Ok(());
    }

    // Arena entry.
    s.packets.clear();
    let (arena_type, arena) = match &opts.arena {
        Some(a) => (arena_type::NAMED, FixedStr::new(a.as_bytes())),
        None => (arena_type::ANY_PUBLIC, FixedStr::default()),
    };
    s.send(GoArena {
        ship: 8,
        allow_audio: 1,
        obscenity_filter: 0,
        x_res: 1024,
        y_res: 768,
        arena_type,
        arena,
        optional_graphics: None,
    });
    s.pump(opts.timeout, |p| matches!(p, S2CPacket::EnteringArena(_)));
    // The ping port now counts this player. Servers may cache the figure (the
    // reference refreshes it at most every 2 s by default), so allow 10 s.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last = None;
    while Instant::now() < deadline {
        last = ping(addr, opts.timeout)?;
        if last.is_none_or(|p| p >= 1) {
            break;
        }
        s.pump(Duration::from_millis(500), |_| false);
    }
    match last {
        Some(pop) => r.check(
            "server.ping",
            "ping-population",
            pop >= 1,
            format!("population still {pop} 10 s after this player entered an arena"),
        ),
        None => r.skip(
            "server.ping",
            "ping-population",
            "no answer on the ping port",
        ),
    }
    let pos = |f: &dyn Fn(&S2CPacket) -> bool| s.packets.iter().position(|(_, p)| f(p));
    let pid = pos(&|p| matches!(p, S2CPacket::PlayerId(_)));
    let settings = pos(&|p| matches!(p, S2CPacket::Settings(_)));
    let me = pos(
        &|p| matches!(p, S2CPacket::PlayerEntering(e) if e.players.iter().any(|d| d.name.as_bytes().eq_ignore_ascii_case(name.as_bytes()))),
    );
    let mapname = pos(&|p| matches!(p, S2CPacket::MapFilename(_)));
    let entered = pos(&|p| matches!(p, S2CPacket::EnteringArena(_)));
    r.check(
        G,
        "arena-player-id",
        pid.is_some(),
        "no S2C 0x01 (your player id)",
    );
    r.check(
        G,
        "arena-settings",
        settings.is_some(),
        "no S2C 0x0F settings packet",
    );
    if let Some(i) = settings {
        r.check(
            G,
            "arena-settings-size",
            s.packets[i].0.len() == 1428,
            format!(
                "settings packet is {} bytes, not 1428",
                s.packets[i].0.len()
            ),
        );
    }
    r.check(
        G,
        "arena-self-listed",
        me.is_some(),
        "no S2C 0x03 listing this player",
    );
    r.check(
        G,
        "arena-map-filename",
        mapname.is_some(),
        "no S2C 0x29 map file name",
    );
    r.check(
        G,
        "arena-entered",
        entered.is_some(),
        "no S2C 0x02 (arena entry complete)",
    );
    if let (Some(a), Some(b), Some(c)) = (pid, settings, entered) {
        r.check(
            G,
            "arena-order",
            a < b && b < c && me.is_none_or(|m| m < c),
            "expected player id, settings, ..., entering arena last (reference order)",
        );
    }

    // Map download.
    let crc = mapname.and_then(|i| match &s.packets[i].1 {
        S2CPacket::MapFilename(MapFilename::Single { checksum, .. }) => Some(*checksum),
        S2CPacket::MapFilename(MapFilename::Files(f)) => f.first().map(|f| f.checksum),
        _ => None,
    });
    let mut grid = None;
    if let Some(crc) = crc {
        s.send(MapRequest { index: None });
        s.pump(opts.timeout * 4, |p| matches!(p, S2CPacket::MapData(_)));
        let data = s.packets.iter().rev().find_map(|(_, p)| match p {
            S2CPacket::MapData(m) => Some(m.data.clone()),
            _ => None,
        });
        match data {
            None => r.fail(G, "map-download", "no S2C 0x2A map data after C2S 0x0C"),
            Some(z) => {
                r.pass(G, "map-download");
                match miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&z, 16 << 20) {
                    Err(_) => r.fail(G, "map-zlib", "map data is not a zlib stream"),
                    Ok(lvl) => {
                        r.check(
                            G,
                            "map-crc",
                            crc32(&lvl) == crc,
                            format!(
                                "CRC-32 {:08x} does not match the 0x29 checksum {crc:08x}",
                                crc32(&lvl)
                            ),
                        );
                        match Level::parse(&lvl) {
                            Ok(l) => {
                                r.pass(G, "map-parses");
                                grid = Some(l.server_tile_grid().0);
                            }
                            Err(e) => r.fail(G, "map-parses", format!("not a valid .lvl: {e}")),
                        }
                    }
                }
            }
        }
    }

    // Security: answer any checksum request correctly; the server must keep the
    // session. Then send position updates for two seconds.
    s.pump(
        Duration::from_secs(2),
        |p| matches!(p, S2CPacket::Security(x) if x.key != 0),
    );
    let settings_bytes = settings.map(|i| s.packets[i].0.clone()).unwrap_or_default();
    let key = s.packets.iter().find_map(|(_, p)| match p {
        S2CPacket::Security(x) if x.key != 0 => Some(x.key),
        _ => None,
    });
    if let Some(key) = key {
        s.send(SecurityResponse {
            weapon_count: 0,
            settings_checksum: settings_checksum(key, &settings_bytes),
            exe_checksum: vie_exe_checksum(key),
            map_checksum: grid
                .as_ref()
                .map_or(0, |g| map_checksum(key, |x, y| g.get(x as u32, y as u32))),
            s2c_slow_total: 0,
            s2c_fast_total: 0,
            s2c_slow_current: 0,
            s2c_fast_current: 0,
            s2c_reliable_out: 0,
            ping_last: 0,
            ping_average: 0,
            ping_low: 0,
            ping_high: 0,
            slow_frame: 0,
            continuum: None,
        });
    } else {
        r.skip(
            G,
            "security",
            "the server sent no checksum request within 2 s",
        );
    }
    for i in 0..20 {
        let p = C2SPosition {
            time: s.conn.server_ticks(ms(s.start)),
            x: 512 * 16,
            y: 512 * 16 + i,
            ..C2SPosition::default()
        };
        s.conn.send(&C2SPacket::Position(p).to_bytes(), false);
        s.pump(Duration::from_millis(100), |_| false);
    }
    r.check(
        G,
        "session-kept",
        !s.closed,
        "the server closed the session after security and positions",
    );
    s.send(c2s::LeaveArena {});
    s.conn.disconnect();
    s.pump(Duration::from_millis(200), |_| false);
    Ok(())
}

// ---- client under test ---------------------------------------------------------------

/// Options for [`check_client`].
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// How long to wait for the client to connect.
    pub connect_timeout: Duration,
    /// How long to wait for each later step.
    pub timeout: Duration,
    /// Security checksum key sent to the client.
    pub security_key: u32,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(120),
            timeout: Duration::from_secs(10),
            security_key: 0x1234_5678,
        }
    }
}

/// The suite's zone side: a server with one client.
struct Zone {
    sock: UdpSocket,
    server: Server<SocketAddr>,
    start: Instant,
    peer: Option<SocketAddr>,
    packets: Vec<C2SPacket>,
    first: Option<Vec<u8>>,
    gone: bool,
}

impl Zone {
    fn pump(&mut self, dur: Duration, mut until: impl FnMut(&C2SPacket) -> bool) -> bool {
        let end = Instant::now() + dur;
        let mut buf = [0u8; 2048];
        while Instant::now() < end {
            if let Ok((n, from)) = self.sock.recv_from(&mut buf) {
                if self.peer.is_none() {
                    self.peer = Some(from);
                    self.first = Some(buf[..n].to_vec());
                }
                if Some(from) == self.peer {
                    self.server.handle_datagram(ms(self.start), from, &buf[..n]);
                }
            }
            self.server.tick(ms(self.start));
            while let Some((to, d)) = self.server.poll_transmit() {
                let _ = self.sock.send_to(&d, to);
                self.server.recycle(d);
            }
            let mut hit = false;
            while let Some((_, e)) = self.server.poll_event() {
                match e {
                    Event::Packet(p) => {
                        if let Ok(pk) = C2SPacket::decode(&p) {
                            hit |= until(&pk);
                            self.packets.push(pk);
                        }
                        self.server.recycle(p);
                    }
                    Event::Disconnected(_) => self.gone = true,
                    _ => {}
                }
            }
            if hit || self.gone {
                return hit;
            }
        }
        false
    }

    /// Whether a packet matching `pred` has arrived, waiting up to `dur`.
    fn wait_for(&mut self, dur: Duration, pred: impl Fn(&C2SPacket) -> bool) -> bool {
        self.packets.iter().any(&pred) || self.pump(dur, &pred)
    }

    fn send(&mut self, p: impl Into<S2CPacket>) {
        if let Some(peer) = self.peer {
            self.server.send(&peer, &p.into().to_bytes(), true);
        }
    }
}

/// Waits for one client on `sock` and checks it: connection request, login,
/// acknowledgements, arena entry, map download, position checksums, time sync
/// and the security checksums.
pub fn check_client(sock: UdpSocket, opts: &ClientOptions) -> io::Result<Report> {
    const G: &str = "client";
    let mut r = Report::default();
    sock.set_read_timeout(Some(Duration::from_millis(5)))?;
    let mut server = Server::new(Config::server());
    server.add_acceptor(Box::new(OpenSecAcceptor::new(None, os_entropy())));
    server.add_acceptor(Box::new(VieAcceptor {
        accept_continuum: false,
    }));
    let mut z = Zone {
        sock,
        server,
        start: Instant::now(),
        peer: None,
        packets: Vec::new(),
        first: None,
        gone: false,
    };
    let deadline = Instant::now() + opts.connect_timeout;
    while z.server.is_empty() && Instant::now() < deadline {
        z.pump(Duration::from_millis(50), |_| false);
        if let Some(f) = &z.first
            && f.len() == 8
            && f[..2] == [0, 1]
            && f[6] == 0x11
        {
            r.skip(
                G,
                "all",
                "Continuum protocol (0x11): its encryption is not part of the public suite",
            );
            return Ok(r);
        }
    }
    let Some(peer) = z.peer else {
        r.fail(G, "connect", "no client connected");
        return Ok(r);
    };
    let first = z.first.clone().unwrap_or_default();
    let opensec = oss_net::opensec::is_client_hello(&first);
    r.check(
        G,
        "connect-request",
        opensec || (first.len() == 8 && first[..2] == [0, 1] && first[6..] == [1, 0]),
        format!("first datagram {first:02x?} is not 00 01 <key> 01 00 or an OpenSec hello"),
    );
    let deadline = Instant::now() + opts.timeout;
    while z.server.connection(&peer).is_none_or(|c| !c.is_connected()) && Instant::now() < deadline
    {
        z.pump(Duration::from_millis(50), |_| false);
    }
    if z.server.connection(&peer).is_none_or(|c| !c.is_connected()) {
        r.fail(G, "handshake", "the client did not complete the handshake");
        return Ok(r);
    }
    r.pass(
        G,
        if opensec {
            "handshake (OpenSec)"
        } else {
            "handshake (VIE)"
        },
    );

    // Login.
    let got_login = z.wait_for(opts.timeout, |p| {
        matches!(p, C2SPacket::Login(_) | C2SPacket::ContLogin(_))
    });
    let login = z.packets.iter().find_map(|p| match p {
        C2SPacket::Login(l) => Some(l.clone()),
        C2SPacket::ContLogin(l) => Some(l.0.clone()),
        _ => None,
    });
    let stats = z
        .server
        .connection(&peer)
        .map(|c| c.stats())
        .unwrap_or_default();
    r.check(
        G,
        "login",
        got_login,
        format!(
            "no C2S 0x09/0x24 login ({} datagrams received from the client, {} sent to it, {} retransmitted, {} dropped as invalid)",
            stats.datagrams_received, stats.datagrams_sent, stats.retransmits, stats.dropped
        ),
    );
    let Some(login) = login else {
        return Ok(r);
    };
    r.check(
        G,
        "login-name",
        !login.name.as_bytes().is_empty(),
        "empty name",
    );
    z.send(s2c::LoginResponse {
        code: login_code::OK,
        server_version: 134,
        exe_checksum: 0xF142_9CE8,
        code_checksum: 0x281C_C948,
        ..Default::default()
    });
    z.pump(Duration::from_secs(1), |_| false);
    let acked = z
        .server
        .connection(&peer)
        .is_some_and(|c| c.queued_reliable() == 0);
    r.check(
        G,
        "acks",
        acked,
        "the login response was not acknowledged within 1 s",
    );

    // Arena entry.
    let got = z.wait_for(opts.timeout, |p| matches!(p, C2SPacket::GoArena(_)));
    r.check(
        G,
        "go-arena",
        got,
        "no C2S 0x01 arena request after a successful login",
    );
    if !got {
        return Ok(r);
    }
    let settings = reference_settings();
    let map = served_map();
    z.send(s2c::PlayerId {
        pid: 0,
        arena: None,
    });
    if let Some(peer) = z.peer {
        z.server.send(&peer, &settings, true);
    }
    z.send(s2c::PlayerEntering {
        players: vec![PlayerData {
            ship: 8,
            accept_audio: 1,
            name: FixedStr::new(login.name.as_bytes()),
            squad: FixedStr::default(),
            kill_points: 0,
            flag_points: 0,
            pid: 0,
            freq: 0,
            wins: 0,
            losses: 0,
            attached_to: -1,
            flags_carried: 0,
            misc_bits: 0,
        }],
    });
    z.send(MapFilename::Single {
        name: SERVED_MAP.into(),
        checksum: crc32(map),
    });
    z.send(s2c::EnteringArena {});

    // Map download (a client with the map cached may skip it).
    if z.wait_for(opts.timeout, |p| matches!(p, C2SPacket::MapRequest(_))) {
        r.pass(G, "map-request");
        z.send(s2c::MapData {
            name: SERVED_MAP.into(),
            data: miniz_oxide::deflate::compress_to_vec_zlib(map, 9),
        });
        z.pump(Duration::from_secs(2), |_| false);
    } else {
        r.skip(G, "map-request", "no C2S 0x0C (map cached?)");
    }

    // Everything sent so far (the arena burst, packed into clusters, and the
    // map transfer) must be acknowledged.
    let deadline = Instant::now() + Duration::from_secs(3);
    while z
        .server
        .connection(&peer)
        .is_some_and(|c| c.queued_reliable() > 0)
        && Instant::now() < deadline
    {
        z.pump(Duration::from_millis(50), |_| false);
    }
    let left = z
        .server
        .connection(&peer)
        .map_or(0, |c| c.queued_reliable());
    r.check(
        G,
        "arena-acks",
        left == 0,
        format!("{left} reliable packets still unacknowledged after 3 s"),
    );

    // Position updates with valid checksums.
    let got = z.wait_for(opts.timeout, |p| matches!(p, C2SPacket::Position(_)));
    let bad = z
        .packets
        .iter()
        .filter(|p| matches!(p, C2SPacket::Position(x) if !x.checksum_ok()))
        .count();
    r.check(G, "position", got, "no C2S 0x03 position update");
    r.check(
        G,
        "position-checksum",
        bad == 0,
        format!("{bad} position packets with a wrong checksum"),
    );

    // Security checksums.
    let key = opts.security_key;
    z.send(s2c::Security {
        green_seed: 1,
        door_seed: 2,
        timestamp: 0,
        key,
    });
    let got = z.wait_for(opts.timeout, |p| {
        matches!(p, C2SPacket::SecurityResponse(_))
    });
    let resp = z.packets.iter().find_map(|p| match p {
        C2SPacket::SecurityResponse(s) => Some(s.clone()),
        _ => None,
    });
    r.check(
        G,
        "security-response",
        got,
        "no C2S 0x1A after S2C 0x18 with a key",
    );
    if let Some(s) = resp {
        let want = settings_checksum(key, &settings);
        r.check(
            G,
            "security-settings-checksum",
            s.settings_checksum == want,
            format!("expected {want:08x}, got {:08x}", s.settings_checksum),
        );
        let want = vie_exe_checksum(key);
        if opensec {
            r.skip(
                G,
                "security-exe-checksum",
                "OpenSec client (exe checksum is client-defined)",
            );
        } else {
            r.check(
                G,
                "security-exe-checksum",
                s.exe_checksum == want,
                format!(
                    "expected {want:08x} (SubSpace 1.34), got {:08x}",
                    s.exe_checksum
                ),
            );
        }
        let grid = Level::parse(map).map(|l| l.server_tile_grid().0);
        if s.map_checksum == 0 {
            r.skip(
                G,
                "security-map-checksum",
                "the client reported no map checksum",
            );
        } else if let Ok(g) = grid {
            let want = map_checksum(key, |x, y| g.get(x as u32, y as u32));
            r.check(
                G,
                "security-map-checksum",
                s.map_checksum == want,
                format!("expected {want:08x}, got {:08x}", s.map_checksum),
            );
        }
    }

    // Time sync.
    let deadline = Instant::now() + opts.timeout;
    while z
        .server
        .connection(&peer)
        .is_some_and(|c| c.peer_counts().is_none())
        && Instant::now() < deadline
    {
        z.pump(Duration::from_millis(100), |_| false);
    }
    r.check(
        G,
        "time-sync",
        z.server
            .connection(&peer)
            .is_some_and(|c| c.peer_counts().is_some()),
        "no 14-byte 00 05 time sync request",
    );

    // Done: disconnect the client.
    z.server.disconnect(&peer);
    while let Some((to, d)) = z.server.poll_transmit() {
        let _ = z.sock.send_to(&d, to);
    }
    Ok(r)
}

// ---- zone under test: directory registration ----------------------------------------

/// Options for [`check_zone_registration`].
#[derive(Debug, Clone)]
pub struct DirectoryOptions {
    /// How long to wait for the first registration.
    pub wait: Duration,
    /// Also wait for the next registration and check the interval (about 60 s).
    pub repeat: bool,
    /// The zone's actual game port, if known: the registered port must match it.
    pub game_port: Option<u16>,
}

impl Default for DirectoryOptions {
    fn default() -> Self {
        Self {
            wait: Duration::from_secs(120),
            repeat: false,
            game_port: None,
        }
    }
}

/// The next datagram long enough to be a registration (directory ports also
/// receive 4-byte pings), optionally only from `from`.
fn next_registration(
    sock: &UdpSocket,
    until: Instant,
    from: Option<std::net::IpAddr>,
) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
    let mut buf = [0u8; 2048];
    while Instant::now() < until {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) if n >= 94 && from.is_none_or(|ip| ip == src.ip()) => {
                return Ok(Some((buf[..n].to_vec(), src)));
            }
            Ok(_) => {}
            // Nothing has arrived yet: a timeout, a Windows ICMP-driven
            // `ConnectionReset` for an earlier send, or OS error 997 for a read
            // still in progress. Keep waiting until `until`.
            Err(e) if oss_net::would_block(&e) || e.kind() == io::ErrorKind::ConnectionReset => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Acts as a directory server on `sock` and checks the first zone registration
/// that arrives against the rules directory servers apply, then pings the zone
/// on its game port + 1.
pub fn check_zone_registration(sock: UdpSocket, opts: &DirectoryOptions) -> io::Result<Report> {
    const G: &str = "directory";
    let mut r = Report::default();
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let Some((pkt, src)) = next_registration(&sock, Instant::now() + opts.wait, None)? else {
        r.fail(G, "registration", "no registration datagram arrived");
        return Ok(r);
    };
    r.pass(G, "registration");
    let Ok(u) = oss_proto::directory::ZoneUpdate::decode(&pkt) else {
        r.fail(
            G,
            "decodes",
            format!("{} bytes do not decode as a zone registration", pkt.len()),
        );
        return Ok(r);
    };
    let printable = |b: &[u8]| b.iter().all(|&c| (0x20..0x7F).contains(&c));
    r.check(
        G,
        "ip-zero",
        u.ip == 0,
        format!("ip field is {:#010x}; it must be 0", u.ip),
    );
    r.check(
        G,
        "version-134",
        u.version == 134,
        format!("version {}; directories expect 134", u.version),
    );
    r.check(
        G,
        "score-keeping",
        u.score_keeping <= 1,
        format!("score keeping {}; must be 0 or 1", u.score_keeping),
    );
    r.check(
        G,
        "name",
        pkt[14..46].contains(&0) && printable(u.name.as_bytes()) && !u.name.as_bytes().is_empty(),
        "the 32-byte name must be printable, non-empty and NUL-terminated",
    );
    // Directories use only the first 16 bytes of the password field.
    r.check(
        G,
        "password-length",
        pkt[61..94].iter().all(|&b| b == 0),
        "password longer than 15 characters: directory servers reject it",
    );
    r.check(
        G,
        "description",
        pkt.len() > 94 && pkt.last() == Some(&0) && pkt.len() <= 480,
        format!(
            "description must end with a NUL and the datagram stay within 480 bytes ({} bytes)",
            pkt.len()
        ),
    );

    match opts.game_port {
        Some(p) => r.check(
            G,
            "registered-port",
            u.port == p,
            format!(
                "registered game port {} but the zone listens on {p}",
                u.port
            ),
        ),
        None => r.skip(
            G,
            "registered-port",
            format!(
                "registered game port {}; pass --zone to check it is the real one",
                u.port
            ),
        ),
    }

    // Directories ping zones on the registered game port + 1.
    let mut target = src;
    target.set_port(u.port.wrapping_add(1));
    let ping = UdpSocket::bind(if src.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
    ping.set_read_timeout(Some(Duration::from_millis(250)))?;
    let token = seed().to_le_bytes();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut answered = false;
    let mut buf = [0u8; 64];
    while !answered && Instant::now() < deadline {
        ping.send_to(&token, target)?;
        while let Ok((n, from)) = ping.recv_from(&mut buf) {
            answered |= from == target && n == 8 && buf[4..8] == token;
        }
    }
    if answered {
        // Name the address: if the registered port is wrong, another program
        // may be the one answering.
        r.pass(G, format!("ping-reachable ({target})"));
    } else {
        r.fail(
            G,
            "ping-reachable",
            format!("no ping answer on {target} (the registered game port + 1)"),
        );
    }

    if opts.repeat {
        let start = Instant::now();
        match next_registration(&sock, start + Duration::from_secs(90), Some(src.ip()))? {
            Some(_) => {
                let secs = start.elapsed().as_secs();
                r.check(
                    G,
                    "repeat-interval",
                    (40..=80).contains(&secs),
                    format!("next registration after {secs} s; expected about 60"),
                );
            }
            None => r.fail(G, "repeat-interval", "no second registration within 90 s"),
        }
    } else {
        r.skip(
            G,
            "repeat-interval",
            "not requested (--repeat waits for the next registration, about a minute)",
        );
    }
    Ok(r)
}

// ---- zone under test: SSC billing ----------------------------------------------------

/// Options for [`check_zone_billing`].
#[derive(Debug, Clone)]
pub struct BillerOptions {
    /// How long to wait for the zone to connect.
    pub wait: Duration,
    /// How long to wait for each later step.
    pub timeout: Duration,
    /// The zone's game address. When set, the suite also logs a player in and
    /// out through the zone and checks that the zone relays both to the biller.
    pub zone: Option<SocketAddr>,
}

impl Default for BillerOptions {
    fn default() -> Self {
        Self {
            wait: Duration::from_secs(120),
            timeout: Duration::from_secs(10),
            zone: None,
        }
    }
}

/// The suite's biller side: one zone connection.
struct Biller {
    sock: UdpSocket,
    server: Server<SocketAddr>,
    start: Instant,
    zone: Option<SocketAddr>,
    packets: Vec<oss_proto::billing::ServerToBiller>,
    gone: bool,
}

impl Biller {
    fn pump(&mut self) {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = self.sock.recv_from(&mut buf) {
            self.zone.get_or_insert(from);
            if Some(from) == self.zone {
                self.server.handle_datagram(ms(self.start), from, &buf[..n]);
            }
        }
        self.server.tick(ms(self.start));
        while let Some((to, d)) = self.server.poll_transmit() {
            let _ = self.sock.send_to(&d, to);
            self.server.recycle(d);
        }
        while let Some((_, e)) = self.server.poll_event() {
            match e {
                Event::Packet(p) => {
                    if let Ok(pk) = oss_proto::billing::ServerToBiller::decode(&p) {
                        self.packets.push(pk);
                    }
                    self.server.recycle(p);
                }
                Event::Disconnected(_) => self.gone = true,
                _ => {}
            }
        }
    }

    fn send(&mut self, p: oss_proto::billing::BillerToServer) {
        if let Some(z) = self.zone {
            self.server.send(&z, &p.to_bytes(), true);
        }
    }

    fn find<T>(&self, f: impl Fn(&oss_proto::billing::ServerToBiller) -> Option<T>) -> Option<T> {
        self.packets.iter().find_map(f)
    }
}

/// Acts as an SSC billing server on `sock` and checks the zone that connects:
/// the connect packet, then (with [`BillerOptions::zone`]) a player's login and
/// logoff relayed through the zone.
pub fn check_zone_billing(sock: UdpSocket, opts: &BillerOptions) -> io::Result<Report> {
    use oss_proto::billing::{
        BillerLogin, BillerToServer, PlayerScore, ServerToBiller, login_result,
    };
    const G: &str = "billing";
    let mut r = Report::default();
    sock.set_read_timeout(Some(Duration::from_millis(5)))?;
    let mut server = Server::new(Config::server());
    // Zones connect to billers without encryption.
    server.add_acceptor(Box::new(oss_net::NullAcceptor));
    let mut b = Biller {
        sock,
        server,
        start: Instant::now(),
        zone: None,
        packets: Vec::new(),
        gone: false,
    };
    let wait_until = |b: &mut Biller, until: Instant, done: &dyn Fn(&Biller) -> bool| {
        while Instant::now() < until && !done(b) && !b.gone {
            b.pump();
        }
        done(b)
    };

    let connected = wait_until(&mut b, Instant::now() + opts.wait, &|b| {
        b.zone
            .is_some_and(|z| b.server.connection(&z).is_some_and(|c| c.is_connected()))
    });
    if !connected {
        r.fail(G, "connect", "no zone connected to the biller");
        return Ok(r);
    }
    r.pass(G, "connect");

    // ServerConnect first; the biller never acknowledges it.
    wait_until(&mut b, Instant::now() + opts.timeout, &|b| {
        !b.packets.is_empty()
    });
    match b.packets.first() {
        Some(ServerToBiller::ServerConnect { name, port, .. }) => {
            r.pass(G, "server-connect");
            r.check(
                G,
                "server-connect-fields",
                !name.as_bytes().is_empty() && *port != 0,
                "the server name must be set and the port non-zero",
            );
        }
        Some(other) => r.fail(
            G,
            "server-connect",
            format!("the first packet was {other:?}, not S2B 0x02 server connect"),
        ),
        None => {
            r.fail(
                G,
                "server-connect",
                "the zone sent nothing after connecting",
            );
            return Ok(r);
        }
    }

    // The reference zone assumes it is logged in after 5 s without an answer
    // and then announces its capabilities; that announcement is optional.
    let caps = wait_until(&mut b, Instant::now() + Duration::from_secs(8), &|b| {
        b.find(|p| matches!(p, ServerToBiller::ServerCapabilities { .. }).then_some(()))
            .is_some()
    });
    if caps {
        r.pass(G, "capabilities");
    } else {
        r.skip(
            G,
            "capabilities",
            "no S2B 0x15 (optional: multicast channel chat)",
        );
    }

    let Some(zone_addr) = opts.zone else {
        r.skip(
            G,
            "user-login",
            "no --zone given, so no player was logged in",
        );
        return Ok(r);
    };

    // A player logs in to the zone; the zone must ask the biller.
    let csock = UdpSocket::bind(if zone_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    csock.connect(zone_addr)?;
    csock.set_read_timeout(Some(Duration::from_millis(5)))?;
    let mut c = Session {
        sock: csock,
        conn: Connection::client(
            Config::client(),
            Box::new(VieClientHandshake::new(seed())),
            0,
        ),
        start: Instant::now(),
        packets: Vec::new(),
        closed: false,
    };
    let name = format!("biller-{:04x}", seed() & 0xFFFF);
    let deadline = Instant::now() + opts.timeout;
    while !c.conn.is_connected() && Instant::now() < deadline && !c.closed {
        c.pump(Duration::from_millis(20), |_| false);
        b.pump();
    }
    if !c.conn.is_connected() {
        r.fail(
            G,
            "user-login",
            format!("could not connect to the zone at {zone_addr}"),
        );
        return Ok(r);
    }
    c.send(Login {
        name: FixedStr::new(name.as_bytes()),
        password: FixedStr::new(b"conformance"),
        machine_id: seed(),
        ..Login::default()
    });
    let deadline = Instant::now() + opts.timeout;
    let mut login = None;
    while login.is_none() && Instant::now() < deadline {
        c.pump(Duration::from_millis(20), |_| false);
        b.pump();
        login = b.find(|p| match p {
            ServerToBiller::UserLogin(l)
                if l.name.as_bytes().eq_ignore_ascii_case(name.as_bytes()) =>
            {
                Some(l.clone())
            }
            _ => None,
        });
    }
    let Some(login) = login else {
        r.fail(
            G,
            "user-login",
            "the zone did not send S2B 0x04 for a player logging in",
        );
        return Ok(r);
    };
    r.pass(G, "user-login");
    r.check(
        G,
        "user-login-client-data",
        login.extra.is_empty(),
        format!(
            "a SubSpace (VIE) client's login carries no client data (86 bytes); got {} extra bytes",
            login.extra.len()
        ),
    );

    // The biller accepts; the zone must tell the player.
    b.send(BillerToServer::UserLogin(BillerLogin {
        result: login_result::OK,
        connection_id: login.connection_id,
        name: FixedStr::new(name.as_bytes()),
        squad: FixedStr::default(),
        user_id: 1,
        score: Some(PlayerScore::default()),
        ..BillerLogin::default()
    }));
    let deadline = Instant::now() + opts.timeout;
    let mut code = None;
    while code.is_none() && Instant::now() < deadline {
        c.pump(Duration::from_millis(20), |_| false);
        b.pump();
        code = c.packets.iter().find_map(|(_, p)| match p {
            S2CPacket::LoginResponse(l) => Some(l.code),
            _ => None,
        });
    }
    r.check(
        G,
        "user-login-relayed",
        matches!(code, Some(login_code::OK | login_code::NO_SCORES)),
        format!("after the biller accepted the login, the player got login code {code:?}"),
    );

    // The player leaves; the zone reports it with the same connection id.
    c.conn.disconnect();
    let deadline = Instant::now() + opts.timeout;
    let mut logoff = None;
    while logoff.is_none() && Instant::now() < deadline {
        c.pump(Duration::from_millis(20), |_| false);
        b.pump();
        logoff = b.find(|p| match p {
            ServerToBiller::UserLogoff { connection_id, .. } => Some(*connection_id),
            _ => None,
        });
    }
    match logoff {
        Some(id) => r.check(
            G,
            "user-logoff",
            id == login.connection_id,
            format!(
                "logoff for connection {id}, login was {}",
                login.connection_id
            ),
        ),
        None => r.fail(
            G,
            "user-logoff",
            "no S2B 0x05 after the player disconnected",
        ),
    }
    Ok(r)
}
