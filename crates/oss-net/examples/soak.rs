//! Load and soak harness for the server side of `oss-net`.
//!
//! Simulates many players connected to one [`Server`] over a lossy, jittery
//! network, with the traffic of a busy arena: position updates every 100 ms
//! relayed to nearby players, reliable chat broadcast to everyone, and players
//! leaving (politely or by vanishing) and joining. Everything runs in one thread
//! on a simulated clock, so runs are reproducible: the same arguments give the
//! same packet counts on any machine, and only the timings differ.
//!
//! Only the server's work is timed and its heap usage tracked; the simulated
//! clients and network are free. `server CPU` is the server's time divided by
//! the simulated duration: the fraction of one core a real server would need.
//!
//! ```sh
//! cargo run --release -p oss-net --example soak -- --peers 500 --seconds 60
//! cargo run --release -p oss-net --example soak -- --help
//! ```
//!
//! See `docs/performance.md` for the scenario, what is measured and results.

// The heap tracker is a global allocator wrapper, which needs `unsafe`; it only
// forwards to `System` and updates counters.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::process::ExitCode;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use oss_net::opensec::{Entropy, OpenSecAcceptor, OpenSecClientHandshake, ServerKey};
use oss_net::{
    Config, Connection, Event, Handshake, NullAcceptor, Priority, SendFlags, Server, VieAcceptor,
    VieClientHandshake,
};

// ---- heap tracking --------------------------------------------------------------

thread_local! {
    static IN_SERVER: Cell<bool> = const { Cell::new(false) };
}
static SERVER_ALLOCS: AtomicU64 = AtomicU64::new(0);
static SERVER_LIVE: AtomicI64 = AtomicI64::new(0);
static TOTAL_LIVE: AtomicI64 = AtomicI64::new(0);
static TOTAL_PEAK: AtomicI64 = AtomicI64::new(0);

fn in_server() -> bool {
    IN_SERVER.try_with(Cell::get).unwrap_or(false)
}

fn account(delta: i64, is_alloc: bool) {
    let live = TOTAL_LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
    TOTAL_PEAK.fetch_max(live, Ordering::Relaxed);
    if in_server() {
        SERVER_LIVE.fetch_add(delta, Ordering::Relaxed);
        if is_alloc {
            SERVER_ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct Tracking;

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        account(layout.size() as i64, true);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        account(-(layout.size() as i64), false);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        account(new_size as i64 - layout.size() as i64, true);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Tracking = Tracking;

/// Runs an oss-net call with its heap use attributed to the server.
fn srv<T>(f: impl FnOnce() -> T) -> T {
    IN_SERVER.with(|c| c.set(true));
    let r = f();
    IN_SERVER.with(|c| c.set(false));
    r
}

/// Like [`srv`], and also adds the call's time to `clock`.
fn server_work<T>(clock: &mut Duration, f: impl FnOnce() -> T) -> T {
    let t = Instant::now();
    let r = srv(f);
    *clock += t.elapsed();
    r
}

// ---- options --------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Opts {
    peers: usize,
    seconds: u64,
    warmup: u64,
    loss: f64,
    latency_ms: u64,
    jitter_ms: u64,
    position_ms: u64,
    fanout: usize,
    chat_interval_ms: u64,
    churn_ms: u64,
    cipher: String,
    seed: u64,
    json: bool,
    max_cpu: Option<f64>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            peers: 500,
            seconds: 60,
            warmup: 5,
            loss: 2.0,
            latency_ms: 40,
            jitter_ms: 10,
            position_ms: 100,
            fanout: 30,
            chat_interval_ms: 60_000,
            churn_ms: 1_000,
            cipher: "vie".into(),
            seed: 1,
            json: false,
            max_cpu: None,
        }
    }
}

const HELP: &str = "\
soak: load and soak test for oss-net's Server

options (defaults in brackets):
  --peers N            simulated players [500]
  --seconds N          measured duration, simulated seconds [60]
  --warmup N           unmeasured seconds before that [5]
  --loss PCT           datagram loss each way, percent [2]
  --latency MS         one-way latency [40]
  --jitter MS          extra random delay, 0..MS (reorders datagrams) [10]
  --position-ms MS     position update interval per player [100]
  --fanout N           players each position is relayed to [30]
  --chat-interval MS   reliable chat per player, broadcast to all; 0 = none [60000]
  --churn-ms MS        one player leaves and a new one joins every MS; 0 = none [1000]
  --cipher C           none | vie | opensec [vie]
  --seed N             random seed [1]
  --json               print one JSON line instead of the table
  --max-cpu PCT        exit 1 if server CPU exceeds PCT of a core (for CI)
";

fn parse() -> Result<Opts, String> {
    let mut o = Opts::default();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().ok_or(format!("{a} needs a value"));
        let num = |v: String| v.parse::<u64>().map_err(|e| format!("{a}: {e}"));
        let flt = |v: String| v.parse::<f64>().map_err(|e| format!("{a}: {e}"));
        match a.as_str() {
            "--peers" => o.peers = num(val()?)? as usize,
            "--seconds" => o.seconds = num(val()?)?,
            "--warmup" => o.warmup = num(val()?)?,
            "--loss" => o.loss = flt(val()?)?,
            "--latency" => o.latency_ms = num(val()?)?,
            "--jitter" => o.jitter_ms = num(val()?)?,
            "--position-ms" => o.position_ms = num(val()?)?.max(10),
            "--fanout" => o.fanout = num(val()?)? as usize,
            "--chat-interval" => o.chat_interval_ms = num(val()?)?,
            "--churn-ms" => o.churn_ms = num(val()?)?,
            "--cipher" => o.cipher = val()?,
            "--seed" => o.seed = num(val()?)?,
            "--json" => o.json = true,
            "--max-cpu" => o.max_cpu = Some(flt(val()?)?),
            "-h" | "--help" => return Err(HELP.into()),
            other => return Err(format!("unknown option {other}\n\n{HELP}")),
        }
    }
    if !["none", "vie", "opensec"].contains(&o.cipher.as_str()) {
        return Err(format!("unknown cipher {}", o.cipher));
    }
    Ok(o)
}

// ---- simulation -----------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    fn chance(&mut self, pct: f64) -> bool {
        (self.next() % 1_000_000) as f64 / 10_000.0 < pct
    }
}

fn entropy(seed: u64) -> Entropy {
    let s = Mutex::new(Rng(seed | 1));
    Arc::new(move |b: &mut [u8]| {
        let mut r = s.lock().unwrap();
        for v in b.iter_mut() {
            *v = r.next() as u8;
        }
    })
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Dest {
    Server(u32),
    Client(u32),
}

/// A datagram on the simulated network: delivery time, destination, per-link
/// sequence number, bytes.
type InFlight = (u64, Dest, u64, Vec<u8>);

/// One simulated player.
struct Peer {
    conn: Connection,
    /// Next time to send a position update.
    next_position: u64,
    next_chat: u64,
    /// Highest chat id received (they must arrive in increasing order).
    last_chat: Option<u64>,
    chats_received: u64,
    positions_received: u64,
    /// Present for the whole measured period (for the delivery check).
    stable: bool,
    joined_at: u64,
}

const POSITION: u8 = 0x03;
const S2C_POSITION: u8 = 0x28;
const CHAT: u8 = 0x06;

#[derive(Default)]
struct Totals {
    server_time: Duration,
    datagrams_in: u64,
    datagrams_out: u64,
    bytes_in: u64,
    bytes_out: u64,
    packets_in: u64,
    packets_out: u64,
    positions_relayed: u64,
    chats_sent: u64,
    joins: u64,
    leaves: u64,
    timeouts: u64,
    server_allocs: u64,
}

fn main() -> ExitCode {
    let o = match parse() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let wall = Instant::now();
    let mut rng = Rng(o.seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);

    let opensec_key = ServerKey::generate(&entropy(o.seed ^ 0x5EC));
    let mut server: Server<u32> = Server::new(Config::server());
    match o.cipher.as_str() {
        "none" => server.add_acceptor(Box::new(NullAcceptor)),
        "vie" => server.add_acceptor(Box::new(VieAcceptor::default())),
        _ => server.add_acceptor(Box::new(OpenSecAcceptor::new(
            Some(opensec_key.clone()),
            entropy(o.seed ^ 0xACC),
        ))),
    }

    let new_client = |rng: &mut Rng, now: u64| -> Connection {
        let hs: Box<dyn Handshake> = match o.cipher.as_str() {
            "opensec" => Box::new(OpenSecClientHandshake::new(
                &entropy(rng.next()),
                Some(opensec_key.public()),
            )),
            // With the null acceptor the server echoes the key, which selects no
            // encryption; with VIE it answers with the server key.
            _ => Box::new(VieClientHandshake::new(rng.next() as u32)),
        };
        Connection::client(Config::client(), hs, now)
    };

    let mut peers: BTreeMap<u32, Peer> = BTreeMap::new();
    let mut next_addr = 1u32;
    // Each direction of each player's link has its own random stream and
    // sequence numbers, so loss and jitter do not depend on the order in which
    // the server happens to emit datagrams for different players: runs with the
    // same arguments produce the same traffic.
    let mut net: BinaryHeap<Reverse<InFlight>> = BinaryHeap::new();
    let mut links: BTreeMap<(bool, u32), (Rng, u64)> = BTreeMap::new();
    let seed = o.seed;
    let mut send_net = |_: &mut Rng, net: &mut BinaryHeap<_>, now: u64, dest: Dest, d: Vec<u8>| {
        let key = match dest {
            Dest::Server(a) => (true, a),
            Dest::Client(a) => (false, a),
        };
        let (rng, seq) = links.entry(key).or_insert_with(|| {
            let mix =
                (u64::from(key.1) << 1 | u64::from(key.0)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            (Rng((seed ^ mix) | 1), 0)
        });
        if rng.chance(o.loss) {
            return;
        }
        let at = now + o.latency_ms + rng.below(o.jitter_ms + 1);
        *seq += 1;
        net.push(Reverse((at, dest, *seq, d)));
    };

    let measure_from = o.warmup * 1_000;
    let end = measure_from + o.seconds * 1_000;
    // After `end`, stop new traffic and let reliable data drain.
    let drain_until = end + 10_000;
    let mut t = Totals::default();
    let mut chat_id = 0u64;
    // Server-side record of chats sent to each address.
    let mut chats_to: BTreeMap<u32, u64> = BTreeMap::new();
    let mut connected: Vec<u32> = Vec::new();
    let mut last_churn = 0u64;
    let mut heap_at_start = 0i64;
    let mut allocs_at_start = 0u64;
    let mut pos_pkt = [0u8; 22];
    pos_pkt[0] = POSITION;
    let mut s2c_pos = [0u8; 16];
    let mut outbox: Vec<(u32, Vec<u8>)> = Vec::with_capacity(4096);
    let mut reasons: BTreeMap<String, u64> = BTreeMap::new();
    s2c_pos[0] = S2C_POSITION;

    // Stagger joins over the first two seconds.
    let join_gap = (2_000 / o.peers.max(1) as u64).max(1);
    let mut to_join = o.peers;

    let mut now = 0u64;
    while now < drain_until {
        now += 10;
        let measuring = now > measure_from && now <= end;
        if now == measure_from + 10 {
            t = Totals::default();
            heap_at_start = SERVER_LIVE.load(Ordering::Relaxed);
            allocs_at_start = SERVER_ALLOCS.load(Ordering::Relaxed);
            for p in peers.values_mut() {
                p.stable = p.conn.is_connected();
                p.chats_received = 0;
                p.last_chat = None;
            }
            chats_to.clear();
        }

        // Joins and churn.
        while to_join > 0 && now >= (o.peers - to_join) as u64 * join_gap {
            to_join -= 1;
            let addr = next_addr;
            next_addr += 1;
            peers.insert(
                addr,
                Peer {
                    conn: new_client(&mut rng, now),
                    next_position: now + rng.below(o.position_ms),
                    next_chat: now + rng.below(o.chat_interval_ms.max(1)),
                    last_chat: None,
                    chats_received: 0,
                    positions_received: 0,
                    stable: false,
                    joined_at: now,
                },
            );
            if measuring {
                t.joins += 1;
            }
        }
        if o.churn_ms > 0 && now <= end && now >= 3_000 && now - last_churn >= o.churn_ms {
            last_churn = now;
            let ids: Vec<u32> = peers.keys().copied().collect();
            if let Some(&victim) = ids.get(rng.below(ids.len() as u64) as usize) {
                let mut p = peers.remove(&victim).unwrap();
                // Half leave politely; half vanish and must time out.
                if rng.below(2) == 0 {
                    p.conn.disconnect();
                    while let Some(d) = p.conn.poll_transmit() {
                        send_net(&mut rng, &mut net, now, Dest::Server(victim), d);
                    }
                }
                if measuring {
                    t.leaves += 1;
                }
                to_join += 1;
            }
        }

        // Deliver due datagrams.
        while let Some(Reverse((at, ..))) = net.peek() {
            if *at > now {
                break;
            }
            let Reverse((_, dest, _, d)) = net.pop().unwrap();
            match dest {
                Dest::Server(addr) => {
                    if measuring {
                        t.datagrams_in += 1;
                        t.bytes_in += d.len() as u64;
                    }
                    server_work(&mut t.server_time, || server.handle_datagram(now, addr, &d));
                }
                Dest::Client(addr) => {
                    if let Some(p) = peers.get_mut(&addr) {
                        p.conn.handle_datagram(now, &d);
                    }
                }
            }
        }

        // Clients: traffic and events.
        let traffic = now <= end;
        for (&addr, p) in peers.iter_mut() {
            p.conn.tick(now);
            if p.conn.is_connected() && traffic {
                if now >= p.next_position {
                    p.next_position += o.position_ms;
                    pos_pkt[1..5].copy_from_slice(&(now as u32).to_le_bytes());
                    p.conn.send(&pos_pkt, false);
                }
                if o.chat_interval_ms > 0 && now >= p.next_chat {
                    p.next_chat += o.chat_interval_ms;
                    p.conn.send(&[CHAT, 2, 0, 0xFF, 0xFF, b'h', b'i', 0], true);
                }
            }
            while let Some(e) = p.conn.poll_event() {
                if let Event::Packet(pk) = e {
                    match pk[0] {
                        S2C_POSITION => p.positions_received += 1,
                        CHAT if pk.len() >= 9 => {
                            let id = u64::from_le_bytes(pk[1..9].try_into().unwrap());
                            assert!(
                                p.last_chat.is_none_or(|l| id > l),
                                "chat out of order for {addr}"
                            );
                            p.last_chat = Some(id);
                            p.chats_received += 1;
                        }
                        _ => {}
                    }
                    p.conn.recycle(pk);
                }
            }
            while let Some(d) = p.conn.poll_transmit() {
                send_net(&mut rng, &mut net, now, Dest::Server(addr), d.clone());
                p.conn.recycle(d);
            }
        }
        peers.retain(|_, p| !p.conn.is_closed());

        // Server: tick, application logic (relay positions, broadcast chat),
        // transmit. The whole step is timed (the relay logic is trivial next to
        // the transport); only oss-net calls count towards the server's heap.
        let step = Instant::now();
        srv(|| server.tick(now));
        while let Some((from, e)) = srv(|| server.poll_event()) {
            match e {
                Event::Connected => {
                    // Sorted, so relay targets do not depend on event order.
                    let i = connected.partition_point(|&a| a < from);
                    connected.insert(i, from);
                }
                Event::Disconnected(reason) => {
                    connected.retain(|&a| a != from);
                    if measuring || now > end {
                        *reasons.entry(format!("{reason:?}")).or_insert(0u64) += 1;
                    }
                    if measuring && matches!(reason, oss_net::DisconnectReason::Timeout) {
                        t.timeouts += 1;
                    }
                }
                Event::Packet(pk) => {
                    if measuring {
                        t.packets_in += 1;
                    }
                    match pk[0] {
                        POSITION if !connected.is_empty() => {
                            let i = connected.iter().position(|&a| a == from).unwrap_or(0);
                            s2c_pos[1..5].copy_from_slice(&pk[1..5]);
                            s2c_pos[5] = from as u8;
                            let n = o.fanout.min(connected.len() - 1);
                            let flags = SendFlags {
                                reliable: false,
                                priority: Priority::Normal,
                                droppable: true,
                            };
                            for k in 1..=n {
                                let to = connected[(i + k) % connected.len()];
                                srv(|| server.send_with(&to, &s2c_pos, flags));
                            }
                            if measuring {
                                t.positions_relayed += n as u64;
                                t.packets_out += n as u64;
                            }
                        }
                        CHAT => {
                            chat_id += 1;
                            let mut msg = [0u8; 24];
                            msg[0] = CHAT;
                            msg[1..9].copy_from_slice(&chat_id.to_le_bytes());
                            for &to in &connected {
                                if srv(|| server.send(&to, &msg, true)) {
                                    *chats_to.entry(to).or_default() += 1;
                                }
                            }
                            if measuring {
                                t.chats_sent += connected.len() as u64;
                                t.packets_out += connected.len() as u64;
                            }
                        }
                        _ => {}
                    }
                    srv(|| server.recycle(pk));
                }
                _ => {}
            }
        }
        while let Some((to, d)) = srv(|| server.poll_transmit()) {
            if measuring {
                t.datagrams_out += 1;
                t.bytes_out += d.len() as u64;
            }
            outbox.push((to, d));
        }
        t.server_time += step.elapsed();
        for (to, d) in outbox.drain(..) {
            send_net(&mut rng, &mut net, now, Dest::Client(to), d.clone());
            let r = Instant::now();
            srv(|| server.recycle(d));
            t.server_time += r.elapsed();
        }
        if now == end {
            t.server_allocs = SERVER_ALLOCS.load(Ordering::Relaxed) - allocs_at_start;
        }
    }

    // Delivery check: players present for the whole run got every chat the
    // server queued for them, in order.
    // Chats still queued on the server when the drain period ended (the link
    // was saturated) are reported separately from chats that were lost.
    let mut stable = 0;
    let mut missing = 0u64;
    let mut backlog = 0u64;
    let mut dropped_stable = 0u64;
    for (addr, p) in &peers {
        if p.stable && p.joined_at <= measure_from {
            stable += 1;
            let sent = chats_to.get(addr).copied().unwrap_or(0);
            let short = sent.saturating_sub(p.chats_received);
            let Some(conn) = server.connection(addr) else {
                // The server dropped this player (see the disconnect reasons);
                // its client has not noticed yet.
                dropped_stable += 1;
                continue;
            };
            let queued = conn.queued_reliable() as u64;
            let queued = queued.min(short);
            backlog += queued;
            missing += short - queued;
        }
    }

    let secs = o.seconds as f64;
    let cpu = t.server_time.as_secs_f64() / secs * 100.0;
    let pkts = (t.packets_in + t.packets_out).max(1);
    let per_packet_ns = t.server_time.as_nanos() as f64 / pkts as f64;
    let server_heap = SERVER_LIVE.load(Ordering::Relaxed);
    let per_peer = server_heap as f64 / server.len().max(1) as f64;
    let ok = missing == 0 && o.max_cpu.is_none_or(|m| cpu <= m);

    if o.json {
        println!(
            "{{\"peers\":{},\"seconds\":{},\"cipher\":\"{}\",\"loss\":{},\"latency_ms\":{},\"jitter_ms\":{},\"fanout\":{},\"position_ms\":{},\"chat_interval_ms\":{},\"churn_ms\":{},\"seed\":{},\
\"server_cpu_pct\":{:.2},\"server_ns_per_packet\":{:.0},\"packets_in_per_s\":{:.0},\"packets_out_per_s\":{:.0},\"datagrams_in_per_s\":{:.0},\"datagrams_out_per_s\":{:.0},\"kbit_in\":{:.0},\"kbit_out\":{:.0},\
\"server_heap_bytes\":{},\"heap_per_peer\":{:.0},\"server_heap_growth\":{},\"server_allocs_per_s\":{:.1},\"joins\":{},\"leaves\":{},\"timeouts\":{},\"stable_peers\":{},\"chats_missing\":{},\"chats_still_queued\":{},\"stable_dropped_by_server\":{},\"server_disconnects\":{{{}}},\"wall_s\":{:.1}}}",
            o.peers,
            o.seconds,
            o.cipher,
            o.loss,
            o.latency_ms,
            o.jitter_ms,
            o.fanout,
            o.position_ms,
            o.chat_interval_ms,
            o.churn_ms,
            o.seed,
            cpu,
            per_packet_ns,
            t.packets_in as f64 / secs,
            t.packets_out as f64 / secs,
            t.datagrams_in as f64 / secs,
            t.datagrams_out as f64 / secs,
            t.bytes_in as f64 * 8.0 / 1000.0 / secs,
            t.bytes_out as f64 * 8.0 / 1000.0 / secs,
            server_heap,
            per_peer,
            server_heap - heap_at_start,
            t.server_allocs as f64 / secs,
            t.joins,
            t.leaves,
            t.timeouts,
            stable,
            missing,
            backlog,
            dropped_stable,
            reasons
                .iter()
                .map(|(k, v)| format!("\"{k}\":{v}"))
                .collect::<Vec<_>>()
                .join(","),
            wall.elapsed().as_secs_f64(),
        );
    } else {
        println!(
            "oss-net soak: {} peers, {} s measured after {} s warm-up, cipher {}, seed {}",
            o.peers, o.seconds, o.warmup, o.cipher, o.seed
        );
        println!(
            "network: {}% loss each way, {} ms latency + 0..{} ms jitter",
            o.loss, o.latency_ms, o.jitter_ms
        );
        println!(
            "traffic: position every {} ms relayed to {} players; chat every {} ms per player to all; churn every {} ms",
            o.position_ms, o.fanout, o.chat_interval_ms, o.churn_ms
        );
        println!();
        println!("server CPU            {cpu:>10.2} % of one core");
        println!(
            "cost per game packet  {per_packet_ns:>10.0} ns   (in + out, all transport work included)"
        );
        println!(
            "game packets in/out   {:>10.0} / {:.0} per s",
            t.packets_in as f64 / secs,
            t.packets_out as f64 / secs
        );
        println!(
            "datagrams in/out      {:>10.0} / {:.0} per s",
            t.datagrams_in as f64 / secs,
            t.datagrams_out as f64 / secs
        );
        println!(
            "bandwidth in/out      {:>10.0} / {:.0} kbit/s",
            t.bytes_in as f64 * 8.0 / 1000.0 / secs,
            t.bytes_out as f64 * 8.0 / 1000.0 / secs
        );
        println!(
            "server heap           {:>10} bytes  ({per_peer:.0} per connection, {} grown during the run)",
            server_heap,
            server_heap - heap_at_start
        );
        println!(
            "server allocations    {:>10.1} per s",
            t.server_allocs as f64 / secs
        );
        println!(
            "churn                 {:>10} joins, {} leaves, {} timed out",
            t.joins, t.leaves, t.timeouts
        );
        println!(
            "reliable delivery     {:>10} stable players, {} chats missing, {} still queued at the end",
            stable, missing, backlog
        );
        println!(
            "process heap peak     {:>10} bytes (server, clients and network together)",
            TOTAL_PEAK.load(Ordering::Relaxed)
        );
        println!(
            "wall time             {:>10.1} s",
            wall.elapsed().as_secs_f64()
        );
    }
    if !o.json {
        println!(
            "server disconnects    {reasons:?}; {dropped_stable} stable players dropped by the server"
        );
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        eprintln!("FAILED: {missing} chats missing; server CPU {cpu:.2}%");
        ExitCode::FAILURE
    }
}
