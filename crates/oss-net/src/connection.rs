//! The per-peer transport state machine.
//!
//! A [`Connection`] is sans-IO: feed it received datagrams with
//! [`Connection::handle_datagram`], drive its timers with [`Connection::tick`]
//! (every ~10 ms is typical), queue packets with [`Connection::send`] /
//! [`Connection::send_sized`], then drain [`Connection::poll_transmit`] (datagrams
//! to put on the wire, already encrypted) and [`Connection::poll_event`]
//! (connection state and received game packets). Time is a caller-supplied
//! monotonic millisecond counter.

use std::collections::{BTreeMap, VecDeque};

use crate::cipher::{Accept, Cipher, CipherContext, Handshake, Step};

/// Tunables. Defaults interoperate with existing servers and clients.
#[derive(Debug, Clone)]
pub struct Config {
    /// Largest plaintext datagram this side sends (512 keeps old servers happy).
    pub max_send: usize,
    /// Largest datagram accepted (520 is what most clients send at most).
    pub max_recv: usize,
    /// Slice size for big (`00 08/09`) and sized (`00 0A`) transfers.
    pub chunk_size: usize,
    /// Reliable receive window (packets beyond it are dropped unacknowledged).
    pub recv_window: u32,
    /// Reliable packets in flight at once.
    pub send_window: usize,
    /// Transmissions of one reliable packet before giving up on the peer.
    pub max_retries: u32,
    /// Lower bound of the retransmission timeout.
    pub rto_min_ms: u64,
    /// Upper bound of the retransmission timeout.
    pub rto_max_ms: u64,
    /// Disconnect after this long without receiving anything.
    pub timeout_ms: u64,
    /// Largest reassembled big packet.
    pub max_big: usize,
    /// Largest incoming sized transfer accepted.
    pub max_sized: usize,
    /// Refill sized-transfer chunks when fewer than this many reliables are
    /// unacknowledged.
    pub sized_threshold: usize,
    /// Chunks queued per refill.
    pub sized_batch: usize,
    /// Send time-sync requests at this interval (clients); `None` to never
    /// initiate.
    pub sync_interval_ms: Option<u64>,
    /// Disconnect if more than this many packets are queued for sending.
    pub max_queue: usize,
}

impl Config {
    /// Defaults for the client end of a connection (initiates time sync).
    pub fn client() -> Self {
        Self {
            sync_interval_ms: Some(5_000),
            ..Self::server()
        }
    }

    /// Defaults for the server end of a connection.
    pub fn server() -> Self {
        Self {
            max_send: 512,
            max_recv: 520,
            chunk_size: 480,
            recv_window: 32,
            send_window: 24,
            max_retries: 15,
            rto_min_ms: 250,
            rto_max_ms: 2_000,
            timeout_ms: 30_000,
            max_big: 65_536,
            max_sized: 16 << 20,
            sized_threshold: 5,
            sized_batch: 25,
            sync_interval_ms: None,
            max_queue: 500,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::client()
    }
}

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    /// [`Connection::disconnect`] was called.
    Local,
    /// The peer sent `00 07`.
    Remote,
    /// Nothing was received for [`Config::timeout_ms`].
    Timeout,
    /// A reliable packet was sent [`Config::max_retries`] times without an ack.
    ReliableRetries,
    /// More than [`Config::max_queue`] packets were waiting to be sent.
    QueueOverflow,
    /// The peer started a new connection from the same address.
    Reconnect,
    /// Connection setup failed.
    HandshakeFailed(&'static str),
}

/// Identifies an outgoing sized transfer.
pub type TransferId = u64;

/// Something that happened on a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Setup finished; the session cipher is active.
    Connected,
    /// A complete game packet (first byte non-zero) arrived, from any framing:
    /// plain, reliable, cluster, big data or a finished sized transfer.
    Packet(Vec<u8>),
    /// Progress of an incoming sized transfer.
    SizedProgress {
        /// Bytes received so far.
        received: usize,
        /// Total size announced by the sender.
        total: usize,
    },
    /// An incoming sized transfer was cancelled (by either side) or was invalid.
    SizedIncomingCancelled,
    /// Every chunk of an outgoing sized transfer was acknowledged.
    SizedSent(TransferId),
    /// An outgoing sized transfer was cancelled (by the peer or locally).
    SizedCancelled(TransferId),
    /// The connection is closed; no further events follow.
    Disconnected(DisconnectReason),
}

/// Counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Datagrams sent.
    pub datagrams_sent: u64,
    /// Datagrams received.
    pub datagrams_received: u64,
    /// Bytes sent (after encryption).
    pub bytes_sent: u64,
    /// Bytes received (before decryption).
    pub bytes_received: u64,
    /// Reliable retransmissions.
    pub retransmits: u64,
    /// Duplicate reliable packets received.
    pub duplicates: u64,
    /// Datagrams dropped as malformed, out of window or undecryptable.
    pub dropped: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    None,
    Sized { id: TransferId, last: bool },
    Cipher,
}

#[derive(Debug)]
struct InFlight {
    seq: i32,
    datagram: Vec<u8>,
    sends: u32,
    last_sent: u64,
    tag: Tag,
}

#[derive(Debug)]
struct SizedOut {
    id: TransferId,
    data: Vec<u8>,
    offset: usize,
}

#[derive(Debug)]
struct SizedIn {
    total: usize,
    data: Vec<u8>,
}

enum State {
    Handshaking(Box<dyn Handshake>),
    Connected,
    Closed,
}

/// Maximum nesting of clusters/reliables processed recursively.
const MAX_DEPTH: u32 = 4;

/// Server time in ticks (1/100 s), 31 bits as the protocol uses.
pub fn ticks(now_ms: u64) -> u32 {
    ((now_ms / 10) as u32) & 0x7FFF_FFFF
}

/// One end of a SubSpace transport connection.
pub struct Connection {
    cfg: Config,
    state: State,
    cipher: Option<Box<dyn Cipher>>,
    last_recv: u64,
    session_started: bool,
    // Reliable send.
    next_seq: i32,
    pending: VecDeque<(Vec<u8>, Tag)>,
    in_flight: VecDeque<InFlight>,
    rtt_avg: u64,
    rtt_dev: u64,
    // Reliable receive.
    expected: i32,
    recv_buf: BTreeMap<i32, Vec<u8>>,
    acks: Vec<i32>,
    // Unreliable send.
    unreliable: VecDeque<Vec<u8>>,
    // Big data receive.
    big: Vec<u8>,
    big_overflow: bool,
    // Sized transfers.
    sized_out: VecDeque<SizedOut>,
    sized_in: Option<SizedIn>,
    sized_ignore_total: Option<u32>,
    next_transfer: TransferId,
    // Time sync.
    next_sync: Option<u64>,
    clock_offset: i32,
    sync_rtt: Option<u32>,
    peer_counts: Option<(u32, u32)>,
    // Output.
    transmit: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
    cipher_out: Vec<(Vec<u8>, bool)>,
    stats: Stats,
}

impl core::fmt::Debug for Connection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Connection")
            .field(
                "state",
                &match self.state {
                    State::Handshaking(_) => "handshaking",
                    State::Connected => "connected",
                    State::Closed => "closed",
                },
            )
            .field("cipher", &self.cipher.as_ref().map(|c| c.name()))
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl Connection {
    fn new(cfg: Config, state: State, now: u64) -> Self {
        Self {
            cfg,
            state,
            cipher: None,
            last_recv: now,
            session_started: false,
            next_seq: 0,
            pending: VecDeque::new(),
            in_flight: VecDeque::new(),
            rtt_avg: 200,
            rtt_dev: 100,
            expected: 0,
            recv_buf: BTreeMap::new(),
            acks: Vec::new(),
            unreliable: VecDeque::new(),
            big: Vec::new(),
            big_overflow: false,
            sized_out: VecDeque::new(),
            sized_in: None,
            sized_ignore_total: None,
            next_transfer: 1,
            next_sync: None,
            clock_offset: 0,
            sync_rtt: None,
            peer_counts: None,
            transmit: VecDeque::new(),
            events: VecDeque::new(),
            cipher_out: Vec::new(),
            stats: Stats::default(),
        }
    }

    /// Starts a client connection; the handshake emits the first datagram on the
    /// first [`Connection::tick`].
    pub fn client(cfg: Config, handshake: Box<dyn Handshake>, now: u64) -> Self {
        let mut c = Self::new(cfg, State::Handshaking(handshake), now);
        c.tick(now);
        c
    }

    /// Creates the server end of a connection from an [`Accept`] result.
    pub fn server(cfg: Config, accept: Accept, now: u64) -> Self {
        let mut c = Self::new(cfg, State::Closed, now);
        match accept {
            Accept::Established(cipher) => c.establish(cipher, now),
            Accept::Pending(h) => c.state = State::Handshaking(h),
        }
        c
    }

    fn establish(&mut self, cipher: Box<dyn Cipher>, now: u64) {
        self.cipher = Some(cipher);
        self.state = State::Connected;
        self.events.push_back(Event::Connected);
        if self.cfg.sync_interval_ms.is_some() {
            self.next_sync = Some(now);
        }
    }

    /// Whether setup has finished and the connection is open.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, State::Connected)
    }

    /// Whether the connection has closed. Drain [`Connection::poll_transmit`]
    /// once more to send the final `00 07`.
    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed)
    }

    /// Whether any reliable or game data has been received yet (servers treat a
    /// repeated connection request differently before and after this).
    pub fn session_started(&self) -> bool {
        self.session_started
    }

    /// Name of the active cipher, if connected.
    pub fn cipher_name(&self) -> Option<&'static str> {
        self.cipher.as_ref().map(|c| c.name())
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Smoothed round-trip time from reliable acknowledgements (ms).
    pub fn rtt_ms(&self) -> u64 {
        self.rtt_avg
    }

    /// Round-trip time of the last accepted time sync (ticks), if any.
    pub fn sync_rtt_ticks(&self) -> Option<u32> {
        self.sync_rtt
    }

    /// The peer's server time estimate for local time `now` (ticks, 31 bits):
    /// local ticks plus the offset learned from time sync.
    pub fn server_ticks(&self, now: u64) -> u32 {
        (ticks(now) as i32).wrapping_add(self.clock_offset) as u32 & 0x7FFF_FFFF
    }

    /// The (sent, received) datagram counts the peer reported in its last
    /// time-sync request, for packet-loss statistics.
    pub fn peer_counts(&self) -> Option<(u32, u32)> {
        self.peer_counts
    }

    /// Next queued event.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Next datagram to send (encrypted, ready for the wire).
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.transmit.pop_front()
    }

    fn rto(&self) -> u64 {
        (self.rtt_avg + 4 * self.rtt_dev).clamp(self.cfg.rto_min_ms, self.cfg.rto_max_ms)
    }

    /// Queues a game packet (or core packet) for sending. Packets too large for
    /// one datagram are always sent reliably, split into big-data chunks.
    pub fn send(&mut self, packet: &[u8], reliable: bool) {
        if packet.is_empty() || self.is_closed() {
            return;
        }
        if packet.len() + 6 > self.cfg.max_send {
            self.send_big(packet);
        } else if reliable {
            self.pending.push_back((packet.to_vec(), Tag::None));
        } else {
            self.unreliable.push_back(packet.to_vec());
        }
    }

    fn send_big(&mut self, packet: &[u8]) {
        let n = self.cfg.chunk_size.max(1);
        let chunks: Vec<&[u8]> = packet.chunks(n).collect();
        let last = chunks.len() - 1;
        for (i, c) in chunks.into_iter().enumerate() {
            let mut d = Vec::with_capacity(c.len() + 2);
            d.extend_from_slice(&[0, if i == last { 0x09 } else { 0x08 }]);
            d.extend_from_slice(c);
            self.pending.push_back((d, Tag::None));
        }
    }

    /// Queues a sized transfer (`00 0A` stream, e.g. a map or file download).
    /// Chunks are paced so other traffic keeps flowing. Completion is reported
    /// with [`Event::SizedSent`].
    pub fn send_sized(&mut self, data: Vec<u8>) -> TransferId {
        let id = self.next_transfer;
        self.next_transfer += 1;
        self.sized_out.push_back(SizedOut {
            id,
            data,
            offset: 0,
        });
        id
    }

    /// Stops an outgoing sized transfer (chunks already queued still go out).
    pub fn cancel_outgoing_sized(&mut self, id: TransferId) {
        if let Some(i) = self.sized_out.iter().position(|s| s.id == id) {
            self.sized_out.remove(i);
            self.events.push_back(Event::SizedCancelled(id));
        }
    }

    /// Asks the peer to stop the sized transfer it is sending us (`00 0B`).
    pub fn cancel_incoming_sized(&mut self) {
        if let Some(s) = self.sized_in.take() {
            self.sized_ignore_total = Some(s.total as u32);
            self.events.push_back(Event::SizedIncomingCancelled);
        }
        self.pending.push_back((vec![0, 0x0B], Tag::None));
    }

    /// Closes the connection, sending `00 07`.
    pub fn disconnect(&mut self) {
        self.close(DisconnectReason::Local, true);
    }

    fn close(&mut self, reason: DisconnectReason, notify_peer: bool) {
        if self.is_closed() {
            return;
        }
        let was_connected = self.is_connected();
        self.state = State::Closed;
        self.pending.clear();
        self.in_flight.clear();
        self.unreliable.clear();
        self.sized_out.clear();
        self.transmit.clear();
        if notify_peer && was_connected {
            self.emit(vec![0, 7]);
        }
        self.events.push_back(Event::Disconnected(reason));
    }

    pub(crate) fn note_recv(&mut self, now: u64, len: usize) {
        self.stats.datagrams_received += 1;
        self.stats.bytes_received += len as u64;
        self.last_recv = now;
    }

    pub(crate) fn set_cipher(&mut self, cipher: Box<dyn Cipher>, now: u64) {
        self.note_recv(now, 0);
        self.stats.datagrams_received -= 1;
        if self.is_connected() {
            self.cipher = Some(cipher);
        } else {
            self.establish(cipher, now);
        }
    }

    pub(crate) fn close_with(&mut self, reason: DisconnectReason) {
        self.close(reason, true);
    }

    fn emit(&mut self, mut datagram: Vec<u8>) {
        if let Some(c) = &mut self.cipher {
            c.encrypt(&mut datagram);
        }
        self.stats.datagrams_sent += 1;
        self.stats.bytes_sent += datagram.len() as u64;
        self.transmit.push_back(datagram);
    }

    fn emit_raw(&mut self, datagram: Vec<u8>) {
        self.stats.datagrams_sent += 1;
        self.stats.bytes_sent += datagram.len() as u64;
        self.transmit.push_back(datagram);
    }

    /// Handles one received datagram (as read from the socket).
    pub fn handle_datagram(&mut self, now: u64, data: &[u8]) {
        if data.is_empty() || data.len() > self.cfg.max_recv {
            self.stats.dropped += 1;
            return;
        }
        self.note_recv(now, data.len());
        match &mut self.state {
            State::Closed => {}
            State::Handshaking(h) => {
                let mut out = Vec::new();
                let step = h.on_datagram(now, data, &mut out);
                out.into_iter().for_each(|d| self.emit_raw(d));
                self.apply_step(step, now);
            }
            State::Connected => {
                // A stray (raw, unencrypted) connection response after setup.
                if data.len() >= 6 && data[0] == 0 && data[1] == 2 {
                    return;
                }
                let mut buf = data.to_vec();
                if let Some(c) = &mut self.cipher
                    && !c.decrypt(&mut buf)
                {
                    self.stats.dropped += 1;
                    return;
                }
                self.process(now, &buf, 0, false);
                self.drain_cipher_out();
            }
        }
    }

    fn apply_step(&mut self, step: Step, now: u64) {
        match step {
            Step::Pending => {}
            Step::Established(c) => self.establish(c, now),
            Step::Failed(why) => self.close(DisconnectReason::HandshakeFailed(why), false),
        }
    }

    fn drain_cipher_out(&mut self) {
        for (p, reliable) in std::mem::take(&mut self.cipher_out) {
            if reliable {
                self.pending.push_back((p, Tag::Cipher));
            } else {
                self.unreliable.push_back(p);
            }
        }
    }

    fn deliver(&mut self, packet: &[u8]) {
        if !packet.is_empty() {
            self.session_started = true;
            self.events.push_back(Event::Packet(packet.to_vec()));
        }
    }

    fn process(&mut self, now: u64, p: &[u8], depth: u32, in_reliable: bool) {
        if !self.is_connected() {
            return;
        }
        let Some(&first) = p.first() else { return };
        if first != 0 {
            self.deliver(p);
            return;
        }
        if p.len() < 2 {
            self.stats.dropped += 1;
            return;
        }
        let u32_at = |i: usize| {
            p.get(i..i + 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        match p[1] {
            0x03 if p.len() >= 7 && !in_reliable => {
                let seq = u32_at(2).unwrap_or(0) as i32;
                self.on_reliable(now, seq, &p[6..], depth);
            }
            0x04 if p.len() == 6 => {
                let seq = u32_at(2).unwrap_or(0) as i32;
                self.on_ack(now, seq);
            }
            0x05 if p.len() >= 6 => {
                let echo = u32_at(2).unwrap_or(0);
                if p.len() >= 14 {
                    self.peer_counts = Some((u32_at(6).unwrap_or(0), u32_at(10).unwrap_or(0)));
                }
                let mut r = vec![0, 6];
                r.extend_from_slice(&echo.to_le_bytes());
                r.extend_from_slice(&ticks(now).to_le_bytes());
                self.emit(r);
            }
            0x06 if p.len() >= 10 => {
                let echo = u32_at(2).unwrap_or(0);
                let server = u32_at(6).unwrap_or(0);
                self.on_sync_response(now, echo, server);
            }
            0x07 if p.len() == 2 => self.close(DisconnectReason::Remote, false),
            0x08 | 0x09 if p.len() >= 3 => self.on_big(&p[2..], p[1] == 0x09),
            0x0A if p.len() >= 7 => {
                let total = u32_at(2).unwrap_or(0);
                self.on_sized(total, &p[6..]);
            }
            0x0B if p.len() == 2 => self.on_sized_cancel_request(),
            0x0C if p.len() == 2 => self.on_sized_cancel_ack(),
            0x0E if p.len() >= 4 && depth < MAX_DEPTH => {
                let mut rest = &p[2..];
                while let Some((&n, tail)) = rest.split_first() {
                    let n = usize::from(n);
                    if n == 0 || tail.len() < n {
                        if n != 0 {
                            self.stats.dropped += 1;
                        }
                        break;
                    }
                    let (item, next) = tail.split_at(n);
                    self.process(now, item, depth + 1, in_reliable);
                    rest = next;
                }
            }
            sub if sub >= 0x10 => {
                if let Some(c) = &mut self.cipher {
                    let mut ctx = CipherContext {
                        out: &mut self.cipher_out,
                    };
                    c.handle_core(now, p, &mut ctx);
                }
            }
            _ => self.stats.dropped += 1,
        }
    }

    fn on_reliable(&mut self, now: u64, seq: i32, payload: &[u8], depth: u32) {
        if seq < 0 || seq.wrapping_sub(self.expected) >= self.cfg.recv_window as i32 {
            self.stats.dropped += 1;
            return;
        }
        self.session_started = true;
        self.acks.push(seq);
        if seq < self.expected || self.recv_buf.contains_key(&seq) {
            self.stats.duplicates += 1;
            return;
        }
        self.recv_buf.insert(seq, payload.to_vec());
        while let Some(p) = self.recv_buf.remove(&self.expected) {
            self.expected = self.expected.wrapping_add(1);
            self.process(now, &p, depth + 1, true);
            if self.is_closed() {
                return;
            }
        }
    }

    fn on_ack(&mut self, now: u64, seq: i32) {
        let Some(i) = self.in_flight.iter().position(|r| r.seq == seq) else {
            return;
        };
        let r = self.in_flight.remove(i).expect("index from position");
        if r.sends == 1 {
            let sample = now.saturating_sub(r.last_sent);
            let diff = self.rtt_avg.abs_diff(sample);
            self.rtt_dev = (3 * self.rtt_dev + diff) / 4;
            self.rtt_avg = (7 * self.rtt_avg + sample) / 8;
        }
        if let Tag::Sized { id, last: true } = r.tag {
            self.events.push_back(Event::SizedSent(id));
        }
    }

    fn on_sync_response(&mut self, now: u64, echo: u32, server: u32) {
        let local = ticks(now);
        let rtt = local.wrapping_sub(echo) & 0x7FFF_FFFF;
        if rtt > 30_000 {
            return;
        }
        let mut offset = (rtt as i32 * 3 / 5)
            .wrapping_add(server as i32)
            .wrapping_sub(local as i32);
        if offset.abs() <= 10 {
            offset = 0;
        }
        self.clock_offset = offset;
        self.sync_rtt = Some(rtt);
    }

    fn on_big(&mut self, slice: &[u8], last: bool) {
        if !self.big_overflow {
            if self.big.len() + slice.len() > self.cfg.max_big {
                self.big_overflow = true;
                self.big = Vec::new();
            } else {
                self.big.extend_from_slice(slice);
            }
        }
        if last {
            let whole = std::mem::take(&mut self.big);
            let overflowed = std::mem::replace(&mut self.big_overflow, false);
            if overflowed || whole.first().is_none_or(|&b| b == 0) {
                self.stats.dropped += 1;
            } else {
                self.deliver(&whole);
            }
        }
    }

    fn on_sized(&mut self, total: u32, slice: &[u8]) {
        if self.sized_in.is_none() {
            if self.sized_ignore_total == Some(total) {
                return;
            }
            self.sized_ignore_total = None;
            if total as usize > self.cfg.max_sized || slice.first().is_none_or(|&b| b == 0) {
                self.events.push_back(Event::SizedIncomingCancelled);
                self.pending.push_back((vec![0, 0x0B], Tag::None));
                self.sized_ignore_total = Some(total);
                return;
            }
            self.sized_in = Some(SizedIn {
                total: total as usize,
                data: Vec::new(),
            });
        }
        let s = self.sized_in.as_mut().expect("set above");
        if s.total != total as usize || s.data.len() + slice.len() > s.total {
            self.sized_in = None;
            self.events.push_back(Event::SizedIncomingCancelled);
            return;
        }
        s.data.extend_from_slice(slice);
        let (received, total) = (s.data.len(), s.total);
        self.events
            .push_back(Event::SizedProgress { received, total });
        if received >= total {
            let s = self.sized_in.take().expect("present");
            self.deliver(&s.data);
        }
    }

    fn on_sized_cancel_request(&mut self) {
        if let Some(s) = self.sized_out.pop_front() {
            self.events.push_back(Event::SizedCancelled(s.id));
        }
        if self.sized_in.take().is_some() {
            self.events.push_back(Event::SizedIncomingCancelled);
        }
        self.pending.push_back((vec![0, 0x0C], Tag::None));
    }

    fn on_sized_cancel_ack(&mut self) {
        self.sized_ignore_total = None;
        if self.sized_in.take().is_some() {
            self.events.push_back(Event::SizedIncomingCancelled);
        }
    }

    /// Runs timers (handshake resends, retransmissions, time sync, timeouts) and
    /// packs queued packets into datagrams. Call it regularly (every ~10 ms) and
    /// after queueing packets you want sent promptly.
    pub fn tick(&mut self, now: u64) {
        match &mut self.state {
            State::Closed => return,
            State::Handshaking(h) => {
                let mut out = Vec::new();
                let step = h.poll(now, &mut out);
                out.into_iter().for_each(|d| self.emit_raw(d));
                self.apply_step(step, now);
                if !self.is_connected() {
                    return;
                }
            }
            State::Connected => {}
        }
        if now.saturating_sub(self.last_recv) >= self.cfg.timeout_ms {
            self.close(DisconnectReason::Timeout, true);
            return;
        }
        if let Some(c) = &mut self.cipher {
            let mut ctx = CipherContext {
                out: &mut self.cipher_out,
            };
            c.poll(now, &mut ctx);
        }
        self.drain_cipher_out();
        if let (Some(at), Some(interval)) = (self.next_sync, self.cfg.sync_interval_ms)
            && now >= at
        {
            let mut p = vec![0, 5];
            p.extend_from_slice(&ticks(now).to_le_bytes());
            p.extend_from_slice(&(self.stats.datagrams_sent as u32 + 1).to_le_bytes());
            p.extend_from_slice(&(self.stats.datagrams_received as u32).to_le_bytes());
            self.unreliable.push_back(p);
            self.next_sync = Some(now + interval);
        }
        self.refill_sized();
        if self.pending.len() + self.in_flight.len() + self.unreliable.len() > self.cfg.max_queue {
            self.close(DisconnectReason::QueueOverflow, true);
            return;
        }
        self.flush(now);
    }

    fn refill_sized(&mut self) {
        let unacked = self.pending.len() + self.in_flight.len();
        if unacked >= self.cfg.sized_threshold {
            return;
        }
        let Some(s) = self.sized_out.front_mut() else {
            return;
        };
        let n = self.cfg.chunk_size.max(1);
        let total = s.data.len() as u32;
        let mut queued = Vec::new();
        for _ in 0..self.cfg.sized_batch {
            if s.offset >= s.data.len() {
                break;
            }
            let end = (s.offset + n).min(s.data.len());
            let mut p = Vec::with_capacity(6 + end - s.offset);
            p.extend_from_slice(&[0, 0x0A]);
            p.extend_from_slice(&total.to_le_bytes());
            p.extend_from_slice(&s.data[s.offset..end]);
            s.offset = end;
            queued.push((
                p,
                Tag::Sized {
                    id: s.id,
                    last: end == s.data.len(),
                },
            ));
        }
        let done = s.offset >= s.data.len();
        let id = s.id;
        self.pending.extend(queued);
        if done {
            self.sized_out.pop_front();
            if total == 0 {
                self.events.push_back(Event::SizedSent(id));
            }
        }
    }

    /// Packs acks, due reliables and unreliable packets into datagrams now.
    pub fn flush(&mut self, now: u64) {
        if !self.is_connected() {
            return;
        }
        // Admit pending reliables into the window.
        while self.in_flight.len() < self.cfg.send_window {
            let Some((payload, tag)) = self.pending.pop_front() else {
                break;
            };
            let mut d = Vec::with_capacity(payload.len() + 6);
            d.extend_from_slice(&[0, 3]);
            d.extend_from_slice(&self.next_seq.to_le_bytes());
            d.extend_from_slice(&payload);
            self.in_flight.push_back(InFlight {
                seq: self.next_seq,
                datagram: d,
                sends: 0,
                last_sent: 0,
                tag,
            });
            self.next_seq = self.next_seq.wrapping_add(1);
        }

        let mut items: Vec<Vec<u8>> = Vec::new();
        for seq in std::mem::take(&mut self.acks) {
            let mut a = vec![0, 4];
            a.extend_from_slice(&seq.to_le_bytes());
            items.push(a);
        }
        let rto = self.rto();
        let mut give_up = false;
        for r in &mut self.in_flight {
            let due = r.sends == 0 || now.saturating_sub(r.last_sent) >= u64::from(r.sends) * rto;
            if !due {
                continue;
            }
            if r.sends >= self.cfg.max_retries {
                give_up = true;
                break;
            }
            if r.sends > 0 {
                self.stats.retransmits += 1;
            }
            r.sends += 1;
            r.last_sent = now;
            items.push(r.datagram.clone());
        }
        if give_up {
            self.close(DisconnectReason::ReliableRetries, true);
            return;
        }
        items.extend(self.unreliable.drain(..));

        let max = self.cfg.max_send;
        let mut cluster: Vec<u8> = Vec::new();
        let mut count = 0;
        let mut single: Option<Vec<u8>> = None;
        for item in items {
            if item.len() > 255 {
                self.emit(item);
                continue;
            }
            let base = if count == 0 { 2 } else { cluster.len() };
            if count > 0 && base + 1 + item.len() > max {
                self.flush_cluster(&mut cluster, &mut count, &mut single);
            }
            if count == 0 {
                cluster.clear();
                cluster.extend_from_slice(&[0, 0x0E]);
            }
            cluster.push(item.len() as u8);
            cluster.extend_from_slice(&item);
            if count == 0 {
                single = Some(item);
            }
            count += 1;
        }
        self.flush_cluster(&mut cluster, &mut count, &mut single);
    }

    fn flush_cluster(
        &mut self,
        cluster: &mut Vec<u8>,
        count: &mut usize,
        single: &mut Option<Vec<u8>>,
    ) {
        match *count {
            0 => {}
            1 => {
                if let Some(s) = single.take() {
                    self.emit(s);
                }
            }
            _ => self.emit(std::mem::take(cluster)),
        }
        *count = 0;
        *single = None;
        cluster.clear();
    }

    /// When the connection next needs [`Connection::tick`] at the latest (ms), if
    /// it has pending work. Calling `tick` more often is always fine.
    pub fn next_timeout(&self) -> Option<u64> {
        if self.is_closed() {
            return None;
        }
        let mut t = self.last_recv + self.cfg.timeout_ms;
        if let Some(s) = self.next_sync {
            t = t.min(s);
        }
        let rto = self.rto();
        for r in &self.in_flight {
            t = t.min(r.last_sent + u64::from(r.sends.max(1)) * rto);
        }
        if !self.pending.is_empty() || !self.unreliable.is_empty() || !self.acks.is_empty() {
            t = 0;
        }
        if matches!(self.state, State::Handshaking(_)) {
            t = t.min(self.last_recv + 100);
        }
        Some(t)
    }
}
