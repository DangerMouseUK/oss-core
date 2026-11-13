//! The per-peer transport state machine.
//!
//! A [`Connection`] is sans-IO: feed it received datagrams with
//! [`Connection::handle_datagram`], drive its timers with [`Connection::tick`]
//! (every ~10 ms is typical), queue packets with [`Connection::send`] /
//! [`Connection::send_sized`], then drain [`Connection::poll_transmit`] (datagrams
//! to put on the wire, already encrypted) and [`Connection::poll_event`]
//! (connection state and received game packets). Time is a caller-supplied
//! monotonic millisecond counter.

use std::collections::VecDeque;

use crate::cipher::{Accept, Cipher, CipherContext, CipherKind, Handshake, Step};

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
    /// Unreliable bytes sent per flush before lower-priority traffic waits and
    /// droppable packets are discarded; `None` for no limit. A crude bandwidth
    /// cap: at a 10 ms flush interval, 1300 bytes is about 1 Mbit/s.
    pub unreliable_budget: Option<usize>,
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
            unreliable_budget: None,
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
    /// Outgoing droppable packets discarded because of the unreliable budget.
    pub dropped_outgoing: u64,
}

/// Priority of an unreliable packet within a flush.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Priority {
    /// Sent after everything else (e.g. bulk updates).
    Low,
    /// Normal traffic.
    #[default]
    Normal,
    /// Sent before normal traffic (e.g. weapons fire).
    High,
    /// Sent immediately in its own datagram, bypassing clustering and the
    /// budget (e.g. time-critical position updates).
    Urgent,
}

/// Delivery options for [`Connection::send_with`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SendFlags {
    /// Deliver reliably and in order (priority and droppable are ignored).
    pub reliable: bool,
    /// Ordering of unreliable packets.
    pub priority: Priority,
    /// May be discarded when [`Config::unreliable_budget`] is exhausted
    /// instead of waiting for the next flush.
    pub droppable: bool,
}

impl SendFlags {
    /// Reliable delivery.
    pub const RELIABLE: Self = Self {
        reliable: true,
        priority: Priority::Normal,
        droppable: false,
    };
    /// Unreliable, normal priority.
    pub const UNRELIABLE: Self = Self {
        reliable: false,
        priority: Priority::Normal,
        droppable: false,
    };
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

/// Capacity of pooled buffers: a full datagram plus cipher overhead.
const BUF_CAPACITY: usize = 576;
/// Most buffers kept for reuse per connection.
pub(crate) const POOL_LIMIT: usize = 256;

/// Free buffers, reused so a busy connection does not allocate per packet.
#[derive(Debug, Default)]
pub(crate) struct Pool {
    free: Vec<Vec<u8>>,
    /// Buffers taken since the last [`Pool::refill_target`]: what one interval
    /// between top-ups actually asked for.
    taken: usize,
    /// Decaying maximum of recent `taken`, which is the top-up target.
    demand: usize,
}

impl Pool {
    fn take(&mut self) -> Vec<u8> {
        self.taken = self.taken.saturating_add(1);
        self.free
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(BUF_CAPACITY))
    }

    fn copy_of(&mut self, data: &[u8]) -> Vec<u8> {
        let mut b = self.take();
        b.extend_from_slice(data);
        b
    }

    pub(crate) fn put(&mut self, b: Vec<u8>) {
        self.put_bounded(b, POOL_LIMIT);
    }

    /// Like [`Pool::put`] with a caller-chosen size limit (a server's shared
    /// pool grows with its connection count).
    pub(crate) fn put_bounded(&mut self, mut b: Vec<u8>, limit: usize) {
        if self.free.len() < limit && b.capacity() >= BUF_CAPACITY && b.capacity() <= 4096 {
            b.clear();
            self.free.push(b);
        }
    }

    /// How many buffers to top this pool up to, from the demand recent
    /// intervals placed on it: a connection the server is pushing a crowded
    /// arena's traffic into needs one buffer per queued packet, which is a
    /// fan-out's worth per tick, not a fixed handful.
    ///
    /// The target rises to a new peak at once and falls by an eighth each
    /// interval, so a burst is served without allocating and a connection that
    /// quietens down gives the buffers back. Call once per top-up: it consumes
    /// the count.
    pub(crate) fn refill_target(&mut self, floor: usize, cap: usize) -> usize {
        let last = std::mem::take(&mut self.taken);
        self.demand = last.max(self.demand - self.demand / 8);
        // A quarter of headroom, so an interval slightly busier than the last
        // does not have to allocate.
        self.demand
            .saturating_add(self.demand / 4)
            .clamp(floor, cap)
    }

    /// Moves buffers from `other` until this pool holds `target` (or `other`
    /// runs out).
    pub(crate) fn refill_from(&mut self, other: &mut Pool, target: usize) {
        while self.free.len() < target {
            let Some(b) = other.free.pop() else { break };
            self.free.push(b);
        }
    }
}

/// Encrypts and queues datagrams; borrows only the fields it needs so callers
/// can iterate other parts of the connection at the same time.
struct Emitter<'a> {
    cipher: &'a mut Option<Box<dyn Cipher>>,
    stats: &'a mut Stats,
    transmit: &'a mut VecDeque<Vec<u8>>,
    pool: &'a mut Pool,
}

impl Emitter<'_> {
    fn emit(&mut self, mut datagram: Vec<u8>) {
        if let Some(c) = self.cipher {
            c.encrypt(&mut datagram);
        }
        self.stats.datagrams_sent += 1;
        self.stats.bytes_sent += datagram.len() as u64;
        self.transmit.push_back(datagram);
    }
}

/// Packs items into cluster datagrams (unwrapping single items).
struct Packer {
    cur: Vec<u8>,
    count: usize,
    max: usize,
}

impl Packer {
    fn add(&mut self, item: &[u8], em: &mut Emitter<'_>) {
        if item.len() > 255 {
            let b = em.pool.copy_of(item);
            em.emit(b);
            return;
        }
        if self.count > 0 && self.cur.len() + 1 + item.len() > self.max {
            self.finish(em);
        }
        if self.count == 0 {
            self.cur.clear();
            self.cur.extend_from_slice(&[0, 0x0E]);
        }
        self.cur.push(item.len() as u8);
        self.cur.extend_from_slice(item);
        self.count += 1;
    }

    fn finish(&mut self, em: &mut Emitter<'_>) {
        match self.count {
            0 => return,
            1 => {
                // A lone item goes out bare: drop the `00 0E len` prefix.
                self.cur.drain(..3);
            }
            _ => {}
        }
        let next = em.pool.take();
        em.emit(std::mem::replace(&mut self.cur, next));
        self.count = 0;
    }
}

/// Server time in ticks (1/100 s), 31 bits as the protocol uses.
pub fn ticks(now_ms: u64) -> u32 {
    ((now_ms / 10) as u32) & 0x7FFF_FFFF
}

/// One end of a SubSpace transport connection.
pub struct Connection {
    cfg: Config,
    state: State,
    cipher: Option<Box<dyn Cipher>>,
    connect_protocol: Option<u16>,
    accept_request: Vec<u8>,
    accept_replies: Vec<Vec<u8>>,
    last_recv: u64,
    session_started: bool,
    // Reliable send.
    next_seq: i32,
    pending: VecDeque<(Vec<u8>, Tag)>,
    in_flight: VecDeque<InFlight>,
    rtt_avg: u64,
    rtt_dev: u64,
    // Reliable receive: slot `seq % recv_window` holds a payload waiting for
    // its turn.
    expected: i32,
    recv_ring: Vec<Option<Vec<u8>>>,
    acks: Vec<i32>,
    pool: Pool,
    // Unreliable send.
    /// Unreliable queues by priority: high, normal, low. Entries carry the
    /// droppable flag.
    unreliable: [VecDeque<(Vec<u8>, bool)>; 3],
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
        let window = cfg.recv_window.max(1) as usize;
        Self {
            recv_ring: (0..window).map(|_| None).collect(),
            pool: Pool::default(),
            cfg,
            state,
            cipher: None,
            connect_protocol: None,
            accept_request: Vec::new(),
            accept_replies: Vec::new(),
            last_recv: now,
            session_started: false,
            next_seq: 0,
            pending: VecDeque::new(),
            in_flight: VecDeque::new(),
            rtt_avg: 200,
            rtt_dev: 100,
            expected: 0,
            acks: Vec::new(),
            unreliable: Default::default(),
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

    /// Encryption family of the active cipher, if connected. Servers use it to
    /// tell SubSpace (VIE) clients from Continuum clients.
    pub fn cipher_kind(&self) -> Option<CipherKind> {
        self.cipher.as_ref().map(|c| c.kind())
    }

    /// The peer's authenticated long-term key, if the cipher has one (an
    /// OpenSec server key, for pinning on the client).
    pub fn peer_key(&self) -> Option<[u8; 32]> {
        self.cipher.as_ref().and_then(|c| c.peer_key())
    }

    /// The protocol word from the client's `00 01` request (0x0001 SubSpace,
    /// 0x0011 Continuum), on server-side connections created by [`crate::Server`].
    pub fn connect_protocol(&self) -> Option<u16> {
        self.connect_protocol
    }

    pub(crate) fn set_connect_protocol(&mut self, p: Option<u16>) {
        self.connect_protocol = p;
    }

    /// Returns a buffer obtained from [`Connection::poll_transmit`] or an
    /// [`Event::Packet`] so it can be reused. Optional, but recycling every
    /// buffer keeps a busy connection free of per-packet allocations.
    pub fn recycle(&mut self, buf: Vec<u8>) {
        self.pool.put(buf);
    }

    pub(crate) fn pool_mut(&mut self) -> &mut Pool {
        &mut self.pool
    }

    fn emitter(&mut self) -> Emitter<'_> {
        Emitter {
            cipher: &mut self.cipher,
            stats: &mut self.stats,
            transmit: &mut self.transmit,
            pool: &mut self.pool,
        }
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Reliable packets not yet acknowledged: waiting for the send window plus
    /// sent and unacknowledged. A growing value means the peer cannot keep up;
    /// servers can use it for back-pressure or metrics.
    pub fn queued_reliable(&self) -> usize {
        self.pending.len() + self.in_flight.len()
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

    /// Largest plaintext datagram, leaving room for the cipher's overhead.
    fn max_plain(&self) -> usize {
        let overhead = self.cipher.as_ref().map_or(0, |c| c.overhead());
        self.cfg.max_send.saturating_sub(overhead)
    }

    /// The connection request this server-side connection was created from and
    /// the raw replies sent to it, so a duplicate request can be answered
    /// identically instead of re-keying.
    pub(crate) fn set_accept_record(&mut self, request: &[u8], replies: &[Vec<u8>]) {
        self.accept_request.clear();
        self.accept_request.extend_from_slice(request);
        self.accept_replies = replies.to_vec();
    }

    pub(crate) fn accept_record(&self) -> (&[u8], &[Vec<u8>]) {
        (&self.accept_request, &self.accept_replies)
    }

    fn rto(&self) -> u64 {
        (self.rtt_avg + 4 * self.rtt_dev).clamp(self.cfg.rto_min_ms, self.cfg.rto_max_ms)
    }

    /// Queues a game packet (or core packet) for sending. Packets too large for
    /// one datagram are always sent reliably, split into big-data chunks.
    pub fn send(&mut self, packet: &[u8], reliable: bool) {
        let flags = if reliable {
            SendFlags::RELIABLE
        } else {
            SendFlags::UNRELIABLE
        };
        self.send_with(packet, flags);
    }

    /// Queues a packet with explicit delivery options (priority, droppable,
    /// urgent). Packets too large for one datagram are always sent reliably.
    pub fn send_with(&mut self, packet: &[u8], flags: SendFlags) {
        if packet.is_empty() || self.is_closed() {
            return;
        }
        if packet.len() + 6 > self.max_plain() {
            self.send_big(packet);
        } else if flags.reliable {
            let b = self.pool.copy_of(packet);
            self.pending.push_back((b, Tag::None));
        } else if flags.priority == Priority::Urgent && self.is_connected() {
            let b = self.pool.copy_of(packet);
            self.emit(b);
        } else {
            let q = match flags.priority {
                Priority::High | Priority::Urgent => 0,
                Priority::Normal => 1,
                Priority::Low => 2,
            };
            let b = self.pool.copy_of(packet);
            self.unreliable[q].push_back((b, flags.droppable));
        }
    }

    fn unreliable_len(&self) -> usize {
        self.unreliable.iter().map(VecDeque::len).sum()
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
        self.unreliable.iter_mut().for_each(VecDeque::clear);
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

    fn emit(&mut self, datagram: Vec<u8>) {
        self.emitter().emit(datagram);
    }

    fn emit_raw(&mut self, datagram: Vec<u8>) {
        self.stats.datagrams_sent += 1;
        self.stats.bytes_sent += datagram.len() as u64;
        self.transmit.push_back(datagram);
    }

    /// Handles one received datagram (as read from the socket).
    pub fn handle_datagram(&mut self, now: u64, data: &[u8]) {
        let overhead = self.cipher.as_ref().map_or(0, |c| c.overhead());
        if data.is_empty() || data.len() > self.cfg.max_recv + overhead {
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
                let mut buf = self.pool.copy_of(data);
                if let Some(c) = &mut self.cipher
                    && !c.decrypt(&mut buf)
                {
                    self.stats.dropped += 1;
                    self.pool.put(buf);
                    return;
                }
                self.process(now, &buf, 0, false);
                self.pool.put(buf);
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
        if self.cipher_out.is_empty() {
            return;
        }
        for (p, reliable) in std::mem::take(&mut self.cipher_out) {
            if reliable {
                self.pending.push_back((p, Tag::Cipher));
            } else {
                self.unreliable[1].push_back((p, false));
            }
        }
    }

    fn deliver(&mut self, packet: &[u8]) {
        if !packet.is_empty() {
            self.session_started = true;
            let b = self.pool.copy_of(packet);
            self.events.push_back(Event::Packet(b));
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
                let mut r = self.pool.take();
                r.extend_from_slice(&[0, 6]);
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
        let n = self.recv_ring.len();
        let slot = seq as usize % n;
        if seq < self.expected || self.recv_ring[slot].is_some() {
            self.stats.duplicates += 1;
            return;
        }
        let b = self.pool.copy_of(payload);
        self.recv_ring[slot] = Some(b);
        loop {
            let slot = self.expected as usize % n;
            let Some(p) = self.recv_ring[slot].take() else {
                break;
            };
            self.expected = self.expected.wrapping_add(1);
            self.process(now, &p, depth + 1, true);
            self.pool.put(p);
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
        self.pool.put(r.datagram);
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
            let mut p = self.pool.take();
            p.extend_from_slice(&[0, 5]);
            p.extend_from_slice(&ticks(now).to_le_bytes());
            p.extend_from_slice(&(self.stats.datagrams_sent as u32 + 1).to_le_bytes());
            p.extend_from_slice(&(self.stats.datagrams_received as u32).to_le_bytes());
            self.unreliable[0].push_back((p, false));
            self.next_sync = Some(now + interval);
        }
        self.refill_sized();
        if self.pending.len() + self.in_flight.len() + self.unreliable_len() > self.cfg.max_queue {
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
            let mut d = self.pool.take();
            d.extend_from_slice(&[0, 3]);
            d.extend_from_slice(&self.next_seq.to_le_bytes());
            d.extend_from_slice(&payload);
            self.pool.put(payload);
            self.in_flight.push_back(InFlight {
                seq: self.next_seq,
                datagram: d,
                sends: 0,
                last_sent: 0,
                tag,
            });
            self.next_seq = self.next_seq.wrapping_add(1);
        }

        // Give up on the peer if a due reliable has used all its retries.
        let rto = self.rto();
        let due = |r: &InFlight| {
            r.sends == 0 || now.saturating_sub(r.last_sent) >= u64::from(r.sends) * rto
        };
        if self
            .in_flight
            .iter()
            .any(|r| due(r) && r.sends >= self.cfg.max_retries)
        {
            self.close(DisconnectReason::ReliableRetries, true);
            return;
        }

        let mut packer = Packer {
            cur: self.pool.take(),
            count: 0,
            max: self.max_plain(),
        };
        let mut em = Emitter {
            cipher: &mut self.cipher,
            stats: &mut self.stats,
            transmit: &mut self.transmit,
            pool: &mut self.pool,
        };
        for &seq in &self.acks {
            let mut a = [0u8; 6];
            a[1] = 4;
            a[2..].copy_from_slice(&seq.to_le_bytes());
            packer.add(&a, &mut em);
        }
        self.acks.clear();
        for r in &mut self.in_flight {
            if !due(r) {
                continue;
            }
            if r.sends > 0 {
                em.stats.retransmits += 1;
            }
            r.sends += 1;
            r.last_sent = now;
            packer.add(&r.datagram, &mut em);
        }
        let mut budget = self.cfg.unreliable_budget.unwrap_or(usize::MAX);
        for q in &mut self.unreliable {
            while let Some((u, droppable)) = q.pop_front() {
                if u.len() > budget {
                    if droppable {
                        em.stats.dropped_outgoing += 1;
                        em.pool.put(u);
                        continue;
                    }
                    // Wait for the next flush; lower priorities wait too.
                    q.push_front((u, droppable));
                    budget = 0;
                    break;
                }
                budget -= u.len();
                packer.add(&u, &mut em);
                em.pool.put(u);
            }
        }
        packer.finish(&mut em);
        em.pool.put(packer.cur);
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
        if !self.pending.is_empty() || self.unreliable_len() > 0 || !self.acks.is_empty() {
            t = 0;
        }
        if matches!(self.state, State::Handshaking(_)) {
            t = t.min(self.last_recv + 100);
        }
        Some(t)
    }
}
