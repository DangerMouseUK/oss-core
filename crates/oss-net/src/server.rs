//! Server endpoint: many [`Connection`]s keyed by peer address.
//!
//! The address type is generic (`SocketAddr` natively, anything hashable in
//! tests or exotic transports). Feed every received datagram to
//! [`Server::handle_datagram`], call [`Server::tick`] regularly, and drain
//! [`Server::poll_transmit`] / [`Server::poll_event`].

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

use crate::cipher::Acceptor;
use crate::connection::{Config, Connection, DisconnectReason, Event, POOL_LIMIT, Pool};

/// Fewest buffers a connection is topped up to when the server collects its
/// output. The actual target follows the connection's own recent demand (see
/// `Pool::refill_target`); this is the floor an idle one keeps.
const CONN_REFILL: usize = 16;
/// Most buffers a connection is topped up to, whatever its demand.
const CONN_REFILL_MAX: usize = POOL_LIMIT;
/// Smallest limit of the server's shared buffer pool.
const SHARED_POOL_MIN: usize = 256;
/// Shared pool buffers allowed per connection.
const SHARED_POOL_PER_CONN: usize = 8;

/// Multiplexes connections for a listening socket.
pub struct Server<A> {
    cfg: Config,
    acceptors: Vec<Box<dyn Acceptor>>,
    conns: HashMap<A, Connection>,
    /// Maximum simultaneous connections; further requests get `00 07`.
    pub max_connections: usize,
    raw_out: VecDeque<(A, Vec<u8>)>,
    events: VecDeque<(A, Event)>,
    pool: Pool,
    scratch: Vec<A>,
}

impl<A> core::fmt::Debug for Server<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Server")
            .field("connections", &self.conns.len())
            .field("acceptors", &self.acceptors.len())
            .finish_non_exhaustive()
    }
}

impl<A: Eq + Hash + Clone> Server<A> {
    /// A server using `cfg` for each connection (see [`Config::server`]).
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            acceptors: Vec::new(),
            conns: HashMap::new(),
            max_connections: 1024,
            raw_out: VecDeque::new(),
            events: VecDeque::new(),
            pool: Pool::default(),
            scratch: Vec::new(),
        }
    }

    /// Adds an acceptor; they are asked in the order added.
    pub fn add_acceptor(&mut self, acceptor: Box<dyn Acceptor>) {
        self.acceptors.push(acceptor);
    }

    fn try_accept(&mut self, now: u64, from: &A, data: &[u8]) -> bool {
        let mut out = Vec::new();
        let accepted = self
            .acceptors
            .iter()
            .find_map(|a| a.accept(now, data, &mut out));
        let replies = out.clone();
        out.into_iter()
            .for_each(|d| self.raw_out.push_back((from.clone(), d)));
        match accepted {
            Some(acc) => {
                let mut conn = Connection::server(self.cfg.clone(), acc, now);
                conn.set_connect_protocol(crate::cipher::parse_connect(data).map(|(_, p)| p));
                conn.set_accept_record(data, &replies);
                // The request itself counts as received traffic.
                conn.note_received(now, data.len());
                self.conns.insert(from.clone(), conn);
                self.collect(from);
                true
            }
            None => false,
        }
    }

    /// Handles a datagram from `from`.
    pub fn handle_datagram(&mut self, now: u64, from: A, data: &[u8]) {
        let is_request = data.len() >= 2 && data[0] == 0 && (data[1] == 0x01 || data[1] == 0x11);
        match self.conns.get_mut(&from) {
            None => {
                if !is_request {
                    return;
                }
                if self.conns.len() >= self.max_connections {
                    if crate::cipher::parse_connect(data).is_some() {
                        self.raw_out.push_back((from, vec![0, 7]));
                    }
                    return;
                }
                self.try_accept(now, &from, data);
            }
            Some(conn)
                if is_request && conn.accept_record().0 == data && !conn.session_started() =>
            {
                // A duplicate of the request this connection came from (its
                // answer was lost): answer identically, keep the session.
                conn.note_received(now, data.len());
                let replies = conn.accept_record().1.to_vec();
                for r in replies {
                    self.raw_out.push_back((from.clone(), r));
                }
            }
            Some(conn) if is_request && data[1] == 0x01 => {
                if conn.session_started() {
                    // A new connection attempt from a live session: end the old
                    // one; the client retries until it is gone.
                    conn.close_for_reconnect();
                    self.collect(&from);
                    self.conns.remove(&from);
                } else {
                    // Lost 00 02 or a client restart before login: answer again
                    // and re-key, keeping sequence numbers and queues.
                    let mut out = Vec::new();
                    let accepted = self
                        .acceptors
                        .iter()
                        .find_map(|a| a.accept(now, data, &mut out));
                    out.into_iter()
                        .for_each(|d| self.raw_out.push_back((from.clone(), d)));
                    match accepted {
                        Some(crate::cipher::Accept::Established(cipher)) => {
                            if let Some(conn) = self.conns.get_mut(&from) {
                                conn.rekey(cipher, now);
                            }
                        }
                        Some(pending) => {
                            let mut conn = Connection::server(self.cfg.clone(), pending, now);
                            conn.set_connect_protocol(
                                crate::cipher::parse_connect(data).map(|(_, p)| p),
                            );
                            self.conns.insert(from.clone(), conn);
                        }
                        None => {}
                    }
                    self.collect(&from);
                }
            }
            Some(conn) => {
                conn.handle_datagram(now, data);
                self.collect(&from);
            }
        }
    }

    fn collect(&mut self, addr: &A) {
        let Some(conn) = self.conns.get_mut(addr) else {
            return;
        };
        // Hand recycled buffers back to the connection, as many as its recent
        // traffic actually asked for: too few and a crowded arena allocates a
        // buffer per relayed packet, too many and idle connections hoard them.
        let p = conn.pool_mut();
        let target = p.refill_target(CONN_REFILL, CONN_REFILL_MAX);
        p.refill_from(&mut self.pool, target);
        while let Some(d) = conn.poll_transmit() {
            self.raw_out.push_back((addr.clone(), d));
        }
        while let Some(e) = conn.poll_event() {
            self.events.push_back((addr.clone(), e));
        }
    }

    /// Runs every connection's timers and packs output; closed connections are
    /// removed after their final datagrams are queued.
    pub fn tick(&mut self, now: u64) {
        let mut addrs = std::mem::take(&mut self.scratch);
        addrs.clear();
        addrs.extend(self.conns.keys().cloned());
        for a in &addrs {
            if let Some(c) = self.conns.get_mut(a) {
                c.tick(now);
            }
            self.collect(a);
            if self.conns.get(a).is_some_and(Connection::is_closed) {
                self.conns.remove(a);
            }
        }
        self.scratch = addrs;
    }

    /// Returns a buffer from [`Server::poll_transmit`] or an [`Event::Packet`] for
    /// reuse. Recycling every buffer keeps the server free of per-packet
    /// allocations once warmed up.
    pub fn recycle(&mut self, buf: Vec<u8>) {
        // Every connection's datagrams and packets come back through here, so
        // the shared pool must hold about one tick's worth for all of them.
        let limit = SHARED_POOL_MIN.max(self.conns.len() * SHARED_POOL_PER_CONN);
        self.pool.put_bounded(buf, limit);
    }

    /// Queues a packet to one connection (see [`Connection::send`]).
    pub fn send(&mut self, to: &A, packet: &[u8], reliable: bool) -> bool {
        match self.conns.get_mut(to) {
            Some(c) => {
                c.send(packet, reliable);
                true
            }
            None => false,
        }
    }

    /// Queues a packet with explicit delivery options (see
    /// [`Connection::send_with`]).
    pub fn send_with(&mut self, to: &A, packet: &[u8], flags: crate::SendFlags) -> bool {
        match self.conns.get_mut(to) {
            Some(c) => {
                c.send_with(packet, flags);
                true
            }
            None => false,
        }
    }

    /// Access to a connection (to send, start sized transfers, read stats...).
    /// Output it produces is collected on the next [`Server::tick`] or datagram.
    pub fn connection_mut(&mut self, addr: &A) -> Option<&mut Connection> {
        self.conns.get_mut(addr)
    }

    /// Read access to a connection.
    pub fn connection(&self, addr: &A) -> Option<&Connection> {
        self.conns.get(addr)
    }

    /// Addresses of all connections.
    pub fn addresses(&self) -> impl Iterator<Item = &A> {
        self.conns.keys()
    }

    /// Number of connections.
    pub fn len(&self) -> usize {
        self.conns.len()
    }

    /// Whether there are no connections.
    pub fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    /// Disconnects a peer (sends `00 07`); it is removed on the next tick.
    pub fn disconnect(&mut self, addr: &A) {
        if let Some(c) = self.conns.get_mut(addr) {
            c.disconnect();
        }
        self.collect(addr);
        self.conns.remove(addr);
    }

    /// Next datagram to send and its destination.
    pub fn poll_transmit(&mut self) -> Option<(A, Vec<u8>)> {
        self.raw_out.pop_front()
    }

    /// Next event and the connection it came from.
    pub fn poll_event(&mut self) -> Option<(A, Event)> {
        self.events.pop_front()
    }
}

impl Connection {
    pub(crate) fn note_received(&mut self, now: u64, len: usize) {
        self.note_recv(now, len);
    }

    pub(crate) fn rekey(&mut self, cipher: Box<dyn crate::cipher::Cipher>, now: u64) {
        self.set_cipher(cipher, now);
    }

    pub(crate) fn close_for_reconnect(&mut self) {
        self.close_with(DisconnectReason::Reconnect);
    }
}
