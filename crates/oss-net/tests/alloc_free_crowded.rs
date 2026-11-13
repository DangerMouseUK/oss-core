//! The same promise as `alloc_free.rs` -- a warmed-up connection whose caller
//! recycles buffers must not allocate per packet -- at the volume a crowded
//! arena really produces.
//!
//! `alloc_free.rs` sends a handful of packets per tick, which fits in the
//! buffers a connection is topped up to whatever that floor is, so it cannot
//! see a top-up target that is too small. Here the server pushes a fan-out's
//! worth of relayed positions into one connection every tick, which is what
//! made the transport allocate about 28,000 times a second at 500 players
//! (measured 2026-11-12, `docs/performance.md`).
//!
//! This test counts heap allocations with a wrapping global allocator, so it
//! is the only test in this binary and nothing else allocates concurrently.

// A global allocator wrapper needs `unsafe`; it only forwards to `System`.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

use oss_net::{
    Config, Connection, Event, Priority, SendFlags, Server, VieAcceptor, VieClientHandshake,
};

struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const ADDR: u32 = 1;

/// Relayed positions pushed into the connection each tick. Comfortably above
/// the idle top-up floor, as a crowded arena is: 500 players at ASSS's
/// quarter-map fan-out put about 36 packets per tick into each connection.
const BURST: usize = 40;

struct Crowd {
    client: Connection,
    server: Server<u32>,
    relayed: u64,
}

impl Crowd {
    fn new() -> Self {
        let mut server = Server::new(Config::server());
        server.add_acceptor(Box::new(VieAcceptor::default()));
        let client = Connection::client(Config::client(), Box::new(VieClientHandshake::new(9)), 0);
        let mut c = Self {
            client,
            server,
            relayed: 0,
        };
        c.step(0);
        c.step(10);
        assert!(c.client.is_connected(), "handshake completed");
        c
    }

    /// One 10 ms tick: the server relays `BURST` positions to the connection,
    /// the client sends its own, everything is delivered and every buffer is
    /// recycled.
    fn step(&mut self, now: u64) {
        let position = [0x03u8; 22];
        let relayed = [0x28u8; 16];
        if self.client.is_connected() {
            self.client.send(&position, false);
            // How a zone server relays: unreliable, droppable, normal priority.
            let flags = SendFlags {
                reliable: false,
                priority: Priority::Normal,
                droppable: true,
            };
            for _ in 0..BURST {
                self.server.send_with(&ADDR, &relayed, flags);
                self.relayed += 1;
            }
        }
        self.client.tick(now);
        self.server.tick(now);
        for _ in 0..4 {
            while let Some(d) = self.client.poll_transmit() {
                self.server.handle_datagram(now, ADDR, &d);
                self.client.recycle(d);
            }
            while let Some((_, d)) = self.server.poll_transmit() {
                self.client.handle_datagram(now, &d);
                self.server.recycle(d);
            }
            self.client.flush(now);
            self.server.tick(now);
        }
        while let Some(e) = self.client.poll_event() {
            if let Event::Packet(p) = e {
                self.client.recycle(p);
            }
        }
        while let Some((_, e)) = self.server.poll_event() {
            if let Event::Packet(p) = e {
                self.server.recycle(p);
            }
        }
    }
}

#[test]
fn crowded_connection_does_not_allocate() {
    let mut crowd = Crowd::new();
    let mut now = 20;
    // Warm up: pools reach the working size this much traffic needs.
    for _ in 0..3_000 {
        crowd.step(now);
        now += 10;
    }
    let before_relayed = crowd.relayed;
    let before = ALLOCS.load(Ordering::Relaxed);
    for _ in 0..3_000 {
        crowd.step(now);
        now += 10;
    }
    let allocs = ALLOCS.load(Ordering::Relaxed) - before;
    let relayed = crowd.relayed - before_relayed;
    assert_eq!(
        relayed,
        BURST as u64 * 3_000,
        "the burst really was queued every tick"
    );
    assert_eq!(
        allocs, 0,
        "{allocs} allocations for {relayed} relayed packets in steady state"
    );
}
