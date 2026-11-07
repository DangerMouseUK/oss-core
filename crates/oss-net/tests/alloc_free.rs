//! Once warmed up, and with callers recycling buffers, a busy connection must
//! not allocate per packet: datagrams, received payloads and events all reuse
//! pooled buffers. This test counts heap allocations with a wrapping global
//! allocator. It is the only test in this binary so nothing else allocates
//! concurrently.

// A global allocator wrapper needs `unsafe`; it only forwards to `System`.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

use oss_net::{Config, Connection, Event, Server, VieAcceptor, VieClientHandshake};

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

struct Pair {
    client: Connection,
    server: Server<u32>,
    delivered: u64,
}

impl Pair {
    fn new() -> Self {
        let mut server = Server::new(Config::server());
        server.add_acceptor(Box::new(VieAcceptor::default()));
        let client = Connection::client(Config::client(), Box::new(VieClientHandshake::new(9)), 0);
        let mut p = Self {
            client,
            server,
            delivered: 0,
        };
        p.step(0);
        p.step(10);
        assert!(p.client.is_connected());
        p
    }

    /// One 10 ms step: both sides exchange a reliable and an unreliable packet
    /// in each direction, everything is delivered without loss, and every buffer
    /// is recycled.
    fn step(&mut self, now: u64) {
        let payload = [0x07u8, 2, 0, 0, b'h', b'i', 0];
        let position = [0x03u8; 22];
        if self.client.is_connected() {
            self.client.send(&payload, true);
            self.client.send(&position, false);
            self.server.send(&ADDR, &payload, true);
            self.server.send(&ADDR, &position[..16], false);
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
                self.delivered += 1;
                self.client.recycle(p);
            }
        }
        while let Some((_, e)) = self.server.poll_event() {
            if let Event::Packet(p) = e {
                self.delivered += 1;
                self.server.recycle(p);
            }
        }
    }
}

#[test]
fn steady_state_does_not_allocate() {
    let mut pair = Pair::new();
    let mut now = 20;
    // Warm up: pools fill, queues reach their working capacity, time sync runs.
    for _ in 0..3_000 {
        pair.step(now);
        now += 10;
    }
    let before_delivered = pair.delivered;
    let before = ALLOCS.load(Ordering::Relaxed);
    for _ in 0..3_000 {
        pair.step(now);
        now += 10;
    }
    let allocs = ALLOCS.load(Ordering::Relaxed) - before;
    let delivered = pair.delivered - before_delivered;
    assert!(
        delivered >= 4 * 3_000,
        "traffic flowed: {delivered} packets"
    );
    assert_eq!(
        allocs, 0,
        "{allocs} allocations for {delivered} packets in steady state"
    );
}
