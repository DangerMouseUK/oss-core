# Transport performance: the soak harness

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Harness: `crates/oss-net/examples/soak.rs`.

The project's budget is **500 players in one arena using under 20% of one CPU core** on the server. The soak harness measures the share of that budget taken by the transport, `oss-net`: connection handling, reliability, clustering, encryption and buffer management for every player.

## Running it

```sh
cargo run --release -p oss-net --example soak -- --peers 500 --seconds 60
cargo run --release -p oss-net --example soak -- --peers 500 --seconds 60 --cipher opensec --json
cargo run --release -p oss-net --example soak -- --help
```

Always build with `--release`.

**Exit status.** The harness exits with status 1 if any reliable packet was lost, or if `--max-cpu PCT` is given and the server needs more than that share of a core. CI uses `--max-cpu 20` as a budget check.

**Reproducibility.** Everything runs in one thread on a simulated clock. Each direction of each player's link has its own seeded random stream, so the same arguments produce identical traffic and identical packet, datagram and delivery counts on any machine. Only the timings vary with the hardware.

## The scenario

| Option | Default | Meaning |
|---|---|---|
| `--peers` | 500 | players connected at once (joins are staggered over the first 2 s) |
| `--seconds` / `--warmup` | 60 / 5 | measured period, after an unmeasured warm-up |
| `--loss` | 2 | % of datagrams lost, each direction |
| `--latency` / `--jitter` | 40 / 10 | one-way delay in ms, plus a uniform random 0..jitter (which reorders datagrams) |
| `--position-ms` | 100 | each player sends a 22-byte position packet this often (unreliable) |
| `--fanout` | 30 | the server relays each position, as a 16-byte S2C `0x28`, to this many other players (unreliable, droppable) |
| `--chat-interval` | 60000 | each player sends a reliable chat this often; the server broadcasts it reliably to everyone |
| `--churn-ms` | 1000 | every interval one player leaves and a new one joins. Half leave with `00 07`; half vanish and must time out |
| `--cipher` | `vie` | `none`, `vie` or `opensec` |
| `--seed` | 1 | random seed |

**What a fan-out of 30 means.** SubSpace servers don't send every player's position to everyone: far-away players are updated rarely or not at all. A fan-out of 30 at 10 Hz approximates a crowded arena, where each player sees about 30 others. A real server's arena logic, such as radar range and weapon relay, is not simulated. Only the transport cost of the resulting traffic is measured.

## What is measured

**Server CPU.** This is the wall-clock time spent in the server's step, divided by the simulated duration: the fraction of one core a real server would spend on this work. The step covers:

- `Server::handle_datagram` for every incoming datagram;
- `Server::tick` every 10 ms;
- draining events, relaying positions and broadcasting chat;
- `poll_transmit`;
- recycling buffers.

The relay logic is a few lines; nearly all of the time is transport. The simulated clients and network are not timed.

**Cost per game packet.** Server time divided by game packets in plus out.

**Server heap.** A global allocator wrapper attributes allocations made inside `oss-net` calls to the server. The output reports:

- live server heap at the end of the run;
- that heap divided by the number of connections;
- growth during the measured period;
- allocations per second during it.

Buffers the server hands out are recycled straight back, so they stay attributed to it.

**Reliable delivery.** For every player present for the whole measured period, every chat the server queued must arrive in order. After the measured period, traffic stops for a 10 s drain.

- Chats still queued on the server at the end are reported separately: a saturated link, not a loss.
- Players the server disconnected are reported with the disconnect reason.

## Results

Measured on 2026-11-08: Intel Core i9-7980XE at 2.6 GHz (4 cores visible), Windows 11, Rust 1.99.1, release build, default options unless noted. The workspace builds with the portable Poly1305 backend (see [OpenSec](#opensec)).

| Players | Cipher | Server CPU (% of a core) | ns per packet | Game packets in / out per s | Datagrams out per s | Out (Mbit/s) | Server heap per player | Allocations per s |
|---|---|---|---|---|---|---|---|---|
| 100 | VIE | 0.4 | 132 | 982 / 29,588 | 10,624 | 4.2 | 16.4 KB | 66 |
| 250 | VIE | 1.2 | 155 | 2,455 / 74,592 | 25,006 | 10.6 | 16.3 KB | 95 |
| **500** | **VIE** | **2.9** | **184** | 4,910 / 151,348 | 49,064 | 21.7 | 16.6 KB | 145 |
| 500 | none | 3.0 | 190 | 4,910 / 151,348 | 49,064 | 21.7 | 16.1 KB | 145 |
| 500 | OpenSec | 5.3 | 336 | 4,909 / 151,305 | 49,007 | 30.0 | 16.3 KB | 144 |
| 500 | OpenSec, crate defaults (see below) | 11.5 | 738 | 4,909 / 151,305 | 49,007 | 30.0 | 16.3 KB | 144 |
| 500 | VIE, no loss, jitter or churn | 2.8 | 176 | 5,008 / 154,167 | 48,412 | 22.0 | 16.5 KB | 29 |
| 1,000 | VIE | 7.2 | 225 | 9,818 / 310,926 | 96,940 | 45.6 | 18.0 KB | 320 |
| 1,000 | OpenSec | 12.4 | 387 | 9,816 / 310,849 | 96,934 | 61.8 | 17.6 KB | 326 |

Every run lost no reliable packets.

The VIE and unencrypted rows differ only by measurement noise; VIE is a few XORs per byte. Most of the allocations come from churn, since each new connection allocates its state. Without churn, about 30 per second remain, from reliable broadcast bursts.

**Reading the numbers against the budget:**

- The transport for 500 players takes about **3% of a core with VIE** and **5% with OpenSec**, leaving roughly 17% and 15% of the 20% budget for game logic.
- OpenSec's extra cost is one ChaCha20-Poly1305 operation per datagram: about 57,000 a second at 500 players. See [OpenSec](#opensec).
- Cost per packet grows slowly with player count (132 to 225 ns), mainly from cache pressure as connection state grows.

**Overload.** With a reliable chat from each of 1,000 players every 10 s, every client must receive 100 reliable packets a second. Add 10% loss and 40-90 ms delay, and some links cannot keep up. The server then disconnects them with `QueueOverflow` (the `max_queue` limit), as designed: no packet is lost for players who stay connected. Command to reproduce:

```sh
cargo run --release -p oss-net --example soak -- --peers 1000 --loss 10 --jitter 50 --chat-interval 10000 --churn-ms 200
```

`Connection::queued_reliable()` exposes the backlog, so servers can apply back-pressure before a link reaches that limit.

## Change found by the harness

The first 500-player run showed about 27,700 allocations per second where the hot path should have none. Two limits caused it:

- the server's shared buffer pool was capped at 256 buffers, below one tick's worth of datagrams for 500 players;
- connections were topped up with only a few buffers, too few for bursts.

The shared pool now scales with the number of connections (8 buffers each), and connections are topped up to 16. Allocations fell to under 150 per second with churn and about 30 without, and CPU dropped by about 10%.

## OpenSec

OpenSec seals every datagram with ChaCha20-Poly1305 (RustCrypto's `chacha20poly1305` 0.11). VIE costs a few XORs per byte, so OpenSec is the largest single cost in the transport. Benchmarks: `cargo bench -p oss-net -- opensec`.

**What was checked:**

- **Per-connection state is cached.** Each connection keeps one keyed cipher per direction, built at the handshake. Per datagram, only what ChaCha20-Poly1305 itself requires is derived: the nonce from the counter, a one-block Poly1305 key, the encryption and the tag.
- **Our wrapper is cheap.** It inserts the 5-byte header, appends the tag and checks the replay window. The bare AEAD call on a 16-byte record costs 290 ns; through `OpenSecCipher` it costs 325 ns.
- **The backend matters most.** On x86, `poly1305` 0.9 switches to an AVX2 implementation at run time. Unless the whole build targets AVX2, that path is about three times slower for game-sized records than the crate's portable backend. `chacha20` also selects AVX2 or SSE2 at run time, and its choice makes little difference at these sizes.

| Seal one record (this CPU) | 16 bytes | 64 bytes | 256 bytes | 491 bytes |
|---|---|---|---|---|
| crate defaults (AVX2 Poly1305 chosen at run time) | 1.07 µs | 1.38 µs | 1.53 µs | 2.02 µs |
| `--cfg poly1305_backend="soft"` (portable Poly1305) | 0.33 µs | 0.35 µs | 0.53 µs | 1.08 µs |
| `-C target-cpu=x86-64-v3` (AVX2 at compile time) | 0.34 µs | — | — | 0.91 µs |

Opening a record costs about the same as sealing it.

| Whole server, 500 players | Server CPU | ns per packet |
|---|---|---|
| VIE | 2.8% | 178 |
| OpenSec, crate defaults | 11.1–11.6% | 708–743 |
| OpenSec, `--cfg poly1305_backend="soft"` | 5.3% | 336 |
| OpenSec, `-C target-cpu=x86-64-v3` | 5.5% | 353 |

**What this repository does.** `.cargo/config.toml` selects the portable Poly1305 backend on x86, so tests, benchmarks and the soak harness are built with it. That setting only applies inside this repository. Crates that depend on `oss-net` need it in their own build.

**What a zone operator should do.** Build the server with one of these:

- `--cfg poly1305_backend="soft"`: runs on any x86-64 CPU and is the recommended default. For example, in the server repository's `.cargo/config.toml`:

  ```toml
  [target.'cfg(any(target_arch = "x86", target_arch = "x86_64"))']
  rustflags = ["--cfg", 'poly1305_backend="soft"']
  ```

  (A `RUSTFLAGS` environment variable replaces config-file flags, so add it there too if you use one.)
- `-C target-cpu=x86-64-v3`: slightly faster for full datagrams, but the binary then needs an AVX2 CPU (Intel Haswell or AMD Excavator, 2013–2015, and later).

**What to expect.** With either setting, OpenSec costs about **5% of a core for 500 players** and **12% for 1,000**, against 3% and 7% for VIE, on this 2.6 GHz desktop CPU. Expect roughly proportional figures on other x86 servers. ARM servers (for example AWS Graviton) use portable Poly1305 and NEON ChaCha20 by default; they have not been measured here.

**This is close to the floor** for this crate: about 0.3 µs for a small record and 1 µs for a full one. Further options, none of them done yet:

- **Fewer records:** flushing every 20 ms instead of 10 ms would pack about twice as many packets into each datagram, but adds 5 ms of average delay to positions.
- **A faster backend:** an assembly-backed crate such as `ring` or `aws-lc-rs` could replace the record cipher behind the same `Cipher` trait. It would cost portability (wasm) and add C or assembly dependencies.
- **An upstream fix** in `poly1305`, so its run-time AVX2 path is no longer slower than the portable one.
