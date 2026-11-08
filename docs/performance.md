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

Measured on 2026-11-08: Intel Core i9-7980XE at 2.6 GHz (4 cores visible), Windows 11, Rust 1.99.1, release build, default options unless noted.

| Players | Cipher | Server CPU (% of a core) | ns per packet | Game packets in / out per s | Datagrams out per s | Out (Mbit/s) | Server heap per player | Allocations per s |
|---|---|---|---|---|---|---|---|---|
| 100 | VIE | 0.4 | 132 | 982 / 29,588 | 10,624 | 4.2 | 16.4 KB | 66 |
| 250 | VIE | 1.2 | 155 | 2,455 / 74,592 | 25,006 | 10.6 | 16.3 KB | 95 |
| **500** | **VIE** | **2.9** | **184** | 4,910 / 151,348 | 49,064 | 21.7 | 16.6 KB | 145 |
| 500 | none | 3.0 | 190 | 4,910 / 151,348 | 49,064 | 21.7 | 16.1 KB | 145 |
| 500 | OpenSec | 11.5 | 738 | 4,909 / 151,305 | 49,007 | 30.0 | 16.3 KB | 144 |
| 500 | VIE, no loss, jitter or churn | 2.8 | 176 | 5,008 / 154,167 | 48,412 | 22.0 | 16.5 KB | 29 |
| 1,000 | VIE | 7.2 | 225 | 9,818 / 310,926 | 96,940 | 45.6 | 18.0 KB | 320 |

Every run lost no reliable packets.

The VIE and unencrypted rows differ only by measurement noise; VIE is a few XORs per byte. Most of the allocations come from churn, since each new connection allocates its state. Without churn, about 30 per second remain, from reliable broadcast bursts.

**Reading the numbers against the budget:**

- The transport for 500 players takes about **3% of a core with VIE** and **12% with OpenSec**. That leaves most of the 20% budget for game logic with VIE, and about 8% with OpenSec.
- OpenSec's extra cost is ChaCha20-Poly1305 over about 57,000 datagrams per second (in plus out). That is about 1.5 µs per datagram, using the portable implementation with no SIMD. It is the place to optimise if OpenSec zones get crowded. Options include batching sends per tick, or a crypto backend with SIMD.
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
