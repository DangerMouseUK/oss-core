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

**Exit status.** The harness exits with status 1 if any reliable packet was lost, or if `--max-cpu PCT` is given and the server needs more than that share of a core. CI's `soak` job runs two: the default fan-out at `--max-cpu 20`, and `--fanout 82 --max-cpu 12`, the whole-map case ASSS's relay rules really produce. The crowded case (`--fanout 350`) is not gated, because it does not currently fit the budget; gating it would mean choosing a threshold it fails.

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

**What the fan-out means.** SubSpace servers don't send every player's position to everyone: far-away players are updated rarely or not at all. A real server's arena logic, such as radar range and weapon relay, is not simulated here; only the transport cost of the resulting traffic is measured.

The default of 30 is a smoke-test value, not a crowded arena. Running oss-server's zone harness against the real ASSS relay rules (`oss-server/docs/performance.md`) gives, for 500 players all in ships, about **82** recipients per position over a whole map, **210** over half of it and **350** over a quarter. Those are the fan-outs to use when asking whether the budget closes; see [Fan-out](#fan-out-what-asss-relay-rules-cost) below.

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

Measured on 2026-11-08: Intel Core i9-7980XE at 2.6 GHz (4 cores visible), Windows 11, Rust 1.99.1, release build, default options. The workspace builds with the portable Poly1305 backend (see [OpenSec](#opensec)). Each run took 60 simulated seconds; repeated runs of the same configuration vary by up to about 10% in CPU time.

**Server CPU** (% of one core), with nanoseconds per game packet in brackets:

| Players | No encryption | VIE | OpenSec | OpenSec with `opensec-ring` |
|---|---|---|---|---|
| 100 | 0.4 (117) | 0.4 (134) | 0.9 (298) | 0.6 (202) |
| 250 | 1.0 (135) | 1.2 (151) | 2.5 (321) | 1.9 (243) |
| **500** | 2.6 (165) | **2.8 (178)** | **5.3 (342)** | **4.2 (268)** |
| 1,000 | 6.3 (197) | 8.1 (252) | 13.2 (412) | 10.6 (329) |

**Traffic and memory**, which are the same for every cipher apart from OpenSec's 21 bytes per datagram:

| Players | Game packets in / out per s | Datagrams out per s | Out (Mbit/s), VIE / OpenSec | Server heap per player | Allocations per s |
|---|---|---|---|---|---|
| 100 | 982 / 29,588 | 10,624 | 4.2 / 6.0 | 16–17 KB | 66 |
| 250 | 2,455 / 74,592 | 25,006 | 10.6 / 14.8 | 16–17 KB | 95 |
| 500 | 4,910 / 151,348 | 49,064 | 21.7 / 30.0 | 16–17 KB | 145 |
| 1,000 | 9,818 / 310,926 | 96,940 | 45.6 / 61.8 | 18–19 KB | 320 |

Every run lost no reliable packets. Most of the allocations come from churn, since each new connection allocates its state. Without churn, loss or jitter, VIE at 500 players makes about 28 allocations per second (from reliable broadcast bursts) and uses 2.7% of a core.

### Fan-out: what ASSS relay rules cost

Measured 2026-11-12 on the machine above, 500 players, VIE, 60 s. **The machine was not idle** (see [Measuring under load](#measuring-under-load)), so every figure is the median of three runs, each immediately preceded by its own `--fanout 30` control run, and the whole set was taken twice: once with the machine at 99% busy and again at 51%, after two of the competing jobs stopped.

| Fan-out | Arena it represents | Server CPU | busy / quiet medians | ns per packet | Packets out per s | Datagrams out per s | Packets per datagram |
|---|---|---|---|---|---|---|---|
| 30 | smoke test (control) | 2.9% | 2.94 / 2.91 | 187–189 | 151,348 | 49,064 | 3.1 |
| **82** | **whole map** | **5.3%** | 5.30 / 5.34 | 127–136 | 406,135 | 51,142 | 7.9 |
| **210** | **half the map** | **11.6%** | 11.71 / 11.63 | 112–115 | 1,033,675 | 51,676 | 20.0 |
| **350** | **a quarter of it** | **19.6%** | 20.02 / 19.59 | 114–119 | 1,719,773 | 87,825 | 19.6 |

The two conditions agree to within 2%, and the control itself barely moved (2.94% against 2.91%) across a load change from 99% to 51%. A single-threaded harness gets a core either way; what the load actually produces is the occasional burst swallowing a whole run, not a steady tax. That is why the method is a control beside every run rather than a quiet machine. The traffic columns are load-independent in any case: the harness is deterministic, so those counts are identical on any machine.

**Cost per packet falls as fan-out rises**, from about 180 ns to about 120 ns, because clustering packs more packets into each datagram. From fan-out 30 to 82 the packet rate rises 2.7 times while the datagram rate rises 4%: the extra packets ride in datagrams that were being sent anyway. Clustering saturates at about 20 packets per datagram (a full VIE datagram of 16-byte position packets), after which datagrams grow with packets again — which is why 350 is no cheaper per packet than 210.

So the estimate in oss-server's doc, which multiplied 1.8M packets/s by the fan-out-30 cost of 178 ns and got roughly 32% of a core, was **pessimistic by about half**. The measured figure is 19.6% (19.39–20.60 across both load conditions). That is essentially the whole budget, for the transport alone, with the game logic still to pay for.

With OpenSec instead of VIE, the same paired-control method gives 8.5% (fan-out 82), 16.0% (210) and 27.5% (350).

**Allocations.** At fan-out 210 and above the server used to allocate on the hot path again: 5,913/s at 210 and 28,348/s at 350, against 145/s at fan-out 30. **Fixed on 2026-11-13** by making the connection top-up target follow demand (see [Change found by the harness](#change-found-by-the-harness)); the same runs now give 172/s at 210 and 189/s at 350, which is the churn floor.

Two things are worth recording about how that was found, because both were wrong in the obvious direction:

- **It was not the shared pool.** The natural reading — one tick at fan-out 350 queues about 17,000 packets against a shared pool limited to 8 per connection, so 4,000 at 500 players — is not the mechanism. Raising `SHARED_POOL_PER_CONN` from 8 to 32 and then 64 moved the rate from 28,348/s to 27,868/s both times, a 1.7% change. Raising the per-connection top-up from 16 to 64 moved it to 206/s. A probe counting allocations by size and sampling their stacks put 99.8% of them at exactly `BUF_CAPACITY` (576 bytes) and three-quarters of those under `Connection::send_with`, where a relayed position is copied into a buffer the connection no longer has.
- **The allocations were not costing much CPU.** The guess here used to be that some of the 19.6% was allocation traffic and the figure would improve once the pool was sized for it. It did not: against a fan-out-30 control that matched the earlier run to 0.3%, fan-out 350 came back at 18.88% where the baseline runs gave 20.22–22.83%. That is within what this machine does to a single run, so the honest summary is that removing 28,000 allocations a second changed CPU by less than the noise. The cost it removes is allocator pressure and jitter, not percent of a core.

### Measuring under load

These figures were taken on a shared desktop running an unrelated six-thread job (about 5.85 of 8 logical cores) plus two other build-and-test sessions; the machine reported 99% busy. That is disclosed rather than hidden because it changes how the numbers should be read.

The method was to pair every measurement with a `--fanout 30` control run immediately before it, and to use the control as a load probe: the harness is deterministic, so the control's *traffic* is fixed and only its *timing* moves. It earned its keep. In one interleaved sequence a control came back at 5.55% / 355 ns, nearly double its neighbours (2.92–2.96%), which is a burst landing inside a single 60-second run. A lone control taken at the start of a session would not have caught that, and the run beside it would have been published as a measurement.

Repeating the whole set after two of the competing jobs stopped (99% busy down to 51%) moved every figure by under 2%, and moved the control by 0.03 points. So the figures are not artefacts of a loaded box; the load shows up as rare bursts inside individual runs, which pairing catches, rather than as a steady offset. Memory is worth a glance too, not just CPU: this machine has 18 GB, and a sibling job's 9.8 GB working set earlier in the day would have contended for bandwidth in a way CI never will.

Figures to rely on should still come from the CI `soak` job, where the runner is clean. The numbers here are good to a few percent, which is enough to locate the cliff and set a gate.

**Reading the numbers against the 20% budget:**

| Encryption | 500 players | 1,000 players |
|---|---|---|
| VIE | 3% | 8% |
| OpenSec (portable build) | 5% | 13% |
| OpenSec with `opensec-ring` | 4% | 11% |

Those are fan-out-30 figures, so they are a floor, not the budget case. At the fan-out ASSS really produces the transport takes 5.3% (whole map), 11.6% (half) or 19.6% (a quarter) with VIE. The rest of the budget is left for game logic, which oss-server measures at 6.4–7.5% for the same arenas — so the two halves fit under 20% over a whole map (about 12%), sit at about 18% over half of it, and reach about 27% in a quarter. See oss-server's `docs/performance.md` for the combined table. Cost per packet grows with player count (165 to 197 ns unencrypted), mainly from cache pressure as connection state grows.

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

**The second, 2026-11-13: the top-up of 16 was itself a fan-out-30 number.** A connection takes one pooled buffer per packet queued into it and gets them back only when it flushes, so its demand over a tick is the fan-out, not a constant. At 500 players and ASSS's quarter-map fan-out that is about 36 buffers per connection per tick against a top-up of 16, and the shortfall is allocated. Sweeping fan-out puts the knee where that predicts: demand per connection per tick of 3.1 (fan-out 30) costs 146 allocations/s, 11.1 costs 567, 15.5 costs 3,112, and 35.8 costs 28,348.

A bigger constant is the wrong fix, because it is paid by every connection: a flat 64 holds the crowded case at 206/s but takes heap per player from 16.6 KB to 59.4 KB in an *empty* arena, and a flat 128 is worse on both counts (329/s, 98.0 KB). So the target now follows each connection's own recent demand — it rises to a new peak at once and decays by an eighth per top-up, with the old 16 as the floor an idle connection keeps and 256 as the cap. Allocations per second, 500 players, before and after:

| Fan-out | 30 | 82 | 210 | 350 |
|---|---|---|---|---|
| Before | 146 | — | 5,913 | 28,348 |
| After | 146 | 148 | 172 | 189 |
| Heap per player, before | 16.6 KB | — | 29.2 KB | 35.3 KB |
| Heap per player, after | 16.6 KB | 21.0 KB | 37.2 KB | 52.6 KB |

An idle arena pays nothing for this and a crowded one pays about 17 KB per player, which is the cost of holding the buffers its own traffic needs. `tests/alloc_free_crowded.rs` guards it: `alloc_free.rs` sends a handful of packets per tick, which fits under any plausible floor, so it could never have caught this.

## OpenSec

OpenSec seals every datagram with ChaCha20-Poly1305. VIE costs a few XORs per byte, so OpenSec is the largest single cost in the transport. Benchmarks: `cargo bench -p oss-net -- opensec`. Add `--features opensec-ring` to measure the `ring` backend.

### Why this repository uses the portable Poly1305 (don't "fix" it)

`.cargo/config.toml` builds the `poly1305` crate with its **portable** backend on x86 (`--cfg poly1305_backend="soft"`). That looks backwards, since the crate ships an AVX2 backend, but for game traffic the AVX2 backend is about three times slower:

- `poly1305` 0.9 picks AVX2 *at run time* when the binary was not compiled for AVX2, which is the normal case for portable x86-64 builds.
- That path costs about 0.75 µs per message on top of the useful work. Records here are 16 to 512 bytes, so the overhead dominates. The likely cause is per-message setup and calls into AVX2 functions the compiler cannot inline into the rest of the build. We measured the effect, not the mechanism.
- The AVX2 code would only pay off on messages of kilobytes, which this protocol never sends.
- When the whole build targets AVX2 (`-C target-cpu=x86-64-v3`), the penalty disappears and both backends cost the same.

So removing the setting, or "upgrading" to the AVX2 backend, would roughly double OpenSec's cost. If a future `poly1305` release changes this, re-measure with the benchmark above before changing anything.

### What was measured

Time to seal one record on this CPU:

| Implementation | 16 bytes | 64 bytes | 256 bytes | 491 bytes |
|---|---|---|---|---|
| RustCrypto, crate defaults (AVX2 Poly1305 chosen at run time) | 1,070 ns | 1,380 ns | 1,530 ns | 2,020 ns |
| RustCrypto, portable Poly1305 (**this repository's default**) | 325 ns | 353 ns | 533 ns | 1,084 ns |
| RustCrypto, `-C target-cpu=x86-64-v3` | 340 ns | — | — | 910 ns |
| `ring` (assembly), through `OpenSecCipher` (feature `opensec-ring`) | 189 ns | 198 ns | 297 ns | 428 ns |
| `ring` (assembly), bare ChaCha20-Poly1305 | 141 ns | 151 ns | 253 ns | 372 ns |
| For comparison, not usable by OpenSec: AES-256-GCM, `ring` | 93 ns | 109 ns | 163 ns | 272 ns |

Opening a record costs about the same as sealing it. Other things checked:

- **Per-connection state is cached.** Each connection keeps one keyed cipher per direction, built at the handshake. Per datagram, only what ChaCha20-Poly1305 itself requires is derived: the nonce from the counter, a one-block Poly1305 key, the encryption and the tag.
- **Our wrapper is cheap.** It inserts the 5-byte header, appends the tag and checks the replay window: about 30–50 ns on top of the cipher.
- **The ChaCha20 backend hardly matters at these sizes.** `chacha20` itself selects AVX2 or SSE2 at run time, and forcing SSE2, AVX2 or the portable code changed small-record times by under 5%.

### Is the remaining gap the floor?

Not for the portable build. `ring`'s assembly implementation of the same algorithm is two to three times faster per record, which brings OpenSec at 500 players from 5.3% to 4.2% of a core.

With `ring`, the remaining gap to VIE is 1.4 points at 500 players. That is close to the floor for ChaCha20-Poly1305 on this CPU: about 0.15 µs for a small record and 0.37 µs for a full one, roughly 57,000 times a second. AES-GCM would be a little cheaper still on CPUs with AES instructions, but OpenSec's specification fixes ChaCha20-Poly1305, which is constant-time everywhere without special hardware.

Reducing the number of records is the only other lever. Flushing every 20 ms instead of 10 ms would pack about twice as many packets into each datagram, but adds 5 ms of average delay to positions.

### What a zone operator should do and budget

1. **Keep the portable Poly1305** in the server's own build. Crates that depend on `oss-net` don't inherit this repository's `.cargo/config.toml`. In the server repository's `.cargo/config.toml`:

   ```toml
   [target.'cfg(any(target_arch = "x86", target_arch = "x86_64"))']
   rustflags = ["--cfg", 'poly1305_backend="soft"']
   ```

   A `RUSTFLAGS` environment variable replaces config-file flags, so add it there too if you use one. Alternatively, build with `-C target-cpu=x86-64-v3`, but the binary then needs an AVX2 CPU (Intel Haswell or AMD Excavator, 2013–2015, and later).
2. **Optionally enable `opensec-ring`** (`oss-net` feature) for servers. It saves about a fifth of the transport's CPU time with OpenSec. It needs a C compiler at build time and is not for wasm builds.
   - It compiles to exactly the same wire format: both backends produce the published OpenSec vectors byte for byte.
   - It isn't the default because `oss-net` otherwise stays pure Rust.
3. **Budget**, on a CPU like this 2.6 GHz desktop:

   | Encryption | 500 players | 1,000 players |
   |---|---|---|
   | VIE | 3% of a core | 8% |
   | OpenSec | 5% | 13% |
   | OpenSec with `opensec-ring` | 4% | 11% |

   For other loads, the transport costs about 0.2 µs per game packet with VIE. OpenSec adds, per datagram in or out, about 0.3–1.1 µs (portable) or 0.2–0.4 µs (`ring`), depending on datagram size. Datagrams average about 60 bytes in this scenario.
4. **ARM servers** (for example AWS Graviton) use the portable Poly1305 and NEON ChaCha20 by default; they have not been measured here.
