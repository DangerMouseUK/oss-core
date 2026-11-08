# Transport (core `0x00` packets)

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-proto::control` (wire shapes) and `oss-net` (behaviour). Evidence for each part: [verification.md](verification.md).

SubSpace runs over UDP. Every datagram is either a **game packet**, whose first byte is a non-zero type, or a **core packet**: `0x00` followed by a subtype byte. The core layer adds connection setup, reliable in-order delivery, packing of several packets into one datagram, transfers larger than a datagram, and clock sync. Both ends implement all of it, apart from setup, which is asymmetric.

Integers are little-endian. A *tick* is 1/100 s. Server clocks are 31-bit tick counters and wrap at 2^31.

## Packet catalogue

| Subtype | Name | Layout after `00 tt` | Length | Notes |
|---|---|---|---|---|
| `01` | connect | `u32 key, u16 protocol` | 8 | `protocol` 0x0001 = SubSpace (VIE), 0x0011 = Continuum. Byte 7 must be 0. Never encrypted. |
| `02` | connect response | `u32 key` [`u8` extra] | 6 (7) | Servers send 6 bytes; accept 6 or more and ignore any extra byte. |
| `03` | reliable | `i32 seq, payload` | ≥ 7 | The payload is one complete packet (game or core). |
| `04` | ack | `i32 seq` | 6 | One per received reliable. |
| `05` | sync request | `u32 time` [`u32 sent, u32 received`] | 14 (6) | Clients send the 14-byte form. |
| `06` | sync response | `u32 echoed time, u32 responder time` | 10 | |
| `07` | disconnect | — | 2 | |
| `08` | big data, more follows | slice | ≥ 3 | Always carried in a reliable. |
| `09` | big data, last slice | slice | ≥ 3 | |
| `0A` | sized data | `i32 total, slice` | ≥ 7 | Always carried in a reliable. |
| `0B` | sized cancel | — | 2 | |
| `0C` | sized cancel ack | — | 2 | |
| `0D` | no-op | — | 2? | Ignore. |
| `0E` | cluster | (`u8 len, packet`)* | ≥ 4 | |
| `0F` | unknown | | | Ignore. |
| `10`–`13` | Continuum key exchange | | | See [encryption](encryption.md). |
| `14` | timer-mode switch | `u8 0x41, u8 on` | 4 | Sent by one modern server only. Ignore. |

A core datagram shorter than 2 bytes, or a packet that fails its length check, is dropped silently.

## Connection setup

1. The client sends `00 01` with its key and protocol word. It resends about once a second until it gets an answer, and gives up after about 10 s.
2. The server recognises a new connection only from a `00 01` (or, for Continuum, `00 11`) arriving from an unknown address. It ignores anything else from unknown addresses and sends no reply.
3. The server's encryption handler validates the request, creates the connection, sends a raw `00 02` with its key, and keys its cipher. A VIE server answers with the negated client key. An unencrypted server echoes the client's key back.
4. If the server has no free slot, it answers with a raw `00 07` instead.
5. The client keys its cipher from the `00 02` it receives. A key equal to its own key, or a key of 0, means no encryption. The client then logs in, which is game-level traffic.

A repeated `00 01` from a known address is handled in one of two ways:

- **No session traffic yet** (the server's `00 02` was lost): answer again and re-key. Sequence numbers and queued data are kept.
- **Session already established**: end the old connection and drop the request. The client keeps retrying until the old connection has gone.

Continuum uses extra setup steps (`00 10`, `00 11`), described in [encryption](encryption.md).

## Reliable delivery

- Each direction has its own sequence counter. It starts at 0, increases by one per reliable datagram, and is signed (negative values are invalid).
- **Receiving `00 03`**: if `seq − expected ≥ window` (32 on servers), drop it **without** acking; the sender will retransmit. Otherwise ack it, even if it is a duplicate or was already delivered. Store it, then deliver stored payloads strictly in order. Each delivered payload is processed as a complete packet, and can itself be a cluster, a big-data slice, a sized chunk or another core packet. A reliable nested directly inside a reliable is rejected.
- **Acks** are not cumulative: `00 04 seq` acknowledges exactly one packet. Senders normally batch the acks from one pass into a cluster.
- **Retransmission** uses `RTO = clamp(avg + 4·dev, 250 ms, 2000 ms)`. The estimate starts at avg 200 ms and dev 100 ms, and is updated only from acks of packets sent exactly once:
  - `dev ← (3·dev + |avg − sample|) / 4`
  - `avg ← (7·avg + sample) / 8`
- Backoff is linear: a packet sent *k* times is resent once `k·RTO` has passed since its last send.
- After 15 transmissions without an ack, the connection is dropped.
- Only a limited number of reliables are in flight at once; ASSS's limit grows with its bandwidth estimate.

## Clustering (`00 0E`)

- A sender may pack several packets of up to 255 bytes each into one datagram: `00 0E`, then a length byte and the packet, repeated.
- Anything can go in a cluster, including reliables and acks. Larger packets travel alone.
- A cluster holding a single packet is sent as that packet, unwrapped. Never send a cluster with fewer than two items; some clients ignore clusters shorter than 6 bytes.
- Cap cluster datagrams at 512 bytes. ASSS stops at 503.
- **Receivers** parse items in order and process each one recursively. They stop at a zero length or at an item that runs past the end, keeping the items already parsed.
- A cluster can also be the payload of a reliable. One server packs several small reliable messages into a single sequence number this way.

## Big data (`00 08` / `00 09`)

Used for a single packet too large for one datagram: more than 506 bytes, since 6 bytes go to the reliable header.

- **Sending**: split it into 480-byte slices. Send every slice but the last as `00 08 slice` and the last as `00 09 slice`, each reliably. (ASSS's player path can send the `00 08` body slices unreliably if the caller asked for unreliable delivery; do not reproduce that.)
- **Receiving**: append each slice to a buffer. On `00 09`, the buffer is one packet.
- Cap the buffer at 65 536 bytes. On overflow, discard everything until the `00 09`, then drop the whole packet.
- A reassembled packet starting with `0x00` is invalid.
- Senders use various slice sizes (480, 500, 512), so accept any slice length of 1 or more.

## Sized transfers (`00 0A`, `00 0B`, `00 0C`)

Used to stream files: maps, LVZ, news and uploads.

**Chunks.** Every chunk is `00 0A total slice`, sent reliably. Slices are 480 bytes except the last.

**Pacing.** The sender keeps a queue of transfers and works on one at a time. Whenever fewer than 5 reliables are unacknowledged, it queues up to 25 more chunks, so other traffic is not starved.

**Receiving.** The first chunk fixes the total; its first byte is the game packet type of the data. Data is complete once `total` bytes have arrived. If a chunk carries a different total, or would overflow the total, the transfer is abandoned. Receivers should cap the total.

**Cancelling.** Implementations disagree about direction. The behaviour that works with all of them:

- **Wanting to stop an incoming stream**: discard the partial data and send `00 0B`.
- **Receiving `00 0B`**: stop the active outgoing transfer, discard any partial incoming one, and reply `00 0C` reliably.
- **Receiving `00 0C`**: discard any partial incoming transfer.

Chunks already queued are not recalled, so after cancelling, ignore stray chunks that carry the cancelled total.

## Time sync (`00 05` / `00 06`)

- **Request**: clients send `00 05 time sent received` right after connecting and then every 5–20 s.
- **Response**: the receiver answers immediately with `00 06 echoed-time own-time`. This reply bypasses clustering and bandwidth limits.
- **Packet counts**: the sent/received counts in the request let the other side estimate packet loss.
- **Clock offset**: the client computes
  - `rtt = now − echoed`
  - `offset = 3·rtt/5 + server_time − now`, treated as 0 if `|offset| ≤ 10` ticks

  Server time is then estimated as local ticks + offset. Implementations may smooth this over several samples or reject slow ones.
- **Server-initiated sync**: one modern server also sends `00 05` to clients. Clients answer it like any request.

## Disconnect and timeouts

**Disconnect.** `00 07` is unreliable and has no handshake. The sender may repeat it. When the receiver gets one, it tears the connection down.

**Servers drop a connection when:**

- nothing has been received for 30 s;
- a reliable reaches its retry limit;
- more than about 500 packets are queued for it.

**Clients:**

- Expect clients to time out on silence. Servers send a 1-byte game keep-alive (S2C `0x27`) to idle players every few seconds.
- A server's own outbound client connections give up after 10 s if nothing was ever received, or after 65 s of silence once traffic has started.

## Sizes

| Item | Value |
|---|---|
| Plaintext datagram to send | ≤ 512 bytes. ASSS reads only 512; most clients send up to 520. |
| Datagram to accept | ≤ 520 bytes plaintext (more under Continuum encryption overhead) |
| Reliable payload | ≤ 506 bytes |
| Cluster item | ≤ 255 bytes |
| Big / sized slice | 480 bytes |
| Big-data reassembly | ≤ 65 536 bytes |
| Per-datagram accounting overhead (IP + UDP) | 28 bytes |

## Encryption placement

Encryption is applied to the whole datagram as the last step before sending, after clustering and reliable framing. Decryption is the first step after the receiver has looked up the connection and checked for a connection request. `00 01` is never encrypted. See [encryption](encryption.md).
