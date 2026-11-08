# Directory server protocol

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-proto::directory`. Evidence for each part: [verification.md](verification.md). Per-packet pages: [packets/](packets/README.md).

Directory servers keep a list of zones. Game servers register with them, and clients fetch the list to show a zone browser. Integers are little-endian unless stated.

## Zone registration (game server → directory, UDP port 4991)

A game server sends one plain UDP datagram about once a minute. It has no type byte, uses no transport framing, and gets no reply.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | IP: must be 0 (the directory uses the datagram's source address) |
| 4 | 2 | game port |
| 6 | 2 | players |
| 8 | 2 | score keeping: 1 if the zone has a billing server, else 0 |
| 10 | 4 | version: 134 |
| 14 | 32 | zone name, NUL-padded |
| 46 | 48 | directory password, NUL-padded |
| 94 | n | description, NUL-terminated |

Directory servers reject an update unless:

- the IP is 0;
- score keeping is 0 or 1;
- the name and description end with a NUL;
- the name is printable;
- byte 61 is 0 and bytes 62–93 are all 0. Only the first 16 bytes of the password field are used, so a password can have at most 15 characters.

**Two separate sockets.**

- **Registration socket.** It sends from any port. The reference server binds its registration socket to port 0 (an ephemeral port). Don't bind it to a particular port, and in particular not to game port + 1. The directory learns the game port from offset 4 of the payload, not from the datagram's source port.
- **Ping socket.** The zone must listen on game port + 1 and answer pings there (see [Zone ping port](#zone-ping-port-game-port--1)). The directory pings the registered port + 1 at the datagram's source *address*: dirserver's `sendPing(ip, port + 1)`.

The reference server caps the description at 385 bytes plus its NUL, so the datagram stays at most 480 bytes.

## Ping (UDP port 4991)

- **Ping:** a 4-byte datagram holding any `u32`, often a timestamp or 0. The directory recognises it by its length.
- **Pong:** an 8-byte reply. The first `u32` is informational: one directory sends its zone count, while one document describes it as the constant 1. The second `u32` echoes the ping.

Directories also ping registered zones to measure latency.

## Zone ping port (game port + 1)

Zones answer the same 4-byte ping on their game port + 1. The pong's first `u32` is the zone's population, then the ping's 4 bytes are echoed. Clients use it to show population and latency in their zone lists, and directories use it to reach registered zones.

- The reference server counts every player on the server, and refreshes the figure at most every `Net:PingDataRefreshTime` (default 200 ticks, 2 s), so it can lag behind.
- The original server (subgame 1.34.14) answers the same way: an empty zone reports 0 (PRIVATE's observation).
- The reference server also accepts an 8-byte request, an extension that returns per-arena counts. oss-core does not implement it.

`oss-conformance server` checks the ping port, and `oss-conformance directory` checks that a registered zone answers on it.

## Zone list (client ↔ directory, port 4990)

Clients connect with the normal transport: the `00 01` handshake, then reliable delivery. See [transport](transport.md).

**Request** (type `0x01`, 5 bytes): `u32` minimum player count.

**Response** (type `0x01`): entries to the end of the packet. The response is usually larger than one datagram, so it arrives as big or sized data.

Each entry:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | IPv4 address in network byte order (a.b.c.d) |
| 4 | 2 | port |
| 6 | 2 | players |
| 8 | 1 | score keeping |
| 9 | 1 | hop count |
| 10 | 4 | version |
| 14 | 64 | zone name, NUL-padded |
| 78 | n | description, NUL-terminated |

One directory implementation writes score keeping as a `u16` (so the hop count is always 0), and writes its 32-byte name followed by 32 zero bytes.
