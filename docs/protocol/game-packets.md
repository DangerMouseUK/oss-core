# Game packets

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-proto` (`s2c`, `c2s`, `position`, `common`, `settings`, `objects`).

**Conventions**

- Offsets start at the type byte (offset 0) and integers are little-endian.
- `pid` is an `i16` player id, with −1 meaning "none" or "everyone" depending on the packet.
- Ships are numbered 0–7 (Warbird … Shark), and 8 is spectator.
- Positions are in pixels (16 per tile; the map is 1024 × 1024 tiles). Rotation runs 0–39 clockwise from up.
- Strings are fixed-size and NUL-padded unless marked NUL-terminated; a full-width string may lack its NUL.

Several types have more than one valid length, and receivers tell the forms apart by length (see the summary table at the end).

## Shared structures

### Weapon word (2 bytes)

Bits 0–4 type, 5–6 level (0–3), 7 shrapnel bounces, 8–9 shrapnel level, 10–14 shrapnel count, 15 alternate fire.

Weapon types: 0 none, 1 bullet, 2 bouncing bullet, 3 bomb, 4 proximity bomb, 5 repel, 6 decoy, 7 burst, 8 thor. Alternate fire turns a bomb into a mine, and bullets into multifire. In damage reports, type 0 also means wormhole and 15 means shrapnel.

### Extra position data (10 bytes)

`u16 energy, u16 ping (10 ms units), u16 flag timer, u32 items`.

The `items` bits:

| Bits | Field |
|---|---|
| 0 | shields |
| 1 | super |
| 2–5 | bursts |
| 6–9 | repels |
| 10–13 | thors |
| 14–17 | bricks |
| 18–21 | decoys |
| 22–25 | rockets |
| 26–29 | portals |

### Status byte

| Bit | Mask | Meaning |
|---|---|---|
| 0 | 0x01 | stealth |
| 1 | 0x02 | cloak |
| 2 | 0x04 | X-radar |
| 3 | 0x08 | antiwarp |
| 4 | 0x10 | flash (just warped or uncloaked) |
| 5 | 0x20 | in safe zone |
| 6 | 0x40 | UFO |
| 7 | 0x80 | unused / client-specific |

### Damage entry (9 bytes)

`i16 attacker, weapon word, i16 energy before, i16 damage, u8 tick offset`.

### LVZ object toggle (2 bytes)

Bits 0–14 object id. Bit 15 set means hide, clear means show.

### LVZ object change (11 bytes)

`u8 mask` (bit 0 position, 1 image, 2 layer, 3 time, 4 mode), then the 10-byte object record documented in [lvz](../formats/lvz.md).

### Player record (64 bytes, S2C `0x03`)

`u8 0x03, i8 ship, u8 accepts audio, name[20], squad[20], i32 kill points, i32 flag points, i16 pid, i16 freq, i16 wins, i16 losses, i16 attached-to (−1 none), i16 flags carried, u8 misc`.

Misc bits: 0 = has crown, 1 = send damage for this player.

Several records may be concatenated in one packet; each starts with its own `0x03`.

### Chat types

| Code | Type |
|---|---|
| 0 | arena (green, server only) |
| 1 | public macro |
| 2 | public |
| 3 | team |
| 4 | to target's frequency |
| 5 | private (same arena) |
| 6 | warning with name (server only) |
| 7 | remote private |
| 8 | server error (red, server only) |
| 9 | channel |

Remote privates are written `:name:text` by the client, and shown as `(name)>text` with pid −1 by the server. Channel messages are `n;text`.

### Prize numbers

| # | Prize | # | Prize | # | Prize | # | Prize |
|---|---|---|---|---|---|---|---|
| 1 | recharge | 8 | gun | 15 | multifire | 22 | burst |
| 2 | energy | 9 | bomb | 16 | proximity | 23 | decoy |
| 3 | rotation | 10 | bounce | 17 | super | 24 | thor |
| 4 | stealth | 11 | thrust | 18 | shields | 25 | multiprize |
| 5 | cloak | 12 | speed | 19 | shrapnel | 26 | brick |
| 6 | X-radar | 13 | full charge | 20 | antiwarp | 27 | rocket |
| 7 | warp | 14 | engine shutdown | 21 | repel | 28 | portal |

## Server to client

| Type | Name | Length | Layout after the type byte |
|---|---|---|---|
| 01 | your player id | 3 (4) | `i16 pid` [`u8` unknown] |
| 02 | arena entered | 1 | |
| 03 | player entering | 64·n | player records |
| 04 | player leaving | 3 | `i16 pid` |
| 05 | weapon / large position | 21 / 23 / 31 | see Position packets |
| 06 | kill | 10 | `u8 green prize, i16 killer, i16 killed, i16 bounty, i16 flags` |
| 07 | chat | 6+ | `u8 type, u8 sound, i16 sender, text NUL-terminated` |
| 08 | prize taken | 13 | `u32 time, i16 x, i16 y (tiles), i16 prize, i16 pid` |
| 09 | score | 15 | `i16 pid, i32 kill points, i32 flag points, i16 kills, i16 deaths` |
| 0A | login response | 36 | see below |
| 0B | soccer goal | 7 | `i16 freq, i32 points` |
| 0C | voice | 3+ | `i16 sender, compressed WAV` |
| 0D | frequency change | 6 | `i16 pid, i16 freq, u8 0xFF` |
| 0E | turret | 5 | `i16 attacher, i16 host (−1 detach)` |
| 0F | arena settings | 1428 | see [settings](settings.md) |
| 10 | incoming file | 17+ | `name[16]` (all zero = news, zlib), data |
| 12 | flag location | 9 | `u16 flag, u16 x, u16 y (tiles), u16 freq` |
| 13 | flag pickup | 5 | `i16 flag, i16 pid` |
| 14 | flag victory | 7 | `i16 freq, i32 points` |
| 15 | turret kickoff | 3 | `i16 host` |
| 16 | flag drop | 3 | `i16 pid` |
| 18 | security / seeds | 17 | `u32 prize seed, u32 door seed, u32 timestamp, u32 checksum key` (0 = seeds only) |
| 19 | request file | 273 | `local path[256], name[16]` |
| 1A | score reset | 3 | `i16 pid` (−1 everyone) |
| 1B | ship reset | 1 | |
| 1C | spectator data | 2 / 3 | 2: `u8` 1 = append extra data to your positions. 3: `i16 pid` went spectator |
| 1D | ship change | 6 | `i8 ship, i16 pid, i16 freq` |
| 1E | banner toggle | 2 | `u8` (meaning unclear) |
| 1F | banner | 99 | `i16 pid, 96 bytes` (12×8 palette indices) |
| 20 | prize received | 5 | `i16 count, i16 prize` |
| 21 | bricks | 1+16n | `i16 x1, y1, x2, y2, i16 freq, u16 id, u32 time` each; length 1 clears all |
| 22 | turf flag owners | 1+2n | `i16 owner freq` per flag id |
| 23 | periodic reward | 1+4n | `i16 freq, i16 points` |
| 24 | speed game result | 38 | `u8 best, u16 rank, i32 score, i32[5] top scores, i16[5] top pids` |
| 25 | UFO allowed | 2 | `u8` |
| 27 | keep-alive | 1 | |
| 28 | small position | 16 / 18 / 26 | see Position packets |
| 29 | map file names | 21 / 1+24n | see below |
| 2A | map / LVZ data | 17+ | `name[16]`, data (maps zlib-compressed; LVZ as stored) |
| 2B | set crown timer | 5 | `u32 ticks` |
| 2C | crown | 8 | `u8 give, u32 ticks, i16 pid (−1 all)` |
| 2D | add crown time | 5 | `u32 ticks` |
| 2E | ball | 16 | `u8 id, i16 x, i16 y, i16 vx, i16 vy, i16 pid, u32 time` |
| 2F | arena list | var | repeated `name NUL-terminated, i16 population` (negative for your current arena) |
| 30 | ad banner | 10+ | `u8 mode, u16 w, u16 h, u32 duration`, data (obsolete) |
| 31 | login OK | 1 | obsolete |
| 32 | warp to | 5 | `i16 x, i16 y` (tiles) |
| 33 | login text | 2+ | text NUL-terminated (Continuum) |
| 34 | Continuum version | 7 | `u16 version, u32 exe checksum` |
| 35 | toggle objects | 1+2n | toggle entries |
| 36 | change objects | 1+11n | change entries |
| 37 | damage reporting | 2 | `u8 on` |
| 38 | damage | 7+9n | `i16 pid, u32 time`, damage entries |
| 39 | batched small positions | 1+10n | see below |
| 3A | batched large positions | 1+11n | see below |
| 3B | redirect | 29 | `ip[4], u16 port, i16 arena type, arena[16], u32 login id` |
| 3C | select box | var | title NUL-terminated, then repeated `i16 value, text NUL-terminated` |

Types `0x11`, `0x17` and `0x26` are no-ops in the original client.

### Login response (0x0A, 36 bytes)

| Offset | Field |
|---|---|
| 1 | result code |
| 2 | `u32` server version (134) |
| 6 | VIP flag (tells Continuum to skip its checksum checks) |
| 7 | 3 unused |
| 10 | `u32` expected exe checksum |
| 14 | 5 unused |
| 19 | `u8` registration request: non-zero asks the client to send C2S `0x17` |
| 20 | `u32` code checksum |
| 24 | `u32` news CRC-32 (0 = no news) |
| 28 | 8 unused |

An exe checksum and code checksum both set to `0xFFFFFFFF` marks the user as staff.

Result codes:

| Code | Meaning | Code | Meaning |
|---|---|---|---|
| 0 | OK | 10 | no new connections |
| 1 | unknown user (resend with new-user flag) | 11 | bad name |
| 2 | bad password | 12 | offensive name |
| 3 | full | 13 | OK, no scores kept |
| 4 | locked out | 14 | busy |
| 5 | no permission | 15 | too little usage |
| 6 | spectate only | 16 | no name |
| 7 | too many points | 17 | too many demo users |
| 8 | too slow | 18 | no demo users |
| 9 | no permission (2) | 19 | custom text, Continuum only |

Code 19 follows S2C `0x33`. Continuum also receives S2C `0x34` before `0x0A`.

### Map file names (0x29)

- **21 bytes** (clients without LVZ support): `name[16], u32 CRC-32 of the uncompressed map file`.
- **1 + 24·n bytes**: repeated `name[16], u32 CRC-32 of the file as stored, u32 size`. The size is the total length of the `0x2A` packet that will carry the file. Entry 0 is the map; the rest are LVZ files.

The client requests entry *i* with C2S `0x0C`.

### Arena entry sequence

A server typically sends, in order:

1. `01` your player id;
2. `0F` settings;
3. `03` for everyone already in the arena, then your own record;
4. `29` map file names;
5. `21` with length 1 (clear bricks);
6. `02` arena entered;
7. optionally `32` warp to.

### Position packets

**`0x28` small form**

| Offset | Field |
|---|---|
| 1 | `i8` rotation |
| 2 | `u16` time (low 16 bits of server ticks) |
| 4 | `i16` x |
| 6 | `u8` latency (ticks) |
| 7 | `u8` bounty |
| 8 | `u8` pid |
| 9 | status |
| 10 | `i16` y velocity |
| 12 | `i16` y |
| 14 | `i16` x velocity |
| 16 | optional tail (below) |

**`0x05` weapon / large form**

| Offset | Field |
|---|---|
| 1 | `i8` rotation |
| 2 | `u16` time |
| 4 | `i16` x |
| 6 | `i16` y velocity |
| 8 | `u16` pid |
| 10 | `i16` x velocity |
| 12 | `u8` checksum: XOR of bytes 0–20, with this byte taken as 0 |
| 13 | status |
| 14 | `u8` latency |
| 15 | `i16` y |
| 17 | `u16` bounty |
| 19 | weapon word |
| 21 | optional tail (below) |

**Tail.** Both forms may end with nothing, with energy only (2 bytes), or with the full extra position data (10 bytes). That gives lengths 16/18/26 for `0x28` and 21/23/31 for `0x05`. The server chooses the tail per recipient.

**Which form.** Servers use `0x05` when a weapon was fired or when the pid or bounty doesn't fit in a byte, and `0x28` otherwise.

**Batched positions** (`0x39`, `0x3A`; only for clients that advertise support).

Each entry packs:

- `u16`: rotation (bits 10–15) and the low 10 bits of the time (bits 0–9);
- `u32`: x (bits 0–13), y (bits 14–27) and x-velocity bits 0–3 (bits 28–31);
- `u16`: y velocity as a signed 14-bit value (bits 0–13) and x-velocity bits 4–5 (bits 14–15);
- `i8`: x-velocity bits 6–13, which carries its sign.

Both velocities are signed 14-bit values. `0x39` entries start with a `u8` pid. `0x3A` entries start with a `u16` holding the pid (bits 0–9) and status bits 0–5 (bits 10–15).

## Client to server

| Type | Name | Length | Layout after the type byte |
|---|---|---|---|
| 01 | enter arena | 26 / 27 | `u8 ship, i8 allow audio, i8 obscenity filter, i16 x res, i16 y res, i16 arena type, arena[16]` [`u8 optional LVZ`] |
| 02 | leave arena | 1 | |
| 03 | position | 22 / 32 | see below |
| 05 | death | 5 | `i16 killer, i16 bounty` |
| 06 | chat | 6+ | `u8 type, u8 sound, i16 target, text NUL-terminated` |
| 07 | take prize | 11 | `u32 time, i16 x, i16 y (tiles), i16 prize` |
| 08 | spectate | 3 | `i16 pid` (−1 none) |
| 09 / 24 | login | 101 / 165 | see below |
| 0A | relay LVZ packet | 4+ | `i16 target (−1 arena)`, an S2C `0x35` or `0x36` packet |
| 0B | update request | 1 | |
| 0C | file request | 1 / 3 | [`u16 index`] into the `0x29` list |
| 0D | news request | 1 | |
| 0E | voice | 4+ | `u8 slot, i16 target, compressed WAV` |
| 0F | set frequency | 3 | `i16 freq` |
| 10 | attach | 3 | `i16 pid` (−1 detach) |
| 13 | flag pickup | 3 | `i16 flag` |
| 14 | detach turrets | 1 | |
| 15 | drop flags | 1 | |
| 16 | upload file | 17+ | `name[16]`, data |
| 17 | registration | 766 | see below |
| 18 | set ship | 2 | `u8 ship` |
| 19 | set banner | 97 | 96 bytes |
| 1A | security response | 40 / 46 | see below |
| 1B | security violation | 2+ | `u8 code` [message] |
| 1C | drop brick | 5 | `i16 x, i16 y` (tiles) |
| 1D | change settings | var | `Section:Key:Value` strings, each NUL-terminated, ending with an empty string |
| 1E | crown expired | 1 | |
| 1F | shoot ball | 16 | as S2C `0x2E` |
| 20 | pick up ball | 6 | `u8 id, u32 time` |
| 21 | goal | 6 | `u8 id, i16 x, i16 y` (tiles) |
| 32 | damage | 5+9n | `u32 time`, damage entries |

Types `0x04`, `0x11`, `0x12` and `0x22` are unused or have no known layout.

### Enter arena (0x01)

The arena type at offset 8 is:

- −3: the named arena at offset 10;
- −1 or −2: any public arena (the server chooses);
- 0 or more: public arena number *n*.

Sources disagree on offsets 2 and 3. Most read 2 = allow audio and 3 = obscenity filter.

### Position (0x03)

| Offset | Field |
|---|---|
| 1 | `i8` rotation |
| 2 | `u32` time (client's estimate of server ticks) |
| 6 | `i16` x velocity |
| 8 | `i16` y |
| 10 | `u8` checksum |
| 11 | status |
| 12 | `i16` x |
| 14 | `i16` y velocity |
| 16 | `u16` bounty |
| 18 | `i16` energy |
| 20 | weapon word |
| 22 | extra position data, only in the 32-byte form |

The checksum makes the XOR of bytes 0–21 equal to zero. The extra data is not covered.

Clients append the extra data while S2C `0x1C` (2-byte form) is on, or when the arena setting `ExtraPositionData` is set. x = y = −1 means dead and waiting to respawn.

### Login (0x09 SubSpace, 0x24 Continuum)

| Offset | Field |
|---|---|
| 1 | flags (1 = new user) |
| 2 | name[32] |
| 34 | password[32] |
| 66 | `u32` machine id |
| 70 | `u8` connection type (4 typical) |
| 71 | `i16` timezone bias (minutes) |
| 73 | `u16` unknown |
| 75 | `u16` client version (134 SubSpace, 40 Continuum 0.40) |
| 77 | `i32` 444 |
| 81 | `i32` 555 |
| 85 | `u32` permission id |
| 89 | 12 reserved bytes |
| 101 | 64-byte Continuum id (0x24 only) |

Servers check the length against the client type negotiated by the encryption handshake, not against the type byte.

**Feature flags.** Some servers read bytes 79–80 as client feature flags:

| Flag | Feature | Packets |
|---|---|---|
| 0x01 | damage watching | `0x38`/`0x32` |
| 0x02 | batched positions | `0x39`/`0x3A` |
| 0x04 | warp-to | `0x32` |
| 0x08 | LVZ | `0x35`/`0x36` and the long `0x29` |
| 0x10 | redirect | `0x3B` |
| 0x20 | select box | `0x3C` |

The same servers read part of the reserved block as the address the client connected to and a login id taken from `0x3B`.

### Registration (0x17, 766 bytes)

| Offset | Field |
|---|---|
| 1 | real name[32] |
| 33 | e-mail[64] |
| 97 | city[32] |
| 129 | state[24] |
| 153 | sex (`M`/`F`) |
| 154 | age |
| 155 | from home |
| 156 | from work |
| 157 | from school |
| 158 | `u32` processor |
| 162 | `u16` unknown |
| 164 | `u16` unknown |
| 166 | Windows owner[40] |
| 206 | Windows organisation[40] |
| 246 | 13 × 40-byte hardware description strings |

### Security response (0x1A)

| Offset | Field |
|---|---|
| 1 | `u32` weapons received |
| 5 | `u32` settings checksum |
| 9 | `u32` exe checksum |
| 13 | `u32` map checksum |
| 17 | `u32` slow S2C packets, total |
| 21 | `u32` fast S2C packets, total |
| 25 | `u16` slow S2C packets, current |
| 27 | `u16` fast S2C packets, current |
| 29 | `u16` reliables outstanding (one source calls it an average) |
| 31 | `u16` ping, last |
| 33 | `u16` ping, average |
| 35 | `u16` ping, lowest |
| 37 | `u16` ping, highest (pings in 10 ms units) |
| 39 | `u8` slow frame detected |
| 40 | `i16` timer drift (Continuum only) |
| 42 | `u32` map CRC (Continuum only) |

The checksum algorithms are in [checksums](checksums.md).

## Lengths that decide the form

| Dir | Type | Lengths |
|---|---|---|
| S2C | 01 | 3 / 4 |
| S2C | 05 | 21 / 23 / 31 |
| S2C | 1C | 2 / 3 |
| S2C | 21 | 1 / 1+16n |
| S2C | 28 | 16 / 18 / 26 |
| S2C | 29 | 21 / 1+24n |
| C2S | 01 | 26 / 27 |
| C2S | 03 | 22 / 32 |
| C2S | 09, 24 | 101 / 165 |
| C2S | 0C | 1 / 3 |
| C2S | 1A | 40 / 46 |
