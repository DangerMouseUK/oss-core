# Billing server protocol

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implemented in `oss-proto::billing`. Evidence for each part: [verification.md](verification.md).

A *biller* is a central server that holds accounts, scores, squads and chat channels for one or more zones. A zone connects to it like a client, using the normal [transport](transport.md), and exchanges the packets below. Integers are little-endian.

Text fields are NUL-terminated and run to the end of the packet; senders keep them to about 250 bytes. A *connection id* is the zone's own number for a player and is echoed in every packet about that player.

**Player score** (14 bytes): `u16 kills, u16 deaths, u16 flags, u32 points, u32 flag points`.

## Zone → biller

| Type | Name | Layout after the type byte |
|---|---|---|
| 01 | ping | — |
| 02 | server connect | `u32 server id, u32 group id, u32 score id, name[126], u16 port, password[32]` (173 bytes total) |
| 03 | server disconnect | — |
| 04 | user login | `u8 make new, ip[4], name[32], password[32], u32 connection id, u32 machine id, i16 timezone, u16 timezone high, u8 unknown, u8 sysop, u16 client version`, then client data to the end (the 64-byte Continuum id, or nothing) |
| 05 | user logoff | `u32 connection id, u16 reason, u16 latency, u16 ping, u16 loss S2C, u16 loss C2S`, then a score only if the zone has one saved: 29 bytes with it, 15 without |
| 06 | remote zone message | `u32 connection id, u32 server id, u8 type, u8 sound`, text |
| 07 | remote private | `u32 connection id (often 0xFFFFFFFF), u32 group id, u8 type, u8 sound`, text in the form `:name:(from)>msg` or `:#squad:(from)>msg` |
| 08 | request file | file name, NUL-terminated |
| 0D | demographics | `u32 connection id`, the registration form (C2S `0x17` without its type byte, up to 765 bytes) |
| 0E | private chat | `u32 source, u32 destination`, text. Already delivered unless it starts with `*`; destination `0xFFFFFFFF` means a `*` command aimed at nobody |
| 0F | security violation | `u32 connection id`, text |
| 10 | banner | `u32 connection id`, 96-byte banner |
| 11 | score | `u32 connection id`, score |
| 12 | score-group message | `u32 connection id, u32 score id, u8 type, u8 sound`, text |
| 13 | command | `u32 connection id`, `?command` text |
| 14 | channel chat | `u32 connection id, channel[32]`, text |
| 15 | capabilities | `u32 flags` (bit 0: multicast channel chat) |

About the timezone field in `04`: one reference zone writes it as a 32-bit signed value, and another document describes it as a 16-bit value followed by 2 unused bytes. The low 16 bits are the same either way. `oss-proto` keeps both halves so packets round-trip exactly.

## Biller → zone

| Type | Name | Layout after the type byte |
|---|---|---|
| 01 | login response | `u8 result, u32 connection id, name[24], squad[24], banner[96], u32 seconds played, u16 year, month, day, hour, minute, second (account creation), u32 unused, u32 user id, u32 unused`, then a score if the login succeeded (178 or 192 bytes) |
| 02 | shut down the zone | — |
| 03 | zone message | `u32 source server, u8 type, u8 sound`, text. A text of the form `:target:(from)>msg` is a remote private message |
| 04 | recycle the zone | — |
| 05 | file | `name[16]`, data |
| 08 | kick | `u32 connection id, u16 reason` |
| 09 | arena message to one player | `u32 connection id`, text |
| 0A | channel message to one player | `u32 connection id, u8 channel`, text |
| 31 | score reset | `u32 score id, u32 negated score id` |
| 32 | user packet | `u32 connection id`, a game packet to forward |
| 33 | biller identity | data to the end of the packet (sources mention 128 and 256 bytes) |
| 34 | multicast channel chat | `u8 count`, then `count × (u32 connection id, u8 channel)`, then the text |

Login results:

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | new user |
| 2 | invalid password |
| 3 | banned |
| 4 | no new connections |
| 5 | bad name |
| 6 | demo version |
| 7 | busy |
| 8 | ask for demographics |

Message types in `03`/`06`/`07`: 1 = arena message, 2 = remote private message.
