# Conformance suite

Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implementation: `crates/oss-conformance` (MIT), binary `oss-conformance`.

The suite lets any implementation of the SubSpace/Continuum protocol show that it behaves correctly, whether it is a client, bot, server or library, and in any language. It has three parts:

| Part | Command | What it checks |
|---|---|---|
| Vectors | `oss-conformance vectors -- <your adapter>` | 3,725 offline checks from published test vectors |
| Live server | `oss-conformance server HOST:PORT` | a running server, with the suite acting as a client |
| Live client | `oss-conformance client --bind ADDR` | a client that connects to the suite, which acts as a zone |

The exit status is 0 if nothing failed, 1 if a check failed, and 2 on usage or I/O errors. `--verbose` lists every check; otherwise only failures are listed after the per-group counts.

```sh
cargo install --path crates/oss-conformance        # or: cargo run -p oss-conformance -- ...
oss-conformance list                               # check groups and counts
oss-conformance vectors                            # oss-core itself (should be all PASS)
oss-conformance vectors -- python3 my_adapter.py   # your implementation
oss-conformance server zone.example:5000 --name Tester --password secret
oss-conformance client --bind 0.0.0.0:5000         # then point your client at this address
```

## Vectors and the adapter protocol

To be checked against the vectors, an implementation provides an *adapter*: a program that reads one request per line on standard input and writes one response per line on standard output, flushing after each.

**Value formats:**

- Byte strings are hex in wire order.
- 32-bit integers are 8 hex digits, most significant first (`checksum.exe 0000002a`).
- Counters are decimal.

**Special responses:**

- `error` means the input is invalid and must be rejected.
- `unsupported` means the implementation does not provide that command; its checks are skipped, not failed.

A minimal adapter can therefore answer `unsupported` to everything and add commands one at a time.

| Request | Response | Vectors |
|---|---|---|
| `hello` | any line starting `hello` | (sent first by some harnesses) |
| `vie.connect_request <client key>` | the C2S `00 01` packet | VIE key exchange, reference server |
| `vie.server_key <client key>` | the key the server answers with in `00 02` | reference server, edge cases included |
| `vie.encrypt <server key> <plaintext>` | ciphertext | 768 packets, reference server |
| `vie.decrypt <server key> <ciphertext>` | plaintext | 768 packets, reference server |
| `checksum.exe <key>` | VIE (SubSpace 1.34) exe checksum | 32 keys |
| `checksum.c2s_position_valid <packet>` | `yes` or `no` | 48 C2S `0x03` packets, reference server |
| `checksum.s2c_weapon <packet>` | the correct checksum byte (offset 12) | 40 S2C `0x05` packets |
| `checksum.settings <key> <settings packet>` | settings checksum | 2 packets × 7 keys, reference server |
| `settings.locate <Section:Key>` | every location of the key in the settings packet, as `bitoffset:bitlength`, space-separated | 1,692 keys from 2 configurations, reference server |
| `checksum.crc32 <bytes>` | CRC-32 (the S2C `0x29` map checksum) | 5 maps |
| `checksum.map <key> <.lvl file>` | security map checksum | 5 maps, 165 keys, reference server |
| `opensec.client_hello <ephemeral secret> <caps>` | client hello | OpenSec |
| `opensec.server_hello <ephemeral secret> <static secret or -> <caps> <client hello>` | server hello | OpenSec |
| `opensec.client_keys <ephemeral secret> <client hello> <server hello>` | `<c2s key> <s2c key>` | OpenSec |
| `opensec.seal <key> <c2s or s2c> <counter> <plaintext>` | record | OpenSec |
| `opensec.open <key> <c2s or s2c> <counter> <record>` | plaintext, or `error` if tampered | OpenSec |
| `packet.roundtrip <s2c, c2s or core> <packet>` | the packet decoded and encoded again | 63 S2C, 37 C2S and 16 core canonical encodings, plus the 2 reference settings packets |
| `relay.frame <frame>` | the frame decoded and encoded again, or `error` | 13 relay frames |

**`packet.roundtrip`.** This tests the codec end to end: decoding must accept the packet, and encoding the decoded value must give back exactly the same bytes. An implementation that only reads packets can still pass by echoing the input for packets it accepts and answering `error` for ones it rejects. That still shows it accepts every canonical form.

**`settings.locate`.** This is the check server implementers most need: building a settings packet from configuration means putting every key at its exact bit position. The vectors list each key's position as the reference server writes it.

**Sources.** The vectors come from three places:

- running unmodified reference implementations: the ASSS 1.4.4 server modules, compiled as-is, and nullspace's MIT exe checksum;
- this project's own specifications (OpenSec, the relay protocol);
- this project's canonical packet encodings.

Each file's header in `crates/oss-conformance/vectors/` says which. The suite embeds the files, so the binary is self-contained. The copies are tested against the vectors the oss-core crates themselves are tested with.

## Live server checks

The suite connects to the server as a SubSpace (VIE) client.

**Transport,** using hand-built datagrams:

| Check | Requirement |
|---|---|
| `connect` | `00 01 <key> 01 00` gets a `00 02` answer (the request is resent every second) |
| `connect-key` | the answer carries the VIE server key for that client key, or the client key itself (no encryption) |
| `sync` | `00 05` gets a `00 06` echoing its time |
| `reliable-ack` | a `00 03` reliable packet is acknowledged with `00 04` and its sequence number |
| `reliable-payload` | the packet inside the reliable is handled once |
| `duplicate-reliable-acked` | sending the same reliable again is acknowledged again |
| `duplicate-reliable-ignored` | and its payload is not handled a second time |
| `cluster` | both packets inside a `00 0E` cluster are handled |
| `disconnect` | after `00 07`, the server ignores the old session |

**Session,** over a full `oss-net` connection:

| Check | Requirement |
|---|---|
| `login-response` | C2S `0x09` gets S2C `0x0A`. If the name is unknown (code 1), the suite logs in again as a new user |
| `arena-player-id`, `arena-settings`, `arena-settings-size`, `arena-self-listed`, `arena-map-filename`, `arena-entered` | after C2S `0x01`: the player id, the 1428-byte settings packet, a `0x03` listing this player, the `0x29` map name, and `0x02` |
| `arena-order` | player id, then settings, then `0x02` last (the reference order, which clients rely on) |
| `map-download`, `map-crc`, `map-parses` | C2S `0x0C` gets S2C `0x2A`. Its zlib contents match the CRC-32 announced in `0x29` and parse as a level |
| `security` | if the server sends `0x18` with a key, the suite answers with correct checksums (skipped otherwise) |
| `session-kept` | after the security answer and two seconds of position updates, the session is still open |

If the server refuses the login (for example because the name needs a password), the arena checks are skipped. Use `--name` and `--password`.

## Live client checks

The suite listens as a zone and checks the first client that connects. It accepts VIE and OpenSec. Continuum's encryption is not public, so Continuum clients are reported as skipped.

| Check | Requirement |
|---|---|
| `connect-request` | the first datagram is `00 01 <key> 01 00` or an OpenSec hello |
| `handshake` | the session is established |
| `login`, `login-name` | C2S `0x09` (or `0x24`) arrives with a non-empty name |
| `acks` | the reliable login response is acknowledged within a second |
| `go-arena` | C2S `0x01` follows the login response |
| `map-request` | C2S `0x0C` after the `0x29` map name. Skipped if the client already has the map |
| `position`, `position-checksum` | C2S `0x03` updates arrive, all with correct checksums |
| `security-response` | S2C `0x18` with a key gets C2S `0x1A` |
| `security-settings-checksum` | correct for the settings packet the suite sent (the reference server's) |
| `security-exe-checksum` | the SubSpace 1.34 value. Skipped for OpenSec clients |
| `security-map-checksum` | correct for the map the suite served (`smallmap.lvl`). Skipped if the client reports 0 |
| `time-sync` | the client sends a 14-byte `00 05` time sync request |

## Verified results

| Implementation | Vectors | Live |
|---|---|---|
| oss-core (reference adapter, in process and as a child process) | 3,725 pass | — |
| `oss-bot-sdk` (`examples/greeter.rs`) as a client | — | 14 pass |
| A zone built on `oss-net` (in the suite's tests) | — | all pass |
| `oss-server` (bundled default zone, 2026-11-08) | — | 21 pass, 1 skipped: it sent no security request within 2 s |
