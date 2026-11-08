//! Directory and SSC billing packets against vectors from the reference server
//! (ASSS 1.4.4 `directory.c`, `billing_ssc.c` and `packets/billing.h`, compiled
//! unmodified; see `vectors/README.md`).
//!
//! * Every packet the reference sends decodes and re-encodes to the same bytes.
//! * Every field of every billing struct sits at the reference offset and size:
//!   each field of a packet built here holds a distinct marker, and the marker
//!   must appear at exactly that offset.

use oss_proto::billing::{BillerLogin, BillerToServer, PlayerScore, ServerToBiller, UserLogin};
use oss_proto::directory::ZoneUpdate;
use oss_proto::wire::{FixedStr, Raw};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn records(text: &'static str) -> impl Iterator<Item = Vec<&'static str>> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split_whitespace().collect())
}

const DIRECTORY: &str = include_str!("vectors/directory.txt");
const BILLING: &str = include_str!("vectors/billing-ssc.txt");

#[test]
fn directory_updates_round_trip() {
    let mut n = 0;
    for f in records(DIRECTORY) {
        let ["update", len, bytes] = f.as_slice() else {
            panic!("unknown record {f:?}");
        };
        let b = hex(bytes);
        assert_eq!(b.len(), len.parse::<usize>().unwrap());
        let u = ZoneUpdate::decode(&b).unwrap();
        assert_eq!(u.ip, 0, "the reference always sends ip 0");
        assert_eq!(u.version, 134, "the reference always sends version 134");
        let mut out = Vec::new();
        u.encode(&mut out);
        assert_eq!(out, b, "{u:?}");
        n += 1;
    }
    assert_eq!(n, 7);
}

#[test]
fn billing_packets_round_trip() {
    let mut n = 0;
    for f in records(BILLING) {
        match f.as_slice() {
            ["s2b", name, len, bytes] => {
                let b = hex(bytes);
                assert_eq!(b.len(), len.parse::<usize>().unwrap(), "{name}");
                let p = ServerToBiller::decode(&b).unwrap();
                assert!(!matches!(p, ServerToBiller::Unknown { .. }), "{name}");
                assert_eq!(p.to_bytes(), b, "{name}: {p:?}");
                n += 1;
            }
            ["b2s", name, len, bytes] => {
                let b = hex(bytes);
                assert_eq!(b.len(), len.parse::<usize>().unwrap(), "{name}");
                let p = BillerToServer::decode(&b).unwrap();
                assert!(!matches!(p, BillerToServer::Unknown { .. }), "{name}");
                assert_eq!(p.to_bytes(), b, "{name}: {p:?}");
                n += 1;
            }
            ["layout" | "field", ..] => {}
            other => panic!("unknown record {other:?}"),
        }
    }
    assert_eq!(n, 12);
}

// ---- field offsets ------------------------------------------------------------------

/// A score whose fields hold distinct markers.
fn score() -> PlayerScore {
    PlayerScore {
        kills: 0x1101,
        deaths: 0x1202,
        flags: 0x1303,
        points: 0x1404_0404,
        flag_points: 0x1505_0505,
    }
}

fn le16(v: u16) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}
fn le32(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}
fn fill(len: usize, b: u8) -> Vec<u8> {
    vec![b; len]
}
fn text(t: &[u8]) -> Vec<u8> {
    t.to_vec()
}

/// Our encoded packet, and the expected bytes of each field under the
/// reference's field names.
type Sample = (Vec<u8>, Vec<(&'static str, Vec<u8>)>);

/// The sample for one reference struct.
fn sample(name: &str) -> Option<Sample> {
    let s = score();
    let score_bytes = {
        let mut v = le16(s.kills);
        v.extend(le16(s.deaths));
        v.extend(le16(s.flags));
        v.extend(le32(s.points));
        v.extend(le32(s.flag_points));
        v
    };
    let t = b"marker text".to_vec();
    Some(match name {
        "PlayerScore" => {
            let p = ServerToBiller::UserScore {
                connection_id: 0,
                score: s,
            };
            // The score starts after the type byte and connection id.
            let b = p.to_bytes()[5..].to_vec();
            (
                b,
                vec![
                    ("Kills", le16(s.kills)),
                    ("Deaths", le16(s.deaths)),
                    ("Flags", le16(s.flags)),
                    ("Score", le32(s.points)),
                    ("FlagScore", le32(s.flag_points)),
                ],
            )
        }
        "S2B_ServerConnect" => {
            let p = ServerToBiller::ServerConnect {
                server_id: 0x2101_0101,
                group_id: 0x2202_0202,
                score_id: 0x2303_0303,
                name: FixedStr::new(&fill(126, b'n')),
                port: 0x2404,
                password: FixedStr::new(&fill(32, b'p')),
            };
            (
                p.to_bytes(),
                vec![
                    ("Type", vec![2]),
                    ("ServerID", le32(0x2101_0101)),
                    ("GroupID", le32(0x2202_0202)),
                    ("ScoreID", le32(0x2303_0303)),
                    ("ServerName", fill(126, b'n')),
                    ("Port", le16(0x2404)),
                    ("Password", fill(32, b'p')),
                ],
            )
        }
        "S2B_UserLogin" => {
            let p = ServerToBiller::UserLogin(UserLogin {
                make_new: 0x31,
                ip: [0x32, 0x33, 0x34, 0x35],
                name: FixedStr::new(&fill(32, b'n')),
                password: FixedStr::new(&fill(32, b'p')),
                connection_id: 0x3606_0606,
                machine_id: 0x3707_0707,
                timezone: 0x3808,
                timezone_high: 0x3909,
                unknown: 0x3A,
                sysop: 0x3B,
                client_version: 0x3C0C,
                extra: fill(256, 0xEE),
            });
            let mut tz = le16(0x3808);
            tz.extend(le16(0x3909));
            (
                p.to_bytes(),
                vec![
                    ("Type", vec![4]),
                    ("MakeNew", vec![0x31]),
                    ("IPAddress", vec![0x32, 0x33, 0x34, 0x35]),
                    ("Name", fill(32, b'n')),
                    ("Password", fill(32, b'p')),
                    ("ConnectionID", le32(0x3606_0606)),
                    ("MachineID", le32(0x3707_0707)),
                    ("Timezone", tz),
                    ("Unused0", vec![0x3A]),
                    ("Sysop", vec![0x3B]),
                    ("ClientVersion", le16(0x3C0C)),
                    ("ClientExtraData", fill(256, 0xEE)),
                ],
            )
        }
        "S2B_UserLogoff" => {
            let p = ServerToBiller::UserLogoff {
                connection_id: 0x4101_0101,
                reason: 0x4202,
                latency: 0x4303,
                ping: 0x4404,
                loss_s2c: 0x4505,
                loss_c2s: 0x4606,
                score: Some(s),
            };
            (
                p.to_bytes(),
                vec![
                    ("ConnectionID", le32(0x4101_0101)),
                    ("DisconnectReason", le16(0x4202)),
                    ("Latency", le16(0x4303)),
                    ("Ping", le16(0x4404)),
                    ("PacketLossS2C", le16(0x4505)),
                    ("PacketLossC2S", le16(0x4606)),
                    ("Score", score_bytes),
                ],
            )
        }
        "S2B_UserScore" => {
            let p = ServerToBiller::UserScore {
                connection_id: 0x5101_0101,
                score: s,
            };
            (
                p.to_bytes(),
                vec![("ConnectionID", le32(0x5101_0101)), ("Score", score_bytes)],
            )
        }
        "S2B_UserBanner" => {
            let p = ServerToBiller::UserBanner {
                connection_id: 0x6101_0101,
                banner: Raw(core::array::from_fn(|i| i as u8)),
            };
            (
                p.to_bytes(),
                vec![
                    ("ConnectionID", le32(0x6101_0101)),
                    ("Data", (0..96).collect()),
                ],
            )
        }
        "S2B_UserPrivateChat" => {
            let p = ServerToBiller::UserRemotePrivate {
                connection_id: 0x7101_0101,
                group_id: 0x7202_0202,
                kind: 0x73,
                sound: 0x74,
                text: t.clone(),
            };
            (
                p.to_bytes(),
                vec![
                    ("ConnectionID", le32(0x7101_0101)),
                    ("GroupID", le32(0x7202_0202)),
                    ("SubType", vec![0x73]),
                    ("Sound", vec![0x74]),
                    ("Text", text(&t)),
                ],
            )
        }
        "S2B_UserChannelChat" => {
            let p = ServerToBiller::UserChannelChat {
                connection_id: 0x8101_0101,
                channel: FixedStr::new(&fill(32, b'c')),
                text: t.clone(),
            };
            (
                p.to_bytes(),
                vec![
                    ("ConnectionID", le32(0x8101_0101)),
                    ("ChannelNr", fill(32, b'c')),
                    ("Text", text(&t)),
                ],
            )
        }
        "S2B_UserCommand" => {
            let p = ServerToBiller::UserCommand {
                connection_id: 0x9101_0101,
                text: t.clone(),
            };
            (
                p.to_bytes(),
                vec![("ConnectionID", le32(0x9101_0101)), ("Text", text(&t))],
            )
        }
        "S2B_UserDemographics" => {
            let p = ServerToBiller::UserDemographics {
                connection_id: 0xA101_0101,
                data: fill(765, 0xDD),
            };
            (
                p.to_bytes(),
                vec![
                    ("ConnectionID", le32(0xA101_0101)),
                    ("Data", fill(765, 0xDD)),
                ],
            )
        }
        "S2B_ServerCapabilities" => (
            ServerToBiller::ServerCapabilities { flags: 0xB101_0101 }.to_bytes(),
            vec![],
        ),
        "B2S_UserLogin" => {
            let p = BillerToServer::UserLogin(BillerLogin {
                result: 0xC1,
                connection_id: 0xC202_0202,
                name: FixedStr::new(&fill(24, b'n')),
                squad: FixedStr::new(&fill(24, b's')),
                banner: Raw(core::array::from_fn(|i| 0x80 | i as u8)),
                seconds_played: 0xC303_0303,
                first_login: [0xC401, 0xC402, 0xC403, 0xC404, 0xC405, 0xC406],
                unused0: 0xC505_0505,
                user_id: 0xC606_0606,
                unused1: 0xC707_0707,
                score: Some(s),
            });
            let mut first = Vec::new();
            for v in [0xC401u16, 0xC402, 0xC403, 0xC404, 0xC405, 0xC406] {
                first.extend(le16(v));
            }
            (
                p.to_bytes(),
                vec![
                    ("Result", vec![0xC1]),
                    ("ConnectionID", le32(0xC202_0202)),
                    ("Name", fill(24, b'n')),
                    ("Squad", fill(24, b's')),
                    ("Banner", (0..96).map(|i| 0x80 | i as u8).collect()),
                    ("SecondsPlayed", le32(0xC303_0303)),
                    ("FirstLogin", first),
                    ("Unused0", le32(0xC505_0505)),
                    ("UserID", le32(0xC606_0606)),
                    ("Unused1", le32(0xC707_0707)),
                    ("Score", score_bytes),
                ],
            )
        }
        "B2S_UserPrivateChat" => {
            let p = BillerToServer::ZoneMessage {
                source_server: 0xD101_0101,
                kind: 0xD2,
                sound: 0xD3,
                text: t.clone(),
            };
            (
                p.to_bytes(),
                vec![
                    ("SourceServerID", le32(0xD101_0101)),
                    ("SubType", vec![0xD2]),
                    ("Sound", vec![0xD3]),
                    ("Text", text(&t)),
                ],
            )
        }
        "B2S_UserKickout" => {
            let p = BillerToServer::Kick {
                connection_id: 0xE101_0101,
                reason: 0xE202,
            };
            (
                p.to_bytes(),
                vec![
                    ("ConnectionID", le32(0xE101_0101)),
                    ("Reason", le16(0xE202)),
                ],
            )
        }
        "B2S_UserCommandChat" => {
            let p = BillerToServer::ArenaMessage {
                connection_id: 0xF101_0101,
                text: t.clone(),
            };
            (
                p.to_bytes(),
                vec![("ConnectionID", le32(0xF101_0101)), ("Text", text(&t))],
            )
        }
        "B2S_UserChannelChat" => {
            let p = BillerToServer::ChannelMessage {
                connection_id: 0x1A01_0101,
                channel: 0x1B,
                text: t.clone(),
            };
            (
                p.to_bytes(),
                vec![
                    ("ConnectionID", le32(0x1A01_0101)),
                    ("ChannelNr", vec![0x1B]),
                    ("Text", text(&t)),
                ],
            )
        }
        "B2S_UserMChannelChat" => {
            // A full recipient array (45 entries) puts the text at the struct's
            // fixed offset; shorter arrays move it up (the reference reads the
            // text right after the last recipient).
            let recipients: Vec<(u32, u8)> = (0..45).map(|i| (0x2000_0000 + i, i as u8)).collect();
            let mut rbytes = Vec::new();
            for (c, ch) in &recipients {
                rbytes.extend(le32(*c));
                rbytes.push(*ch);
            }
            let p = BillerToServer::MultiChannelChat {
                recipients,
                text: t.clone(),
            };
            (
                p.to_bytes(),
                vec![
                    ("Count", vec![45]),
                    ("Recipient", rbytes),
                    ("Text", text(&t)),
                ],
            )
        }
        _ => return None,
    })
}

#[test]
fn billing_field_offsets_match_the_reference() {
    let mut checked = 0;
    let mut layouts = std::collections::HashMap::new();
    for f in records(BILLING) {
        if let ["layout", name, size] = f.as_slice() {
            layouts.insert(*name, size.parse::<usize>().unwrap());
        }
    }
    for f in records(BILLING) {
        let ["field", st, field, off, size] = f.as_slice() else {
            continue;
        };
        let (off, size): (usize, usize) = (off.parse().unwrap(), size.parse().unwrap());
        let (bytes, fields) = sample(st).unwrap_or_else(|| panic!("no sample for {st}"));
        if *field == "Type" && st.starts_with("B2S") {
            continue;
        }
        let Some((_, want)) = fields.iter().find(|(n, _)| n == field) else {
            // Type bytes of S2B structs without a listed marker.
            assert_eq!(*field, "Type", "{st}.{field} has no marker");
            continue;
        };
        if matches!(*field, "Text") {
            // Variable text fields: the text must start at the offset.
            assert_eq!(
                &bytes[off..off + want.len()],
                want.as_slice(),
                "{st}.{field} at {off}"
            );
        } else {
            assert_eq!(want.len(), size, "{st}.{field}: marker length");
            assert_eq!(
                &bytes[off..off + size],
                want.as_slice(),
                "{st}.{field} at {off}"
            );
        }
        checked += 1;
    }
    // Fixed-size structs encode to exactly the reference `sizeof`.
    for (st, full) in [
        ("PlayerScore", 14),
        ("S2B_ServerConnect", 173),
        ("S2B_UserLogin", 342),
        ("S2B_UserLogoff", 29),
        ("S2B_UserScore", 19),
        ("S2B_UserBanner", 101),
        ("S2B_ServerCapabilities", 5),
        ("B2S_UserLogin", 192),
        ("B2S_UserKickout", 7),
    ] {
        assert_eq!(layouts[st], full, "{st} sizeof");
        let (bytes, _) = sample(st).unwrap();
        assert_eq!(bytes.len(), full, "{st}: our encoding");
    }
    assert!(checked >= 65, "{checked} fields checked");
}
