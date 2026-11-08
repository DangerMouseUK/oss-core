//! The offline checks: published test vectors turned into adapter requests and
//! expected responses (the protocol is in `docs/conformance.md`).
//!
//! The vector files are embedded, so the suite is self-contained. Most come
//! from running unmodified reference implementations (see each file's header);
//! `packets.txt`, `opensec.txt` and `relay.txt` are this project's canonical
//! encodings.

/// Embedded vector files: (name, contents).
pub const FILES: &[(&str, &str)] = &[
    ("vie.txt", include_str!("../vectors/vie.txt")),
    (
        "vie-exe-checksum.txt",
        include_str!("../vectors/vie-exe-checksum.txt"),
    ),
    (
        "position-checksum.txt",
        include_str!("../vectors/position-checksum.txt"),
    ),
    (
        "clientset-asss-public.txt",
        include_str!("../vectors/clientset-asss-public.txt"),
    ),
    (
        "clientset-subgame-svs.txt",
        include_str!("../vectors/clientset-subgame-svs.txt"),
    ),
    (
        "map-checksum-synthetic.txt",
        include_str!("../vectors/map-checksum-synthetic.txt"),
    ),
    ("opensec.txt", include_str!("../vectors/opensec.txt")),
    ("packets.txt", include_str!("../vectors/packets.txt")),
    ("relay.txt", include_str!("../vectors/relay.txt")),
    ("directory.txt", include_str!("../vectors/directory.txt")),
    (
        "billing-ssc.txt",
        include_str!("../vectors/billing-ssc.txt"),
    ),
];

/// Embedded map files used by the map checksum vectors.
pub const MAPS: &[(&str, &[u8])] = &[
    (
        "synth-a-plain.lvl",
        include_bytes!("../vectors/synth-a-plain.lvl"),
    ),
    (
        "synth-b-edges.lvl",
        include_bytes!("../vectors/synth-b-edges.lvl"),
    ),
    (
        "synth-c-elvl.lvl",
        include_bytes!("../vectors/synth-c-elvl.lvl"),
    ),
    (
        "synth-d-overflow.lvl",
        include_bytes!("../vectors/synth-d-overflow.lvl"),
    ),
];

/// What a correct adapter answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// Exactly this line (hex compared case-insensitively).
    Exact(String),
    /// A space-separated list that contains this item.
    Contains(String),
    /// The word `error`: the input must be rejected.
    Error,
}

/// One offline check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    /// Group (shown in reports), e.g. `vie.encrypt`.
    pub group: &'static str,
    /// Identifier within the group.
    pub id: String,
    /// The request line sent to the adapter.
    pub request: String,
    /// The expected answer.
    pub expect: Expect,
}

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parses hex; `None` if malformed.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s == "-" {
        return Some(Vec::new());
    }
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn records(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().collect())
}

fn file(name: &str) -> &'static str {
    FILES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, t)| *t)
        .unwrap_or("")
}

fn map(name: &str) -> Option<&'static [u8]> {
    MAPS.iter().find(|(n, _)| *n == name).map(|(_, b)| *b)
}

fn exact(group: &'static str, id: String, request: String, answer: impl Into<String>) -> Case {
    Case {
        group,
        id,
        request,
        expect: Expect::Exact(answer.into()),
    }
}

/// Every offline check, in a stable order.
pub fn cases() -> Vec<Case> {
    let mut v = Vec::new();
    vie(&mut v);
    exe(&mut v);
    position(&mut v);
    settings(&mut v, "clientset-asss-public.txt", "asss-public");
    settings(&mut v, "clientset-subgame-svs.txt", "subgame-svs");
    maps(&mut v, "map-checksum-synthetic.txt");
    opensec(&mut v);
    packets(&mut v);
    directory_and_billing(&mut v);
    relay(&mut v);
    v
}

fn directory_and_billing(v: &mut Vec<Case>) {
    for (i, f) in records(file("directory.txt")).enumerate() {
        if let ["update", _len, p] = f.as_slice() {
            v.push(exact(
                "packet.directory",
                format!("update-{i}"),
                format!("packet.roundtrip directory {p}"),
                *p,
            ));
        }
    }
    for f in records(file("billing-ssc.txt")) {
        if let [dir @ ("s2b" | "b2s"), name, _len, p] = f.as_slice() {
            v.push(exact(
                if *dir == "s2b" {
                    "packet.billing-s2b"
                } else {
                    "packet.billing-b2s"
                },
                (*name).to_owned(),
                format!("packet.roundtrip {dir} {p}"),
                *p,
            ));
        }
    }
}

fn vie(v: &mut Vec<Case>) {
    let mut n = 0;
    for f in records(file("vie.txt")) {
        n += 1;
        match f.as_slice() {
            ["keyexchange", key, request, response] => {
                v.push(exact(
                    "vie.connect",
                    format!("request-{key}"),
                    format!("vie.connect_request {key}"),
                    *request,
                ));
                // The server's key is in bytes 2..6 of its response.
                let r = unhex(response).unwrap_or_default();
                let server = r
                    .get(2..6)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                v.push(exact(
                    "vie.connect",
                    format!("server-key-{key}"),
                    format!("vie.server_key {key}"),
                    format!("{server:08x}"),
                ));
            }
            ["encrypt", key, plain, cipher] => v.push(exact(
                "vie.encrypt",
                format!("{n}"),
                format!("vie.encrypt {key} {plain}"),
                *cipher,
            )),
            ["decrypt", key, cipher, plain] => v.push(exact(
                "vie.decrypt",
                format!("{n}"),
                format!("vie.decrypt {key} {cipher}"),
                *plain,
            )),
            // Keystream tables and client state are internal to VIE; encrypt and
            // decrypt cover them.
            _ => {}
        }
    }
}

fn exe(v: &mut Vec<Case>) {
    for f in records(file("vie-exe-checksum.txt")) {
        if let ["exe", key, sum] = f.as_slice() {
            v.push(exact(
                "checksum.exe",
                (*key).to_owned(),
                format!("checksum.exe {key}"),
                *sum,
            ));
        }
    }
}

fn position(v: &mut Vec<Case>) {
    for (i, f) in records(file("position-checksum.txt")).enumerate() {
        match f.as_slice() {
            ["c2s", p] => v.push(exact(
                "checksum.position",
                format!("c2s-{i}"),
                format!("checksum.c2s_position_valid {p}"),
                "yes",
            )),
            ["c2s_bad", p] => v.push(exact(
                "checksum.position",
                format!("c2s-bad-{i}"),
                format!("checksum.c2s_position_valid {p}"),
                "no",
            )),
            ["s2c", p] => {
                let byte = unhex(p).and_then(|b| b.get(12).copied()).unwrap_or(0);
                v.push(exact(
                    "checksum.position",
                    format!("s2c-{i}"),
                    format!("checksum.s2c_weapon {p}"),
                    format!("{byte:02x}"),
                ));
            }
            _ => {}
        }
    }
}

fn settings(v: &mut Vec<Case>, name: &str, label: &str) {
    let mut packet = "";
    for f in records(file(name)) {
        match f.as_slice() {
            ["packet", p] => {
                packet = p;
                v.push(exact(
                    "settings.packet",
                    label.to_owned(),
                    format!("packet.roundtrip s2c {p}"),
                    *p,
                ));
            }
            ["checksum", key, sum] => v.push(exact(
                "checksum.settings",
                format!("{label}-{key}"),
                format!("checksum.settings {key} {packet}"),
                *sum,
            )),
            ["field", key, off, len, _value] => v.push(Case {
                group: "settings.layout",
                id: format!("{label}-{key}"),
                request: format!("settings.locate {key}"),
                expect: Expect::Contains(format!("{off}:{len}")),
            }),
            _ => {}
        }
    }
}

fn maps(v: &mut Vec<Case>, name: &str) {
    let mut current: Option<(&str, &[u8])> = None;
    for f in records(file(name)) {
        match f.as_slice() {
            // `map <label> [<source path>] <file name> <size> <crc32>`: read the
            // file name, size and CRC from the end.
            ["map", .., file, _size, crc] => {
                current = map(file).map(|b| (*file, b));
                if let Some((file, bytes)) = current {
                    v.push(exact(
                        "checksum.map",
                        format!("{file}-crc32"),
                        format!("checksum.crc32 {}", hex(bytes)),
                        *crc,
                    ));
                }
            }
            ["checksum", key, sum] => {
                if let Some((file, bytes)) = current {
                    v.push(exact(
                        "checksum.map",
                        format!("{file}-{key}"),
                        format!("checksum.map {key} {}", hex(bytes)),
                        *sum,
                    ));
                }
            }
            _ => {}
        }
    }
}

fn opensec(v: &mut Vec<Case>) {
    let mut case = String::new();
    let mut fields: Vec<(String, String)> = Vec::new();
    let get = |fields: &[(String, String)], k: &str| {
        fields
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "-".into())
    };
    for f in records(file("opensec.txt")) {
        match f.as_slice() {
            ["case", name] => {
                case = (*name).to_owned();
                fields.clear();
            }
            ["record", dir, counter, plain, wire] => {
                let key = get(&fields, if *dir == "c2s" { "key_c2s" } else { "key_s2c" });
                v.push(exact(
                    "opensec.record",
                    format!("{case}-{dir}-{counter}-seal"),
                    format!("opensec.seal {key} {dir} {counter} {plain}"),
                    *wire,
                ));
                v.push(exact(
                    "opensec.record",
                    format!("{case}-{dir}-{counter}-open"),
                    format!("opensec.open {key} {dir} {counter} {wire}"),
                    *plain,
                ));
                // A one-bit change must be rejected.
                let mut bad = unhex(wire).unwrap_or_default();
                if let Some(b) = bad.last_mut() {
                    *b ^= 1;
                }
                v.push(Case {
                    group: "opensec.record",
                    id: format!("{case}-{dir}-{counter}-tampered"),
                    request: format!("opensec.open {key} {dir} {counter} {}", hex(&bad)),
                    expect: Expect::Error,
                });
            }
            [k, val] => {
                fields.push(((*k).to_owned(), (*val).to_owned()));
                // Emit the handshake checks once the case's values are known.
                if *k == "key_s2c" {
                    let ce = get(&fields, "client_ephemeral_secret");
                    let se = get(&fields, "server_ephemeral_secret");
                    let ss = get(&fields, "server_static_secret");
                    let ci = get(&fields, "client_identity_secret");
                    // Optional trailing identity argument, only when there is one.
                    let id_arg = if ci == "-" {
                        String::new()
                    } else {
                        format!(" {ci}")
                    };
                    let server_caps = get(&fields, "server_caps");
                    let ch = get(&fields, "client_hello");
                    let sh = get(&fields, "server_hello");
                    let caps = unhex(&ch)
                        .and_then(|b| b.get(8..10).map(|c| u16::from_le_bytes([c[0], c[1]])))
                        .unwrap_or(0);
                    v.push(exact(
                        "opensec.handshake",
                        format!("{case}-client-hello"),
                        format!("opensec.client_hello {ce} {caps:04x}{id_arg}"),
                        ch.clone(),
                    ));
                    v.push(exact(
                        "opensec.handshake",
                        format!("{case}-server-hello"),
                        format!("opensec.server_hello {se} {ss} {server_caps} {ch}"),
                        sh.clone(),
                    ));
                    v.push(exact(
                        "opensec.handshake",
                        format!("{case}-client-keys"),
                        format!("opensec.client_keys {ce} {ch} {sh}{id_arg}"),
                        format!("{} {}", get(&fields, "key_c2s"), get(&fields, "key_s2c")),
                    ));
                }
            }
            _ => {}
        }
    }
}

fn packets(v: &mut Vec<Case>) {
    for (i, f) in records(file("packets.txt")).enumerate() {
        if let [dir, name, p] = f.as_slice() {
            let group = match *dir {
                "s2c" => "packet.s2c",
                "c2s" => "packet.c2s",
                _ => "packet.core",
            };
            v.push(exact(
                group,
                format!("{name}-{i}"),
                format!("packet.roundtrip {dir} {p}"),
                *p,
            ));
        }
    }
}

fn relay(v: &mut Vec<Case>) {
    for (i, f) in records(file("relay.txt")).enumerate() {
        match f.as_slice() {
            ["frame", p, "ok"] => v.push(exact(
                "relay.frame",
                format!("{i}"),
                format!("relay.frame {p}"),
                *p,
            )),
            ["frame", p, "error"] => v.push(Case {
                group: "relay.frame",
                id: format!("{i}-invalid"),
                request: format!("relay.frame {p}"),
                expect: Expect::Error,
            }),
            _ => {}
        }
    }
}
