//! The suite run against oss-core itself: the offline checks with the reference
//! adapter (in process and as a child process), the live client checks against
//! an `oss-bot-sdk` bot, and the live server checks against a small zone built
//! on `oss-net`.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use oss_conformance::adapter::{self, Process, Reference};
use oss_conformance::live::{self, ClientOptions, ServerOptions};
use oss_conformance::{Report, Status, vectors};
use oss_net::{Config, Event, Server, VieAcceptor};
use oss_proto::checksum::crc32;
use oss_proto::common::PlayerData;
use oss_proto::s2c::{self, MapFilename, login_code};
use oss_proto::wire::FixedStr;
use oss_proto::{C2SPacket, S2CPacket};

fn assert_all_pass(r: &Report, what: &str) {
    assert!(r.passed(), "{what}:\n{}", r.render(true, 100));
}

#[test]
fn vectors_pass_in_process() {
    let cases = vectors::cases();
    assert!(cases.len() > 3_700, "{} cases", cases.len());
    let r = adapter::run(&mut Reference, &cases, None).unwrap();
    assert_all_pass(&r, "reference adapter");
    assert_eq!(r.count(Status::Skip), 0);
}

#[test]
fn vectors_pass_through_a_child_process() {
    let mut p = Process::spawn(env!("CARGO_BIN_EXE_oss-conformance"), &["adapter".into()]).unwrap();
    // A subset keeps the test quick; the in-process test covers everything.
    let cases: Vec<_> = vectors::cases()
        .into_iter()
        .filter(|c| !c.group.starts_with("vie.") && c.group != "settings.layout")
        .collect();
    let r = adapter::run(&mut p, &cases, None).unwrap();
    assert_all_pass(&r, "child adapter");
}

#[test]
fn broken_implementations_fail() {
    /// Answers like the reference, except for one command.
    struct Broken(&'static str);
    impl adapter::Adapter for Broken {
        fn call(&mut self, request: &str) -> std::io::Result<String> {
            let mut a = adapter::reference(request);
            if request.starts_with(self.0) {
                a = a.chars().rev().collect();
            }
            Ok(a)
        }
    }
    let cases = vectors::cases();
    for cmd in [
        "vie.encrypt",
        "checksum.map",
        "packet.roundtrip",
        "opensec.open",
    ] {
        let r = adapter::run(&mut Broken(cmd), &cases, None).unwrap();
        assert!(!r.passed(), "{cmd} breakage went unnoticed");
    }
    struct Unsupported;
    impl adapter::Adapter for Unsupported {
        fn call(&mut self, _: &str) -> std::io::Result<String> {
            Ok("unsupported".into())
        }
    }
    let r = adapter::run(&mut Unsupported, &cases, None).unwrap();
    assert_eq!(r.count(Status::Skip), cases.len());
}

/// The embedded copies must match the vectors the other crates test against.
#[test]
fn vector_copies_match_their_sources() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let pairs = [
        ("oss-net/tests/vectors/vie.txt", "vie.txt"),
        ("oss-net/tests/vectors/opensec.txt", "opensec.txt"),
        (
            "oss-proto/tests/vectors/vie-exe-checksum.txt",
            "vie-exe-checksum.txt",
        ),
        (
            "oss-proto/tests/vectors/position-checksum.txt",
            "position-checksum.txt",
        ),
        (
            "oss-proto/tests/vectors/clientset-asss-public.txt",
            "clientset-asss-public.txt",
        ),
        (
            "oss-proto/tests/vectors/clientset-subgame-svs.txt",
            "clientset-subgame-svs.txt",
        ),
        (
            "oss-formats/tests/vectors/map-checksum-synthetic.txt",
            "map-checksum-synthetic.txt",
        ),
    ];
    let norm = |s: String| s.replace("\r\n", "\n");
    for (src, name) in pairs {
        let Ok(original) = std::fs::read_to_string(format!("{root}/{src}")) else {
            eprintln!("skipped {src}: not present");
            continue;
        };
        let copy = vectors::FILES.iter().find(|(n, _)| *n == name).unwrap().1;
        assert_eq!(
            norm(original),
            norm(copy.to_owned()),
            "{name} differs from {src}"
        );
    }
    if let Ok(original) = std::fs::read(format!("{root}/oss-formats/tests/fixtures/smallmap.lvl")) {
        let copy = vectors::MAPS
            .iter()
            .find(|(n, _)| *n == "smallmap.lvl")
            .unwrap()
            .1;
        assert_eq!(original, copy);
    }
    // The smallmap checksums are the smallmap block of the full map vectors.
    if let Ok(full) =
        std::fs::read_to_string(format!("{root}/oss-formats/tests/vectors/map-checksum.txt"))
    {
        let copy = vectors::FILES
            .iter()
            .find(|(n, _)| *n == "map-checksum-smallmap.txt")
            .unwrap()
            .1;
        let full = norm(full);
        for line in copy.lines().filter(|l| !l.starts_with('#')) {
            assert!(
                full.lines().any(|l| l == line),
                "{line} not in map-checksum.txt"
            );
        }
    }
}

#[test]
fn client_checks_pass_for_the_bot_sdk() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let bot = thread::spawn(move || {
        let config = oss_bot_sdk::BotConfig::new("ConformanceBot", "pw");
        oss_bot_sdk::run(addr, config, &mut |_: &mut oss_bot_sdk::Session, _| {})
    });
    let opts = ClientOptions {
        connect_timeout: Duration::from_secs(10),
        timeout: Duration::from_secs(8),
        ..ClientOptions::default()
    };
    let r = live::check_client(sock, &opts).unwrap();
    assert_all_pass(&r, "client checks");
    assert!(r.count(Status::Pass) >= 14, "{}", r.render(true, 100));
    // The suite disconnected the bot.
    let _ = bot.join().unwrap();
}

/// A small zone: login, arena entry with the reference settings packet, map
/// download and a security request.
fn zone(sock: UdpSocket, stop: Arc<AtomicBool>) {
    sock.set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    let mut server: Server<SocketAddr> = Server::new(Config::server());
    server.add_acceptor(Box::new(VieAcceptor::default()));
    let start = Instant::now();
    let map: &[u8] = vectors::MAPS[0].1;
    let settings = S2CPacket::Settings(Box::default()).to_bytes();
    let mut buf = [0u8; 2048];
    let mut names = std::collections::HashMap::new();
    while !stop.load(Ordering::Relaxed) {
        let now = start.elapsed().as_millis() as u64;
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            server.handle_datagram(now, from, &buf[..n]);
        }
        server.tick(now);
        while let Some((from, e)) = server.poll_event() {
            let Event::Packet(p) = e else { continue };
            let mut reply = |p: S2CPacket| {
                server.send(&from, &p.to_bytes(), true);
            };
            match C2SPacket::decode(&p) {
                Ok(C2SPacket::Login(l)) => {
                    names.insert(from, l.name);
                    reply(
                        s2c::LoginResponse {
                            code: login_code::OK,
                            server_version: 134,
                            ..Default::default()
                        }
                        .into(),
                    );
                }
                Ok(C2SPacket::GoArena(_)) => {
                    let name = names.get(&from).cloned().unwrap_or_default();
                    reply(
                        s2c::PlayerId {
                            pid: 1,
                            extra: None,
                        }
                        .into(),
                    );
                    server.send(&from, &settings, true);
                    let mut reply = |p: S2CPacket| {
                        server.send(&from, &p.to_bytes(), true);
                    };
                    reply(
                        s2c::PlayerEntering {
                            players: vec![PlayerData {
                                ship: 8,
                                accept_audio: 1,
                                name: FixedStr::new(name.as_bytes()),
                                squad: FixedStr::default(),
                                kill_points: 0,
                                flag_points: 0,
                                pid: 1,
                                freq: 0,
                                wins: 0,
                                losses: 0,
                                attached_to: -1,
                                flags_carried: 0,
                                misc_bits: 0,
                            }],
                        }
                        .into(),
                    );
                    reply(
                        MapFilename::Single {
                            name: "smallmap.lvl".into(),
                            checksum: crc32(map),
                        }
                        .into(),
                    );
                    reply(s2c::EnteringArena {}.into());
                }
                Ok(C2SPacket::MapRequest(_)) => {
                    reply(
                        s2c::MapData {
                            name: "smallmap.lvl".into(),
                            data: miniz_oxide::deflate::compress_to_vec_zlib(map, 9),
                        }
                        .into(),
                    );
                    reply(
                        s2c::Security {
                            green_seed: 1,
                            door_seed: 2,
                            timestamp: 3,
                            key: 0xCAFE_F00D,
                        }
                        .into(),
                    );
                }
                _ => {}
            }
        }
        while let Some((to, d)) = server.poll_transmit() {
            let _ = sock.send_to(&d, to);
        }
    }
}

#[test]
fn server_checks_pass_for_an_oss_net_zone() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let z = {
        let stop = stop.clone();
        thread::spawn(move || zone(sock, stop))
    };
    let r = live::check_server(addr, &ServerOptions::default()).unwrap();
    stop.store(true, Ordering::Relaxed);
    z.join().unwrap();
    assert_all_pass(&r, "server checks");
    assert!(r.count(Status::Pass) >= 20, "{}", r.render(true, 100));
}
