//! The SDK against a scripted in-process zone built on `oss_net::Server`.

use oss_bot_sdk::{BotConfig, BotEvent, ChatKind, Session};
use oss_formats::{Level, TileEntry};
use oss_net::{Config, Event, Server, VieAcceptor};
use oss_proto::checksum::{crc32, map_checksum, settings_checksum, vie_exe_checksum};
use oss_proto::common::{PlayerData, chat_type};
use oss_proto::s2c::{self, ChatBody, MapFilename, login_code};
use oss_proto::{C2SPacket, ClientSettings, S2CPacket};

const BOT: i16 = 1;
const ALICE: i16 = 2;
const BOB: i16 = 3;
const KEY: u32 = 0x1234_5678;

fn player(pid: i16, name: &str, ship: i8) -> PlayerData {
    PlayerData {
        ship,
        accept_audio: 1,
        name: name.into(),
        squad: "".into(),
        kill_points: 0,
        flag_points: 0,
        pid,
        freq: 0,
        wins: 0,
        losses: 0,
        attached_to: -1,
        flags_carried: 0,
        misc_bits: 0,
    }
}

fn level() -> Vec<u8> {
    let mut tiles = Vec::new();
    for i in 0..1024u16 {
        tiles.push(TileEntry {
            x: i,
            y: (i * 7) % 1024,
            tile: (i % 160) as u8 + 1,
        });
    }
    Level {
        tiles,
        ..Level::default()
    }
    .to_bytes()
}

/// A zone that answers like a real one, records what the bot sends, and plays a
/// short script once the bot is in.
struct Zone {
    server: Server<u8>,
    got: Vec<C2SPacket>,
    settings: Vec<u8>,
    map: Vec<u8>,
}

impl Zone {
    fn new() -> Self {
        let mut server = Server::new(Config::server());
        server.add_acceptor(Box::new(VieAcceptor::default()));
        Self {
            server,
            got: Vec::new(),
            settings: S2CPacket::Settings(Box::default()).to_bytes(),
            map: level(),
        }
    }

    fn send(&mut self, p: impl Into<S2CPacket>) {
        let b = p.into().to_bytes();
        self.server.send(&0, &b, true);
    }

    fn on_packet(&mut self, p: C2SPacket) {
        match &p {
            C2SPacket::Login(l) => {
                let code = if l.flags == 0 {
                    login_code::NEW_USER
                } else {
                    login_code::OK
                };
                self.send(s2c::LoginResponse {
                    code,
                    server_version: 134,
                    ..Default::default()
                });
            }
            C2SPacket::GoArena(_) => {
                self.send(s2c::PlayerId {
                    pid: BOT,
                    extra: None,
                });
                let settings = self.settings.clone();
                self.server.send(&0, &settings, true);
                self.send(s2c::PlayerEntering {
                    players: vec![player(ALICE, "Alice", 2)],
                });
                self.send(s2c::PlayerEntering {
                    players: vec![player(BOT, "TestBot", 8)],
                });
                self.send(MapFilename::Single {
                    name: "test.lvl".into(),
                    checksum: crc32(&self.map),
                });
                self.send(s2c::EnteringArena {});
            }
            C2SPacket::MapRequest(_) => {
                let data = miniz_oxide::deflate::compress_to_vec_zlib(&self.map, 6);
                self.send(s2c::MapData {
                    name: "test.lvl".into(),
                    data,
                });
                // Now ask for checksums.
                self.send(s2c::Security {
                    green_seed: 1,
                    door_seed: 2,
                    timestamp: 3,
                    key: KEY,
                });
            }
            C2SPacket::SetShip(s) => {
                self.send(s2c::ShipChange {
                    ship: s.ship as i8,
                    pid: BOT,
                    freq: 0,
                });
                // The script: Bob arrives, pings, Carol pings from afar, a kill,
                // Bob leaves.
                self.send(s2c::PlayerEntering {
                    players: vec![player(BOB, "Bob", 1)],
                });
                self.send(s2c::S2CChat(ChatBody {
                    kind: chat_type::PUBLIC,
                    sound: 0,
                    pid: BOB,
                    text: b"!ping".to_vec(),
                }));
                self.send(s2c::S2CChat(ChatBody {
                    kind: chat_type::REMOTE_PRIVATE,
                    sound: 0,
                    pid: -1,
                    text: b"(Carol)> !ping".to_vec(),
                }));
                self.send(s2c::Kill {
                    green: 0,
                    killer: BOB,
                    killed: ALICE,
                    bounty: 25,
                    flags: 0,
                });
                self.send(s2c::PlayerLeaving { pid: BOB });
            }
            _ => {}
        }
        self.got.push(p);
    }
}

#[test]
fn bot_logs_in_answers_security_and_chats() {
    let mut zone = Zone::new();
    let config = BotConfig::new("TestBot", "pw").ship(1);
    let mut bot = Session::new(config, 0);
    let mut events = Vec::new();

    let mut now = 0;
    let mut stop_at = 10_000;
    while now < stop_at {
        now += 10;
        if stop_at == 10_000
            && events
                .iter()
                .any(|e| matches!(e, BotEvent::PlayerLeft { .. }))
        {
            // Let the last replies reach the zone.
            stop_at = now + 500;
        }
        bot.tick(now);
        zone.server.tick(now);
        while let Some(d) = bot.poll_transmit() {
            zone.server.handle_datagram(now, 0, &d);
        }
        while let Some((_, e)) = zone.server.poll_event() {
            if let Event::Packet(p) = e {
                zone.on_packet(C2SPacket::decode(&p).unwrap());
            }
        }
        while let Some((_, d)) = zone.server.poll_transmit() {
            bot.handle_datagram(now, &d);
        }
        while let Some(e) = bot.poll_event() {
            // The example bot's behaviour.
            match &e {
                BotEvent::PlayerEntered {
                    player,
                    initial: false,
                } => bot.send_private(player.pid, &format!("Welcome, {}!", player.name)),
                BotEvent::Chat(m) if m.text == "!ping" => bot.reply(m, "pong"),
                _ => {}
            }
            events.push(e);
        }
    }

    // Events, in order.
    let names: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            BotEvent::Connected => Some("connected"),
            BotEvent::LoggedIn => Some("logged in"),
            BotEvent::EnteredArena => Some("entered"),
            BotEvent::PlayerEntered { initial: true, .. } => Some("initial player"),
            BotEvent::PlayerEntered { initial: false, .. } => Some("player entered"),
            BotEvent::Chat(_) => Some("chat"),
            BotEvent::Kill { .. } => Some("kill"),
            BotEvent::PlayerLeft { .. } => Some("player left"),
            BotEvent::ShipChanged { .. } => Some("ship"),
            _ => None,
        })
        .collect();
    assert_eq!(
        names,
        [
            "connected",
            "logged in",
            "initial player",
            "initial player",
            "entered",
            "ship",
            "player entered",
            "chat",
            "chat",
            "kill",
            "player left",
        ]
    );
    let chats: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            BotEvent::Chat(m) => Some(m),
            _ => None,
        })
        .collect();
    assert_eq!(chats[0].kind, ChatKind::Public);
    assert_eq!(chats[0].from, Some(BOB));
    assert_eq!(chats[0].sender.as_deref(), Some("Bob"));
    assert_eq!(chats[1].kind, ChatKind::RemotePrivate);
    assert_eq!(chats[1].sender.as_deref(), Some("Carol"));
    assert_eq!(chats[1].text, "!ping");
    assert!(events.contains(&BotEvent::Kill {
        killer: BOB,
        killed: ALICE,
        bounty: 25
    }));

    // State.
    assert_eq!(bot.pid(), Some(BOT));
    assert!(bot.in_arena());
    assert_eq!(bot.player(ALICE).unwrap().losses, 1);
    assert!(bot.player(BOB).is_none());
    assert_eq!(bot.player_by_name("alice").unwrap().pid, ALICE);

    // What the zone received, in order of interest.
    let logins: Vec<u8> = zone
        .got
        .iter()
        .filter_map(|p| match p {
            C2SPacket::Login(l) => Some(l.flags),
            _ => None,
        })
        .collect();
    assert_eq!(logins, [0, 1], "retries as a new user");
    let security = zone
        .got
        .iter()
        .find_map(|p| match p {
            C2SPacket::SecurityResponse(s) => Some(s.clone()),
            _ => None,
        })
        .expect("security response");
    let settings_bytes = S2CPacket::Settings(Box::<ClientSettings>::default()).to_bytes();
    assert_eq!(
        security.settings_checksum,
        settings_checksum(KEY, &settings_bytes)
    );
    assert_eq!(security.exe_checksum, vie_exe_checksum(KEY));
    let grid = Level::parse(&level()).unwrap().server_tile_grid().0;
    assert_eq!(
        security.map_checksum,
        map_checksum(KEY, |x, y| grid.get(x as u32, y as u32))
    );
    assert!(
        zone.got
            .iter()
            .any(|p| matches!(p, C2SPacket::SetShip(s) if s.ship == 1))
    );
    let chats: Vec<(u8, i16, String)> = zone
        .got
        .iter()
        .filter_map(|p| match p {
            C2SPacket::Chat(c) => Some((
                c.0.kind,
                c.0.pid,
                String::from_utf8(c.0.text.clone()).unwrap(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        chats,
        [
            (chat_type::PRIVATE, BOB, "Welcome, Bob!".to_owned()),
            (chat_type::PRIVATE, BOB, "pong".to_owned()),
            (chat_type::REMOTE_PRIVATE, -1, ":Carol:pong".to_owned()),
        ]
    );
    assert!(
        zone.got
            .iter()
            .filter(|p| matches!(p, C2SPacket::Position(_)))
            .count()
            >= 2,
        "sends positions"
    );

    // Leaving politely.
    bot.disconnect();
    assert!(bot.is_closed());
    assert!(matches!(
        bot.poll_event(),
        Some(BotEvent::Disconnected(oss_bot_sdk::DisconnectReason::Local))
    ));
}

#[test]
fn login_failure_is_reported() {
    let mut server: Server<u8> = Server::new(Config::server());
    server.add_acceptor(Box::new(VieAcceptor::default()));
    let mut bot = Session::new(BotConfig::new("X", "wrong"), 0);
    let mut failed = None;
    for now in (10..5_000).step_by(10) {
        bot.tick(now);
        server.tick(now);
        while let Some(d) = bot.poll_transmit() {
            server.handle_datagram(now, 0, &d);
        }
        while let Some((_, e)) = server.poll_event() {
            if let Event::Packet(p) = e
                && let Ok(C2SPacket::Login(_)) = C2SPacket::decode(&p)
            {
                let r = S2CPacket::from(s2c::LoginResponse {
                    code: login_code::BAD_PASSWORD,
                    ..Default::default()
                });
                server.send(&0, &r.to_bytes(), true);
            }
        }
        while let Some((_, d)) = server.poll_transmit() {
            bot.handle_datagram(now, &d);
        }
        while let Some(e) = bot.poll_event() {
            if let BotEvent::LoginFailed { code, reason } = e {
                failed = Some((code, reason));
            }
        }
        if bot.is_closed() {
            break;
        }
    }
    assert_eq!(failed, Some((login_code::BAD_PASSWORD, "wrong password")));
    assert!(bot.is_closed());
}
