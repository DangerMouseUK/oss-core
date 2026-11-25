//! The bot's security mechanisms: which ones it can speak, which one it uses,
//! and the one registration line that adds another.
//!
//! The first test is the point. A mechanism from outside this crate,
//! `dummy@example.org`, is added to a bot and to a zone with **one
//! `register` line each**, and the bot logs in over it. The bot's default is
//! the automatic order, so the one line is all it takes.
//!
//! The rest pin what goes on the wire. The automatic order, which is now the
//! default, walks OpenSec, then Subspace, stepping down after 1000 ms, exactly
//! as the library's automatic choice did before mechanisms were registered; a
//! mechanism of middle strength is tried between the two; a key on record
//! gives one rung; and the SubSpace cipher asked for by name is that and
//! nothing else, which was the default until the bot was made to negotiate as
//! the client does.

use oss_bot_sdk::{
    BotConfig, BotEvent, Encryption, Mechanism, MechanismError, MechanismId, MechanismRegistry,
    Session,
};
use oss_net::mechanism::{Era, OpenSecSetup, Selection};
use oss_net::opensec::{ServerKey, os_entropy};
use oss_net::{Accept, Acceptor, Cipher, Config, Event, Handshake, MechanismPolicy, Server, Step};
use oss_proto::s2c::{self, login_code};
use oss_proto::{C2SPacket, S2CPacket};

// ---------------------------------------------------------------------------
// The dummy mechanism, defined as anyone outside oss-core would define theirs.
// ---------------------------------------------------------------------------

/// The dummy's opening: `00 01`, the only openings a server offers its
/// acceptors, and 6 bytes, so neither built-in acceptor takes it.
const DUMMY_HELLO: [u8; 6] = [0, 1, b'D', b'U', b'M', b'Y'];
/// The zone's answer to it.
const DUMMY_REPLY: [u8; 6] = [0, 2, b'Y', b'M', b'U', b'D'];

/// XORs every byte. Secures nothing; it only has to be its own cipher.
struct DummyCipher;

impl Cipher for DummyCipher {
    fn encrypt(&mut self, datagram: &mut Vec<u8>) {
        datagram.iter_mut().for_each(|b| *b ^= 0x5A);
    }
    fn decrypt(&mut self, datagram: &mut Vec<u8>) -> bool {
        datagram.iter_mut().for_each(|b| *b ^= 0x5A);
        true
    }
    fn name(&self) -> &'static str {
        "dummy"
    }
}

/// Sends the hello every 250 ms until answered, for up to 10 s.
#[derive(Default)]
struct DummyClient {
    started: Option<u64>,
    last_sent: Option<u64>,
}

impl Handshake for DummyClient {
    fn on_datagram(&mut self, _now: u64, data: &[u8], _out: &mut Vec<Vec<u8>>) -> Step {
        if data == DUMMY_REPLY {
            Step::Established(Box::new(DummyCipher))
        } else {
            Step::Pending
        }
    }
    fn poll(&mut self, now: u64, out: &mut Vec<Vec<u8>>) -> Step {
        let started = *self.started.get_or_insert(now);
        if now - started >= 10_000 {
            return Step::Failed("no answer to the dummy hello");
        }
        if self.last_sent.is_none_or(|t| now - t >= 250) {
            out.push(DUMMY_HELLO.to_vec());
            self.last_sent = Some(now);
        }
        Step::Pending
    }
}

struct DummyAcceptor;

impl Acceptor for DummyAcceptor {
    fn accept(&self, _now: u64, first: &[u8], out: &mut Vec<Vec<u8>>) -> Option<Accept> {
        (first == DUMMY_HELLO).then(|| {
            out.push(DUMMY_REPLY.to_vec());
            Accept::Established(Box::new(DummyCipher))
        })
    }
}

/// The dummy: stronger than every built-in, so first in the automatic order.
fn dummy() -> Mechanism {
    Mechanism::new(
        "dummy@example.org",
        "Dummy",
        Era::Modern,
        Mechanism::STRENGTH_OPENSEC + 1000,
        Selection::Automatic,
    )
    .unwrap()
    .client(|_| Box::new(DummyClient::default()))
    .server(|| Box::new(DummyAcceptor))
}

fn id(s: &str) -> MechanismId {
    MechanismId::new(s).unwrap()
}

// ---------------------------------------------------------------------------
// A zone that serves a registry's automatic order and accepts any login.
// ---------------------------------------------------------------------------

/// How a run against a zone ended.
#[derive(Debug, Default)]
struct Outcome {
    logged_in: bool,
    bot_cipher: Option<&'static str>,
    zone_cipher: Option<&'static str>,
    /// Fresh endpoints the bot asked for.
    fresh: u32,
    /// SubSpace connection requests (`00 01`, 8 bytes) sent before any
    /// cipher was in place.
    subspace_requests: u32,
}

/// Runs `bot` against a zone whose acceptors are `zone`'s automatic order,
/// until the bot has logged in or 10 seconds pass. A fresh endpoint is taken
/// the way `run` takes it: the zone meets the next attempt at a new address.
fn log_in(bot: &mut Session, zone: &MechanismRegistry) -> Outcome {
    let mut server: Server<u32> = Server::new(Config::server());
    for a in MechanismPolicy::automatic(zone).acceptors(zone).unwrap() {
        server.add_acceptor(a);
    }
    let mut addr = 1;
    let mut out = Outcome::default();
    let mut now = 0;
    while now < 10_000 && !out.logged_in {
        now += 10;
        bot.tick(now);
        while let Some(d) = bot.poll_transmit() {
            if bot.connection().cipher_name().is_none() && d.len() == 8 && d[..2] == [0, 1] {
                out.subspace_requests += 1;
            }
            server.handle_datagram(now, addr, &d);
        }
        if bot.take_fresh_endpoint() {
            out.fresh += 1;
            addr += 1;
        }
        server.tick(now);
        while let Some((_, e)) = server.poll_event() {
            if let Event::Packet(p) = e
                && let Ok(C2SPacket::Login(_)) = C2SPacket::decode(&p)
            {
                let r = S2CPacket::from(s2c::LoginResponse {
                    code: login_code::OK,
                    server_version: 134,
                    ..Default::default()
                });
                server.send(&addr, &r.to_bytes(), true);
            }
        }
        while let Some((_, d)) = server.poll_transmit() {
            bot.handle_datagram(now, &d);
        }
        while let Some(e) = bot.poll_event() {
            if let BotEvent::LoggedIn = e {
                out.logged_in = true;
            }
        }
    }
    out.bot_cipher = bot.connection().cipher_name();
    out.zone_cipher = server.connection(&addr).and_then(|c| c.cipher_name());
    out
}

// ---------------------------------------------------------------------------
// What a bot sends to a zone that never answers.
// ---------------------------------------------------------------------------

/// One thing the bot did, at a time in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    /// An OpenSec hello.
    OpenSecHello(u64),
    /// A SubSpace connection request (`00 01`, 8 bytes).
    SubSpaceRequest(u64),
    /// A request for a fresh endpoint: a step down.
    FreshEndpoint(u64),
}

/// Everything a bot with `config` sends in its first three seconds to a zone
/// that never answers, ticking every 10 ms.
fn silence(config: BotConfig) -> Vec<Sent> {
    let mut bot = Session::new(config, 0).unwrap();
    let mut sent = Vec::new();
    for now in (0..3_000).step_by(10) {
        bot.tick(now);
        while let Some(d) = bot.poll_transmit() {
            sent.push(if oss_net::opensec::is_client_hello(&d) {
                Sent::OpenSecHello(now)
            } else {
                assert_eq!((d.len(), &d[..2]), (8, &[0, 1][..]), "at {now}: {d:02x?}");
                Sent::SubSpaceRequest(now)
            });
        }
        if bot.take_fresh_endpoint() {
            sent.push(Sent::FreshEndpoint(now));
        }
    }
    sent
}

/// OpenSec hellos every 250 ms from `from` until before `until`.
fn hellos(from: u64, until: u64) -> impl Iterator<Item = Sent> {
    (from..until).step_by(250).map(Sent::OpenSecHello)
}

// ---------------------------------------------------------------------------
// The tests.
// ---------------------------------------------------------------------------

/// One `register` line on the bot and the same one line on the zone: the bot
/// logs in over the dummy. Nothing else in this test names it except to check
/// the result.
#[test]
fn one_registration_line_lets_a_bot_connect_with_a_new_mechanism() {
    let mut config = BotConfig::new("bot", "pw");
    config.mechanisms.register(dummy()).unwrap();

    let mut zone = MechanismRegistry::builtin();
    zone.register(dummy()).unwrap();

    // The line a bot would log, and the order it will try, read from the
    // registry.
    assert_eq!(
        config.mechanisms.supported_line(),
        "Mechanisms supported: None, Subspace, OpenSecurity, Dummy"
    );
    assert_eq!(
        MechanismPolicy::automatic(&config.mechanisms).automatic_line(&config.mechanisms),
        "Automatic order: Dummy, then OpenSecurity, then Subspace"
    );

    let mut bot = Session::new(config.clone(), 0).unwrap();
    let out = log_in(&mut bot, &zone);
    assert!(out.logged_in, "{out:?}");
    assert_eq!(out.bot_cipher, Some("dummy"));
    assert_eq!(out.zone_cipher, Some("dummy"));
    assert_eq!(out.fresh, 0, "the first rung answered");
    let progress = bot.automatic_progress().expect("automatic");
    assert_eq!(progress.established(), Some(&id("dummy@example.org")));
    assert_eq!(progress.established_era(), Some(Era::Modern));

    // Asked for by name, it is the only mechanism tried, and it connects.
    let mut bot = Session::new(
        config
            .clone()
            .encryption(Encryption::named("dummy@example.org")),
        0,
    )
    .unwrap();
    let out = log_in(&mut bot, &zone);
    assert!(out.logged_in, "{out:?}");
    assert_eq!(out.bot_cipher, Some("dummy"));
    assert!(bot.automatic_progress().is_none());

    // Against a zone without it, the automatic order steps down past it after
    // a second and connects with the next, OpenSec.
    let mut bot = Session::new(config, 0).unwrap();
    let out = log_in(&mut bot, &MechanismRegistry::builtin());
    assert!(out.logged_in, "{out:?}");
    assert_eq!(out.bot_cipher, Some("opensec"));
    assert_eq!(out.fresh, 1);
    assert_eq!(
        bot.automatic_progress().unwrap().established(),
        Some(&id("opensec"))
    );
}

/// The default is the automatic order, as the graphical client's is: OpenSec
/// hellos every 250 ms, one fresh endpoint at 1000 ms, then a SubSpace
/// connection request every second. Against a zone that serves OpenSec it
/// connects with OpenSec, without stepping down.
#[test]
fn the_default_is_the_automatic_order() {
    let config = BotConfig::new("bot", "pw");
    assert_eq!(config.encryption, Encryption::Automatic);
    assert_eq!(config.encryption, Encryption::default());
    assert!(config.pinned.is_none());

    let bot = Session::new(config.clone(), 0).unwrap();
    let rungs: Vec<_> = bot.automatic_progress().unwrap().rungs().cloned().collect();
    assert_eq!(rungs, [id("opensec"), id("vie")]);

    let mut expected: Vec<Sent> = hellos(0, 1_000).collect();
    expected.extend([
        Sent::FreshEndpoint(1_000),
        Sent::SubSpaceRequest(1_010),
        Sent::SubSpaceRequest(2_010),
    ]);
    assert_eq!(silence(config.clone()), expected);

    let mut bot = Session::new(config, 0).unwrap();
    let out = log_in(&mut bot, &MechanismRegistry::builtin());
    assert!(out.logged_in, "{out:?}");
    assert_eq!(out.bot_cipher, Some("opensec"));
    assert_eq!(out.zone_cipher, Some("opensec"));
    assert_eq!(out.fresh, 0);
}

/// The default order is read from the registry by strength, never written
/// out: a mechanism registered between the SubSpace cipher and OpenSec in
/// strength is tried between them, whatever order it was registered in.
/// This is where a mechanism of middle strength supplied from elsewhere goes.
#[test]
fn a_mid_ranked_mechanism_lands_between_opensec_and_subspace_by_default() {
    let middle = || {
        Mechanism::new(
            "middle@example.org",
            "Middle",
            Era::Modern,
            (Mechanism::STRENGTH_VIE + Mechanism::STRENGTH_OPENSEC) / 2,
            Selection::Automatic,
        )
        .unwrap()
        .client(|_| Box::new(DummyClient::default()))
        .server(|| Box::new(DummyAcceptor))
    };

    let mut config = BotConfig::new("bot", "pw");
    config.mechanisms.register(middle()).unwrap();
    let bot = Session::new(config.clone(), 0).unwrap();
    let rungs: Vec<_> = bot.automatic_progress().unwrap().rungs().cloned().collect();
    assert_eq!(
        rungs,
        [id("opensec"), id("middle@example.org"), id("vie")],
        "by strength, strongest first"
    );
    assert_eq!(
        MechanismPolicy::automatic(&config.mechanisms).automatic_line(&config.mechanisms),
        "Automatic order: OpenSecurity, then Middle, then Subspace"
    );

    // Registered first, into an empty registry, it lands in the same place.
    let mut first = BotConfig::new("bot", "pw");
    first.mechanisms = MechanismRegistry::new();
    first.mechanisms.register(middle()).unwrap();
    for m in MechanismRegistry::builtin().iter() {
        first.mechanisms.register(m.clone()).unwrap();
    }
    let bot = Session::new(first, 0).unwrap();
    let again: Vec<_> = bot.automatic_progress().unwrap().rungs().cloned().collect();
    assert_eq!(again, rungs);

    // Against a zone without OpenSec, the default steps down once, to the
    // mechanism in the middle, and logs in over it.
    let mut zone = MechanismRegistry::new();
    zone.register(Mechanism::vie()).unwrap();
    zone.register(middle()).unwrap();
    let mut bot = Session::new(config, 0).unwrap();
    let out = log_in(&mut bot, &zone);
    assert!(out.logged_in, "{out:?}");
    assert_eq!(out.bot_cipher, Some("dummy"));
    assert_eq!(out.fresh, 1);
    assert_eq!(
        bot.automatic_progress().unwrap().established(),
        Some(&id("middle@example.org"))
    );
}

/// The SubSpace cipher asked for by name, the default until the bot was
/// made to negotiate as the client does, is still that and nothing else: a
/// connection request every second, never an OpenSec hello, never a step
/// down. Registering another mechanism does not change that.
#[test]
fn vie_by_name_is_vie_only() {
    let config = BotConfig::new("bot", "pw").encryption(Encryption::named("vie"));

    let vie_only = vec![
        Sent::SubSpaceRequest(0),
        Sent::SubSpaceRequest(1_000),
        Sent::SubSpaceRequest(2_000),
    ];
    assert_eq!(silence(config.clone()), vie_only);

    let mut with_dummy = config.clone();
    with_dummy.mechanisms.register(dummy()).unwrap();
    assert_eq!(silence(with_dummy), vie_only);

    // Against a zone that serves OpenSec too, it still connects with VIE.
    let mut bot = Session::new(config, 0).unwrap();
    assert!(bot.automatic_progress().is_none());
    let out = log_in(&mut bot, &MechanismRegistry::builtin());
    assert!(out.logged_in, "{out:?}");
    assert_eq!(out.bot_cipher, Some("vie"));
    assert_eq!(out.zone_cipher, Some("vie"));
}

/// A key on record for OpenSec gives one rung: OpenSec, never a step down to
/// the SubSpace cipher, whether OpenSec is asked for by name or the automatic
/// order is used.
#[test]
fn a_pinned_opensec_key_gives_one_rung() {
    let key = [7u8; 32];
    let opensec_only: Vec<Sent> = hellos(0, 3_000).collect();

    let automatic = BotConfig::new("bot", "pw").pinned(id("opensec"), key);
    let bot = Session::new(automatic.clone(), 0).unwrap();
    let rungs: Vec<_> = bot.automatic_progress().unwrap().rungs().cloned().collect();
    assert_eq!(rungs, [id("opensec")]);
    assert_eq!(silence(automatic), opensec_only);

    let named = BotConfig::new("bot", "pw")
        .encryption(Encryption::named("opensec"))
        .pinned(id("opensec"), key);
    assert_eq!(silence(named), opensec_only);

    // OpenSec by name without a key is OpenSec alone too.
    let unpinned = BotConfig::new("bot", "pw").encryption(Encryption::named("opensec"));
    assert_eq!(silence(unpinned), opensec_only);

    // A key on record does not choose the mechanism: with VIE by name, the
    // key is not used.
    let vie_with_key = BotConfig::new("bot", "pw")
        .encryption(Encryption::named("vie"))
        .pinned(id("opensec"), key);
    assert_eq!(
        silence(vie_with_key),
        [
            Sent::SubSpaceRequest(0),
            Sent::SubSpaceRequest(1_000),
            Sent::SubSpaceRequest(2_000)
        ]
    );
}

/// The key on record reaches the handshake, by name and automatically: a zone
/// holding that key is reached over OpenSec, and a zone holding another key is
/// not reached at all, with no step down to the SubSpace cipher.
#[test]
fn a_pinned_opensec_key_is_enforced() {
    let held = ServerKey::from_secret([3; 32]);
    let other = ServerKey::from_secret([4; 32]);
    let zone = MechanismRegistry::builtin_with_opensec(
        OpenSecSetup::new(os_entropy()).server_key(held.clone()),
    );
    for encryption in [Encryption::Automatic, Encryption::named("opensec")] {
        let right = BotConfig::new("bot", "pw")
            .encryption(encryption.clone())
            .pinned(id("opensec"), held.public());
        let out = log_in(&mut Session::new(right, 0).unwrap(), &zone);
        assert!(out.logged_in, "{encryption:?}: {out:?}");
        assert_eq!(out.bot_cipher, Some("opensec"), "{encryption:?}");

        let wrong = BotConfig::new("bot", "pw")
            .encryption(encryption.clone())
            .pinned(id("opensec"), other.public());
        let out = log_in(&mut Session::new(wrong, 0).unwrap(), &zone);
        assert!(!out.logged_in, "{encryption:?}: {out:?}");
        assert_eq!(out.bot_cipher, None, "{encryption:?}");
        assert_eq!(out.fresh, 0, "{encryption:?}");
        assert_eq!(out.subspace_requests, 0, "{encryption:?}");
    }
}

/// Automatic: OpenSec first, a hello every 250 ms; after 1000 ms without an
/// answer one fresh endpoint and a step down to the SubSpace cipher, whose
/// first request goes out on the next tick.
#[test]
fn automatic_walks_opensec_then_subspace_at_1000_ms() {
    let config = BotConfig::new("bot", "pw").encryption(Encryption::Automatic);

    let mut bot = Session::new(config.clone(), 0).unwrap();
    let progress = bot.automatic_progress().unwrap().clone();
    let rungs: Vec<_> = progress.rungs().cloned().collect();
    assert_eq!(rungs, [id("opensec"), id("vie")]);
    assert_eq!(
        MechanismPolicy::automatic(&config.mechanisms).automatic_line(&config.mechanisms),
        "Automatic order: OpenSecurity, then Subspace"
    );
    for now in (0..990).step_by(10) {
        bot.tick(now);
        while bot.poll_transmit().is_some() {}
    }
    assert_eq!(progress.current(), &id("opensec"));
    for now in (990..1_020).step_by(10) {
        bot.tick(now);
        while bot.poll_transmit().is_some() {}
    }
    assert_eq!(progress.current(), &id("vie"));
    assert_eq!(progress.current_era(), Era::SubSpace);

    let mut expected: Vec<Sent> = hellos(0, 1_000).collect();
    expected.extend([
        Sent::FreshEndpoint(1_000),
        Sent::SubSpaceRequest(1_010),
        Sent::SubSpaceRequest(2_010),
    ]);
    assert_eq!(silence(config), expected);
}

/// A configuration that asks for something the registry does not hold is
/// refused before anything is sent, and `run` reports it as invalid input.
#[test]
fn a_mechanism_the_bot_does_not_have_is_refused() {
    let unknown = BotConfig::new("bot", "pw").encryption(Encryption::named("dtls@example.org"));
    assert!(matches!(
        Session::new(unknown.clone(), 0),
        Err(MechanismError::Unknown(name)) if name == "dtls@example.org"
    ));

    let pinned_elsewhere = BotConfig::new("bot", "pw")
        .encryption(Encryption::Automatic)
        .pinned(id("dummy@example.org"), [1; 32]);
    assert!(matches!(
        Session::new(pinned_elsewhere, 0),
        Err(MechanismError::Unknown(_))
    ));

    let empty = BotConfig {
        mechanisms: MechanismRegistry::new(),
        ..BotConfig::new("bot", "pw").encryption(Encryption::Automatic)
    };
    assert!(matches!(Session::new(empty, 0), Err(MechanismError::Empty)));

    // Typed names follow the registry's rules: short names in any case.
    assert!(
        Session::new(
            BotConfig::new("bot", "pw").encryption(Encryption::named("VIE")),
            0
        )
        .is_ok()
    );

    let err = oss_bot_sdk::run("127.0.0.1:9", unknown, &mut |_: &mut Session, _| {}).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}
