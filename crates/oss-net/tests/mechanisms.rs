//! The mechanism registry: one description per mechanism, and everything that
//! lists, orders or picks mechanisms read from it.
//!
//! The first test is the point of the module. A fourth mechanism,
//! `dummy@example.org`, is added to a client and to a server by **one
//! registration line each and no other change**, and that one line is enough
//! for it to take its place in the automatic order, to be chosen by name, to
//! appear in the start-up line, and to connect. The dummy is a trivial cipher
//! defined in this file, as anyone outside this crate would define theirs.
//!
//! The rest pin the rules around it: where a mechanism lands by strength, the
//! floor (`none` and anything weaker than the SubSpace cipher are never
//! automatic), which names are refused, how typed names match, and the ladder
//! that walks the automatic order.

use std::sync::{Arc, Mutex};

use oss_net::mechanism::ClientContext;
use oss_net::{
    Accept, Acceptor, Cipher, Config, Connection, Era, Event, Fallback, Handshake, Ladder,
    Mechanism, MechanismError, MechanismId, MechanismPolicy, MechanismRegistry, NullCipher,
    Selection, Server, Step,
};

/// How long the client waits on a silent rung, as the client does today.
const STEP_AFTER_MS: u64 = 1500;

// ---------------------------------------------------------------------------
// The dummy mechanism: a trivial cipher with both halves, defined the way a
// mechanism from outside this crate would be.
// ---------------------------------------------------------------------------

/// The dummy's opening. It starts `00 01`, the only openings a server offers to
/// its acceptors, and is 6 bytes, so neither the SubSpace acceptor (8 bytes)
/// nor the OpenSec one (90) takes it.
const DUMMY_HELLO: [u8; 6] = [0, 1, b'D', b'U', b'M', b'Y'];
/// The server's answer to it.
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

/// The dummy as a mechanism, at `strength`.
fn dummy_at(id: &str, display: &str, strength: u16, selection: Selection) -> Mechanism {
    Mechanism::new(id, display, Era::Modern, strength, selection)
        .unwrap()
        .client(|_| Box::new(DummyClient::default()))
        .server(|| Box::new(DummyAcceptor))
}

/// The dummy fourth mechanism: stronger than every built-in, so it is the
/// first rung of the automatic order.
fn dummy() -> Mechanism {
    dummy_at(
        "dummy@example.org",
        "Dummy",
        Mechanism::STRENGTH_OPENSEC + 1000,
        Selection::Automatic,
    )
}

// ---------------------------------------------------------------------------
// Running a client against a server.
// ---------------------------------------------------------------------------

/// What a run ended as.
#[derive(Debug, Default)]
struct Outcome {
    client_cipher: Option<&'static str>,
    server_cipher: Option<&'static str>,
}

/// Runs a client with `handshake` against a server with `acceptors` until the
/// client connects or 15 seconds pass.
fn connect(handshake: Box<dyn Handshake>, acceptors: Vec<Box<dyn Acceptor>>) -> Outcome {
    const ADDR: u32 = 1;
    let mut server: Server<u32> = Server::new(Config::server());
    for a in acceptors {
        server.add_acceptor(a);
    }
    let mut client = Connection::client(Config::client(), handshake, 0);
    let mut out = Outcome::default();
    let mut now = 0;
    while now < 15_000 && out.client_cipher.is_none() {
        now += 10;
        client.tick(now);
        while let Some(d) = client.poll_transmit() {
            server.handle_datagram(now, ADDR, &d);
        }
        server.tick(now);
        while server.poll_event().is_some() {}
        while let Some((_, d)) = server.poll_transmit() {
            client.handle_datagram(now, &d);
        }
        while let Some(ev) = client.poll_event() {
            if let Event::Connected = ev {
                out.client_cipher = client.cipher_name();
            }
        }
        out.server_cipher = server.connection(&ADDR).and_then(|c| c.cipher_name());
    }
    out
}

fn id(s: &str) -> MechanismId {
    MechanismId::new(s).unwrap()
}

/// A ladder's rungs, by identifier, first tried first.
#[cfg(feature = "opensec")]
fn rung_names(ladder: &Ladder) -> Vec<String> {
    ladder.progress().rungs().map(|r| r.to_string()).collect()
}

// ---------------------------------------------------------------------------
// One line, four effects.
// ---------------------------------------------------------------------------

/// The test the module exists for. Everything after each `register` line is
/// generic: it reads the registry, and nothing in it names the dummy except to
/// check the result.
#[test]
fn one_registration_line_has_all_four_effects() {
    let builtin = MechanismRegistry::builtin();
    let order_before = MechanismPolicy::automatic(&builtin).order().to_vec();
    let line_before = builtin.supported_line();

    // The client: the built-ins, and the one line.
    let mut client = MechanismRegistry::builtin();
    client.register(dummy()).unwrap();

    // The server: the built-ins, and the same one line.
    let mut server = MechanismRegistry::builtin();
    server.register(dummy()).unwrap();

    // 1. It takes its rank in the automatic order: strongest, so first.
    let policy = MechanismPolicy::automatic(&client);
    let mut expected = vec![id("dummy@example.org")];
    expected.extend(order_before);
    assert_eq!(policy.order(), expected);

    // 2. It can be selected by name.
    assert_eq!(
        client.find("dummy@example.org").unwrap().display_name(),
        "Dummy"
    );
    let mut by_name = client
        .client_handshake("dummy@example.org", &ClientContext::new(7))
        .unwrap();
    let mut first = Vec::new();
    by_name.poll(0, &mut first);
    assert_eq!(first, [DUMMY_HELLO.to_vec()]);

    // 3. It appears in the supported line, in its place (strongest, so last).
    assert_eq!(client.supported_line(), format!("{line_before}, Dummy"));

    // 4. A client connects to a server that registered the same one line.
    let ladder = policy
        .client_handshake(&client, &ClientContext::new(7), STEP_AFTER_MS)
        .unwrap();
    let progress = ladder.progress();
    let acceptors = MechanismPolicy::automatic(&server)
        .acceptors(&server)
        .unwrap();
    let out = connect(Box::new(ladder), acceptors);
    assert_eq!(out.client_cipher, Some("dummy"));
    assert_eq!(out.server_cipher, Some("dummy"));
    assert_eq!(progress.established(), Some(&id("dummy@example.org")));
    assert_eq!(progress.established_era(), Some(Era::Modern));
}

// ---------------------------------------------------------------------------
// Where a mechanism lands.
// ---------------------------------------------------------------------------

/// The built-ins' start-up line, exactly as `D37` gives it.
#[cfg(all(feature = "opensec", feature = "os-entropy"))]
#[test]
fn the_builtin_supported_line_is_exact() {
    let registry = MechanismRegistry::builtin();
    assert_eq!(
        registry.supported_line(),
        "Mechanisms supported: None, Subspace, OpenSecurity"
    );
    assert_eq!(
        MechanismPolicy::automatic(&registry).automatic_line(&registry),
        "Automatic order: OpenSecurity, then Subspace"
    );
    let ids: Vec<&str> = registry.ids().map(MechanismId::as_str).collect();
    assert_eq!(ids, ["none", "vie", "opensec"]);
}

/// Built without OpenSec, the line says so by leaving it out.
#[cfg(not(all(feature = "opensec", feature = "os-entropy")))]
#[test]
fn the_builtin_supported_line_without_opensec() {
    assert_eq!(
        MechanismRegistry::builtin().supported_line(),
        "Mechanisms supported: None, Subspace"
    );
}

/// A mechanism ranked between two others lands between them, and one ranked
/// below the SubSpace cipher lands below it. This is the proof that a
/// mechanism supplied from outside, registered with a strength between the
/// SubSpace cipher's and OpenSec's, takes the slot between them in the line
/// and in the automatic order, with no list written out anywhere.
#[cfg(feature = "opensec")]
#[test]
fn lower_and_mid_ranked_mechanisms_land_in_their_place() {
    let setup = || oss_net::mechanism::OpenSecSetup::new(fixed_entropy());

    // Below the floor, so by name only.
    let mut low = MechanismRegistry::builtin_with_opensec(setup());
    low.register(dummy_at(
        "low@example.org",
        "Dummy",
        Mechanism::STRENGTH_VIE / 2,
        Selection::ByNameOnly,
    ))
    .unwrap();
    assert_eq!(
        low.supported_line(),
        "Mechanisms supported: None, Dummy, Subspace, OpenSecurity"
    );
    assert_eq!(
        MechanismPolicy::automatic(&low).automatic_line(&low),
        "Automatic order: OpenSecurity, then Subspace"
    );

    // Between the SubSpace cipher and OpenSec.
    let mid_strength = (Mechanism::STRENGTH_VIE + Mechanism::STRENGTH_OPENSEC) / 2;
    let mut mid = MechanismRegistry::builtin_with_opensec(setup());
    mid.register(dummy_at(
        "mid@example.org",
        "Dummy",
        mid_strength,
        Selection::Automatic,
    ))
    .unwrap();
    assert_eq!(
        mid.supported_line(),
        "Mechanisms supported: None, Subspace, Dummy, OpenSecurity"
    );
    assert_eq!(
        MechanismPolicy::automatic(&mid).automatic_line(&mid),
        "Automatic order: OpenSecurity, then Dummy, then Subspace"
    );

    // The order mechanisms are registered in means nothing.
    let mut reversed = MechanismRegistry::new();
    for m in [
        dummy_at(
            "mid@example.org",
            "Dummy",
            mid_strength,
            Selection::Automatic,
        ),
        Mechanism::opensec(setup()),
        Mechanism::vie(),
        Mechanism::none(),
    ] {
        reversed.register(m).unwrap();
    }
    assert_eq!(reversed.supported_line(), mid.supported_line());
    assert_eq!(
        MechanismPolicy::automatic(&reversed),
        MechanismPolicy::automatic(&mid)
    );
}

/// Two mechanisms of equal strength are ordered by identifier, never by which
/// was registered first.
#[test]
fn equal_strengths_are_ordered_by_identifier() {
    let a = || dummy_at("a@example.org", "A", 2000, Selection::Automatic);
    let b = || dummy_at("b@example.org", "B", 2000, Selection::Automatic);
    let mut ab = MechanismRegistry::new();
    ab.register(a()).unwrap();
    ab.register(b()).unwrap();
    let mut ba = MechanismRegistry::new();
    ba.register(b()).unwrap();
    ba.register(a()).unwrap();
    assert_eq!(ab.supported_line(), "Mechanisms supported: A, B");
    assert_eq!(ba.supported_line(), ab.supported_line());
    assert_eq!(
        MechanismPolicy::automatic(&ab),
        MechanismPolicy::automatic(&ba)
    );
}

/// A mid-ranked mechanism is reached by walking the ladder down to it: the
/// server below does not speak OpenSec, so the first rung hears nothing, and
/// the client steps down to the dummy and connects.
#[cfg(feature = "opensec")]
#[test]
fn a_mid_ranked_mechanism_is_reached_by_stepping_down() {
    let mid = || {
        dummy_at(
            "mid@example.org",
            "Dummy",
            (Mechanism::STRENGTH_VIE + Mechanism::STRENGTH_OPENSEC) / 2,
            Selection::Automatic,
        )
    };
    let mut client = MechanismRegistry::builtin_with_opensec(
        oss_net::mechanism::OpenSecSetup::new(fixed_entropy()),
    );
    client.register(mid()).unwrap();

    let mut server = MechanismRegistry::new();
    server.register(Mechanism::vie()).unwrap();
    server.register(mid()).unwrap();

    let ladder = MechanismPolicy::automatic(&client)
        .client_handshake(&client, &ClientContext::new(7), STEP_AFTER_MS)
        .unwrap();
    let progress = ladder.progress();
    let rungs: Vec<&str> = progress.rungs().map(MechanismId::as_str).collect();
    assert_eq!(rungs, ["opensec", "mid@example.org", "vie"]);

    let out = connect(
        Box::new(ladder),
        MechanismPolicy::automatic(&server)
            .acceptors(&server)
            .unwrap(),
    );
    assert_eq!(out.client_cipher, Some("dummy"));
    assert_eq!(out.server_cipher, Some("dummy"));
    assert_eq!(progress.established(), Some(&id("mid@example.org")));
}

// ---------------------------------------------------------------------------
// The floor.
// ---------------------------------------------------------------------------

/// `none` cannot be put in the automatic order, by registration or by a
/// person's order; it is served only when switched on deliberately.
#[test]
fn none_cannot_be_put_in_the_automatic_order() {
    // Declared automatic, whatever strength it claims: refused.
    let mut registry = MechanismRegistry::new();
    let automatic_none = Mechanism::new("none", "None", Era::SubSpace, 5000, Selection::Automatic)
        .unwrap()
        .client(|_| Box::new(DummyClient::default()));
    assert_eq!(
        registry.register(automatic_none),
        Err(MechanismError::BelowFloor(id("none")))
    );

    // Anything weaker than the SubSpace cipher, declared automatic: refused.
    assert_eq!(
        registry.register(dummy_at(
            "weak@example.org",
            "Weak",
            Mechanism::STRENGTH_VIE - 1,
            Selection::Automatic,
        )),
        Err(MechanismError::BelowFloor(id("weak@example.org")))
    );

    // The built-in `none` is by name only, so no derived order holds it...
    let builtin = MechanismRegistry::builtin();
    assert!(!builtin.find("none").unwrap().is_automatic());
    let policy = MechanismPolicy::automatic(&builtin);
    assert!(!policy.order().contains(&id("none")));

    // ...and an order a person writes cannot hold it either.
    assert_eq!(
        MechanismPolicy::from_names(&builtin, ["vie", "none"]),
        Err(MechanismError::NotAutomatic(id("none")))
    );

    // Switched on deliberately, a server serves it after everything else, and
    // a client's ladder still does not try it.
    let allowed = policy.clone().allow_deliberately(&builtin, "none").unwrap();
    assert!(!allowed.order().contains(&id("none")));
    assert_eq!(allowed.deliberate(), [id("none")]);
    let ladder = allowed
        .client_handshake(&builtin, &ClientContext::new(7), STEP_AFTER_MS)
        .unwrap();
    assert!(ladder.progress().rungs().all(|r| r.as_str() != "none"));
    assert_eq!(
        allowed.acceptors(&builtin).unwrap().len(),
        policy.order().len() + 1
    );

    // Asked for by name, against a server that switched it on: connects in the
    // clear. Against one that did not: does not connect.
    let asked = || {
        builtin
            .client_handshake("none", &ClientContext::new(7))
            .unwrap()
    };
    let served = connect(asked(), allowed.acceptors(&builtin).unwrap());
    assert_eq!(served.client_cipher, Some("none"));
    let refused = connect(asked(), policy.acceptors(&builtin).unwrap());
    assert_eq!(refused.client_cipher, None);
}

/// A key on record means that mechanism and nothing else; a mechanism asked
/// for by name is used whatever key is on record.
#[cfg(feature = "opensec")]
#[test]
fn a_key_on_record_means_that_mechanism_only() {
    let registry = MechanismRegistry::builtin_with_opensec(oss_net::mechanism::OpenSecSetup::new(
        fixed_entropy(),
    ));
    let policy = MechanismPolicy::automatic(&registry);
    let pinned = ClientContext::new(7).pinned(id("opensec"), [9; 32]);

    let ladder = policy
        .client_handshake(&registry, &pinned, STEP_AFTER_MS)
        .unwrap();
    assert_eq!(rung_names(&ladder), ["opensec"], "no rung to step down to");

    // Without the key, the whole order.
    let open = policy
        .client_handshake(&registry, &ClientContext::new(7), STEP_AFTER_MS)
        .unwrap();
    assert_eq!(rung_names(&open), ["opensec", "vie"]);

    // A person asking for `none` or `vie` gets it, key or no key.
    let mut out = Vec::new();
    let mut none = registry.client_handshake("none", &pinned).unwrap();
    none.poll(0, &mut out);
    assert_eq!(
        out[0],
        [0, 1, 0, 0, 0, 0, 1, 0],
        "a request for no encryption"
    );
    out.clear();
    let mut vie = registry.client_handshake("VIE", &pinned).unwrap();
    vie.poll(0, &mut out);
    assert_eq!(out[0].len(), 8);
    assert_ne!(out[0][2..6], [0, 0, 0, 0], "an encrypted SubSpace request");

    // A key recorded by a mechanism this program does not have is not quietly
    // ignored.
    let unknown = ClientContext::new(7).pinned(id("dummy@example.org"), [9; 32]);
    assert!(matches!(
        policy.client_handshake(&registry, &unknown, STEP_AFTER_MS),
        Err(MechanismError::Unknown(_))
    ));
}

// ---------------------------------------------------------------------------
// Names.
// ---------------------------------------------------------------------------

#[test]
fn malformed_identifiers_are_refused() {
    let at_64 = format!("{}@example.org", "x".repeat(64 - "@example.org".len()));
    assert_eq!(at_64.len(), 64);
    assert!(MechanismId::new(&at_64).is_ok());
    let at_65 = format!("x{at_64}");

    for bad in [
        "",
        at_65.as_str(),
        "a b@example.org",
        "a,b@example.org",
        "@example.org",
        "a@b@example.org",
        "a@localhost",
        "a@-bad.example.org",
        "a@bad-.example.org",
        "a@exa_mple.org",
        "a@example..org",
        "\u{e9}@example.org",
        "a\t@example.org",
    ] {
        assert!(
            matches!(MechanismId::new(bad), Err(MechanismError::Malformed { .. })),
            "{bad:?} should be malformed"
        );
    }

    // A short name that is not this project's: not malformed, but not allowed.
    for unqualified in ["dtls", "subspace", "opensecurity", "dummy"] {
        assert_eq!(
            MechanismId::new(unqualified),
            Err(MechanismError::Unqualified(unqualified.to_owned()))
        );
    }

    // The project's own short names, in any case, are stored in lower case.
    assert_eq!(MechanismId::new("VIE").unwrap().as_str(), "vie");
    assert!(MechanismId::new("continuum").unwrap().is_reserved());
    assert!(!id("dummy@example.org").is_reserved());

    // And a mechanism cannot be described with a bad name of either kind.
    assert!(Mechanism::new("dtls", "DTLS", Era::Modern, 4000, Selection::Automatic).is_err());
    for display in ["", "  ", "A, B", "A\nB"] {
        assert!(
            matches!(
                Mechanism::new(
                    "x@example.org",
                    display,
                    Era::Modern,
                    4000,
                    Selection::Automatic
                ),
                Err(MechanismError::BadDisplayName { .. })
            ),
            "{display:?}"
        );
    }
}

#[test]
fn duplicates_are_refused() {
    let mut registry = MechanismRegistry::builtin();
    registry.register(dummy()).unwrap();
    assert_eq!(
        registry.register(dummy()),
        Err(MechanismError::DuplicateId(id("dummy@example.org")))
    );
    assert_eq!(
        registry.register(Mechanism::vie()),
        Err(MechanismError::DuplicateId(id("vie")))
    );
    // Another identifier with a display name already in the line, in any case.
    assert!(matches!(
        registry.register(dummy_at(
            "other@example.org",
            "dummy",
            2000,
            Selection::Automatic
        )),
        Err(MechanismError::DuplicateDisplayName(_))
    ));
    assert!(matches!(
        registry.register(dummy_at(
            "other@example.org",
            "SUBSPACE",
            2000,
            Selection::Automatic
        )),
        Err(MechanismError::DuplicateDisplayName(_))
    ));

    // An order a person writes: no repeats, no unknowns, not empty.
    assert_eq!(
        MechanismPolicy::from_names(&registry, ["vie", "Vie"]),
        Err(MechanismError::Repeated(id("vie")))
    );
    assert_eq!(
        MechanismPolicy::from_names(&registry, ["dtls"]),
        Err(MechanismError::Unknown("dtls".into()))
    );
    assert_eq!(
        MechanismPolicy::from_names(&registry, Vec::<&str>::new()),
        Err(MechanismError::Empty)
    );
    // A written order is kept as written.
    let written = MechanismPolicy::from_names(&registry, ["vie", "dummy@example.org"]).unwrap();
    assert_eq!(written.order(), [id("vie"), id("dummy@example.org")]);
}

/// `D37` point 5: this project's short names match without regard to case;
/// `name@domain` names match exactly. Display names are not typed words.
#[test]
fn typed_names_match_as_d37_says() {
    let mut registry = MechanismRegistry::builtin();
    registry.register(dummy()).unwrap();

    for typed in ["vie", "VIE", "Vie", " vie "] {
        assert_eq!(
            registry.find(typed).unwrap().id().as_str(),
            "vie",
            "{typed:?}"
        );
    }
    assert_eq!(registry.find("NONE").unwrap().id().as_str(), "none");
    #[cfg(all(feature = "opensec", feature = "os-entropy"))]
    assert_eq!(registry.find("OpenSec").unwrap().id().as_str(), "opensec");

    assert!(registry.find("dummy@example.org").is_some());
    assert!(registry.find("Dummy@example.org").is_none());
    assert!(registry.find("dummy@EXAMPLE.org").is_none());

    // No extra spellings: the line's words are not typed words.
    for display in ["Subspace", "subspace", "OpenSecurity", "Dummy"] {
        assert!(registry.find(display).is_none(), "{display:?}");
    }
    assert!(matches!(
        registry.client_handshake("subspace", &ClientContext::new(7)),
        Err(MechanismError::Unknown(_))
    ));
}

// ---------------------------------------------------------------------------
// The ladder.
// ---------------------------------------------------------------------------

/// A rung whose behaviour is chosen by what it is sent. Every poll emits
/// `[0xA0 + tag, polls so far]`; abandoning it emits `[0xEE, tag]` and logs.
struct Scripted {
    tag: u8,
    polls: u8,
    answered: bool,
    log: Arc<Mutex<Vec<String>>>,
}

impl Scripted {
    fn boxed(tag: u8, log: &Arc<Mutex<Vec<String>>>) -> Box<dyn Handshake> {
        Box::new(Self {
            tag,
            polls: 0,
            answered: false,
            log: log.clone(),
        })
    }
}

/// What a scripted rung is sent: `a` answers it, `f` fails it, `s` makes it
/// step down, `o` establishes it. Only the rung whose tag follows reacts.
fn say(what: u8, tag: u8) -> Vec<u8> {
    vec![what, tag]
}

impl Handshake for Scripted {
    fn on_datagram(&mut self, _now: u64, data: &[u8], _out: &mut Vec<Vec<u8>>) -> Step {
        match data {
            [b'a', t] if *t == self.tag => {
                self.answered = true;
                Step::Pending
            }
            [b'f', t] if *t == self.tag => Step::Failed("scripted failure"),
            [b's', t] if *t == self.tag => Step::StepDown("scripted step down"),
            [b'o', t] if *t == self.tag => Step::Established(Box::new(NullCipher)),
            _ => Step::Pending,
        }
    }
    fn poll(&mut self, _now: u64, out: &mut Vec<Vec<u8>>) -> Step {
        self.polls += 1;
        out.push(vec![0xA0 + self.tag, self.polls]);
        Step::Pending
    }
    fn answered(&self) -> bool {
        self.answered
    }
    fn abandon(&mut self, _now: u64, out: &mut Vec<Vec<u8>>) {
        self.log
            .lock()
            .unwrap()
            .push(format!("abandon {}", self.tag));
        out.push(vec![0xEE, self.tag]);
    }
}

fn ladder_of(n: u8, step_after_ms: u64) -> (Ladder, Arc<Mutex<Vec<String>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let rungs = (0..n)
        .map(|t| {
            (
                id(&format!("rung{t}@example.org")),
                Era::Modern,
                Scripted::boxed(t, &log),
            )
        })
        .collect();
    (Ladder::new(step_after_ms, rungs).unwrap(), log)
}

#[test]
fn the_ladder_steps_down_on_silence_through_every_rung() {
    let (mut ladder, log) = ladder_of(3, 100);
    let progress = ladder.progress();
    let mut out = Vec::new();

    assert!(matches!(ladder.poll(0, &mut out), Step::Pending));
    assert_eq!(out.pop(), Some(vec![0xA0, 1]));
    assert!(!ladder.take_fresh_endpoint());

    // Silence for the time limit: rung 0 is abandoned, nothing of rung 1 is
    // sent until the next poll, and a fresh endpoint is asked for once.
    assert!(matches!(ladder.poll(100, &mut out), Step::Pending));
    assert_eq!(out, [vec![0xEE, 0]]);
    out.clear();
    assert_eq!(progress.current().as_str(), "rung1@example.org");
    assert!(ladder.take_fresh_endpoint());
    assert!(!ladder.take_fresh_endpoint());

    // Rung 1's clock starts at its own first poll.
    ladder.poll(150, &mut out);
    assert_eq!(out.pop(), Some(vec![0xA1, 1]));
    ladder.poll(249, &mut out);
    assert_eq!(progress.current().as_str(), "rung1@example.org");
    out.clear();
    ladder.poll(250, &mut out);
    assert_eq!(out, [vec![0xEE, 1]]);
    assert_eq!(progress.current().as_str(), "rung2@example.org");

    // The last rung has no clock: it is never stepped down from.
    out.clear();
    for now in [300, 1_000, 60_000] {
        assert!(matches!(ladder.poll(now, &mut out), Step::Pending));
    }
    assert_eq!(progress.current().as_str(), "rung2@example.org");
    assert!(out.iter().all(|d| d[0] == 0xA2));
    assert_eq!(*log.lock().unwrap(), ["abandon 0", "abandon 1"]);
    assert_eq!(progress.established(), None);
}

#[test]
fn the_ladder_stops_on_a_failure() {
    let (mut ladder, log) = ladder_of(3, 100);
    let progress = ladder.progress();
    let mut out = Vec::new();
    ladder.poll(0, &mut out);
    ladder.poll(100, &mut out); // silence: down to rung 1
    ladder.poll(110, &mut out);
    let step = ladder.on_datagram(120, &say(b'f', 1), &mut out);
    assert!(matches!(step, Step::Failed("scripted failure")), "{step:?}");
    // Not stepped down, not abandoned: a failure is not a reason to try a
    // weaker mechanism.
    assert_eq!(progress.current().as_str(), "rung1@example.org");
    assert_eq!(*log.lock().unwrap(), ["abandon 0"]);
}

#[test]
fn the_ladder_stays_on_a_rung_that_has_answered() {
    let (mut ladder, _log) = ladder_of(3, 100);
    let progress = ladder.progress();
    let mut out = Vec::new();
    ladder.poll(0, &mut out);
    ladder.on_datagram(50, &say(b'a', 0), &mut out);
    assert!(ladder.answered());
    for now in [100, 1_000, 30_000] {
        assert!(matches!(ladder.poll(now, &mut out), Step::Pending));
    }
    assert_eq!(progress.current().as_str(), "rung0@example.org");
    let step = ladder.on_datagram(30_010, &say(b'o', 0), &mut out);
    assert!(matches!(step, Step::Established(_)), "{step:?}");
    assert_eq!(progress.established(), Some(&id("rung0@example.org")));
    assert_eq!(progress.established_era(), Some(Era::Modern));
}

#[test]
fn the_ladder_steps_down_at_once_on_a_recognised_answer() {
    let (mut ladder, log) = ladder_of(3, 1_000);
    let progress = ladder.progress();
    let mut out = Vec::new();
    ladder.poll(0, &mut out);
    out.clear();
    // Long before the clock: straight down, rung 0 closed.
    assert!(matches!(
        ladder.on_datagram(10, &say(b's', 0), &mut out),
        Step::Pending
    ));
    assert_eq!(out, [vec![0xEE, 0]]);
    assert_eq!(progress.current().as_str(), "rung1@example.org");
    assert!(ladder.take_fresh_endpoint());
    // The next rung hears datagrams at once, before its first poll.
    ladder.on_datagram(11, &say(b's', 1), &mut out);
    assert_eq!(progress.current().as_str(), "rung2@example.org");
    // From the last rung a step down has nowhere to go and is passed on, which
    // the connection treats as a failure.
    let step = ladder.on_datagram(12, &say(b's', 2), &mut out);
    assert!(matches!(step, Step::StepDown(_)), "{step:?}");
    assert_eq!(*log.lock().unwrap(), ["abandon 0", "abandon 1"]);
}

/// A two-rung ladder and a `Fallback` are the same thing: given the same
/// script they send the same datagrams, take the same steps, and abandon the
/// same rungs.
#[test]
fn a_two_rung_ladder_behaves_exactly_as_fallback() {
    type Script = Vec<(u64, Option<Vec<u8>>)>;
    let poll = |t| (t, None);
    let recv = |t, d| (t, Some(d));
    let scripts: Vec<Script> = vec![
        // Silence all the way.
        vec![poll(0), poll(50), poll(100), poll(150), poll(5_000)],
        // The first rung answers, then establishes late.
        vec![
            poll(0),
            recv(10, say(b'a', 0)),
            poll(100),
            poll(9_000),
            recv(9_001, say(b'o', 0)),
        ],
        // The first rung steps down at once; the second establishes.
        vec![
            poll(0),
            recv(5, say(b's', 0)),
            poll(6),
            recv(7, say(b'o', 1)),
        ],
        // The first rung fails.
        vec![poll(0), recv(5, say(b'f', 0)), poll(200)],
        // Down on silence, then the second rung steps down too.
        vec![poll(0), poll(100), poll(101), recv(102, say(b's', 1))],
    ];

    for script in scripts {
        let fb_log = Arc::new(Mutex::new(Vec::new()));
        let mut fallback = Fallback::new(
            Scripted::boxed(0, &fb_log),
            Scripted::boxed(1, &fb_log),
            100,
        );
        let (mut ladder, ld_log) = ladder_of(2, 100);
        for (now, datagram) in &script {
            let (mut fo, mut lo) = (Vec::new(), Vec::new());
            let (fs, ls) = match datagram {
                None => (fallback.poll(*now, &mut fo), ladder.poll(*now, &mut lo)),
                Some(d) => (
                    fallback.on_datagram(*now, d, &mut fo),
                    ladder.on_datagram(*now, d, &mut lo),
                ),
            };
            let context = format!("at {now} in {script:?}");
            assert_eq!(format!("{fs:?}"), format!("{ls:?}"), "{context}");
            assert_eq!(fo, lo, "{context}");
            assert_eq!(fallback.answered(), ladder.answered(), "{context}");
            assert_eq!(
                fallback.take_fresh_endpoint(),
                ladder.take_fresh_endpoint(),
                "{context}"
            );
        }
        assert_eq!(*fb_log.lock().unwrap(), *ld_log.lock().unwrap());
    }
}

#[test]
fn an_empty_ladder_or_policy_is_refused() {
    assert!(matches!(
        Ladder::new(100, Vec::new()),
        Err(MechanismError::Empty)
    ));
    // A registry whose only mechanism is by name only has no automatic order.
    let mut registry = MechanismRegistry::new();
    registry.register(Mechanism::none()).unwrap();
    let policy = MechanismPolicy::automatic(&registry);
    assert!(policy.order().is_empty());
    assert!(matches!(
        policy.client_handshake(&registry, &ClientContext::new(7), STEP_AFTER_MS),
        Err(MechanismError::Empty)
    ));
}

/// The server's line names what is switched on, weakest first.
#[cfg(all(feature = "opensec", feature = "os-entropy"))]
#[test]
fn the_enabled_line_reads_from_the_policy() {
    let registry = MechanismRegistry::builtin();
    let policy = MechanismPolicy::automatic(&registry);
    assert_eq!(
        policy.enabled_line(&registry),
        "Mechanisms enabled on this zone: Subspace, OpenSecurity"
    );
    let with_none = policy.allow_deliberately(&registry, "none").unwrap();
    assert_eq!(
        with_none.enabled_line(&registry),
        "Mechanisms enabled on this zone: None, Subspace, OpenSecurity"
    );
    let vie_only = MechanismPolicy::from_names(&registry, ["vie"]).unwrap();
    assert_eq!(
        vie_only.enabled_line(&registry),
        "Mechanisms enabled on this zone: Subspace"
    );
}

/// Deterministic randomness, so OpenSec runs are repeatable.
#[cfg(feature = "opensec")]
fn fixed_entropy() -> oss_net::opensec::Entropy {
    Arc::new(|buf: &mut [u8]| {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
    })
}
