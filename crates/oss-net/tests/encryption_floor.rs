//! What it takes to end up in a session with no encryption.
//!
//! The SubSpace-era handshake is two unauthenticated datagrams: the client
//! offers a key in a `00 01`, the server answers `00 02` with that key negated
//! (encrypt) or with the key itself (do not encrypt). Nothing signs either one,
//! so "the server said so" is not a thing this exchange can establish.
//!
//! Three ways into an unencrypted session existed in this crate, and each of
//! them is pinned below with the fault it used to be:
//!
//! 1. **The server answered a request for none.** A client key of 0 expands to
//!    no cipher, and `VieAcceptor` handed back the `NullCipher` that fell out of
//!    that. It now declines the request instead.
//! 2. **One forged datagram put a client in the clear.** A `00 02` echoing the
//!    client's own key back established a `NullCipher`, on the first connection,
//!    with no failed attempt and no step down. The client now refuses that
//!    answer unless it asked for an unencrypted session.
//! 3. **A forged request re-keyed a server connection.** Before a connection's
//!    session starts, a second `00 01` from its address re-runs the acceptors and
//!    replaces the cipher. With (1) closed there is no longer a reply that
//!    reaches `NullCipher` by that route in a default build.
//!
//! `rekey_window.rs` measures the window in (3); this file is about what can be
//! reached through it.

use oss_net::{
    Acceptor, Config, Connection, DisconnectReason, Event, Handshake, NullAcceptor, Server,
    VieAcceptor, VieClientHandshake,
};

/// The peer address the server knows the client by.
const ADDR: u32 = 1;

/// A game session's first reliable packet carries the player's password. Its
/// layout belongs to `oss-proto`, not here; what this file needs is a
/// recognisable run of bytes that must never appear on the wire unencrypted.
const PASSWORD: &[u8] = b"PASSWORD-MUST-NOT-APPEAR-IN-CLEAR";

fn login_packet() -> Vec<u8> {
    let mut p = vec![0x09];
    p.extend_from_slice(PASSWORD);
    p
}

/// What a run ended as.
#[derive(Debug)]
struct Outcome {
    /// The cipher the client settled on, if it connected.
    client_cipher: Option<&'static str>,
    /// The cipher the server settled on for `ADDR`, if it made a connection.
    server_cipher: Option<&'static str>,
    /// Why the client gave up, if it did.
    failure: Option<DisconnectReason>,
    /// Every datagram the client put on the wire.
    wire: Vec<Vec<u8>>,
}

impl Outcome {
    /// Whether the password went out in a form anyone on the path can read.
    fn password_in_the_clear(&self) -> bool {
        self.wire
            .iter()
            .any(|d| d.windows(PASSWORD.len()).any(|w| w == PASSWORD))
    }
}

/// Runs a client against a server to a 15-second deadline, sending the login
/// packet as soon as the client connects.
///
/// `inject` sees every datagram the client sends, in the same step, and returns
/// datagrams to hand the client as though they came from the server. That is an
/// attacker who can watch the path and send, which is all either of the forgery
/// tests below needs: no ability to modify or to suppress anything.
fn run(
    client_hs: Box<dyn Handshake>,
    acceptors: Vec<Box<dyn Acceptor>>,
    mut inject: impl FnMut(&[u8]) -> Vec<Vec<u8>>,
) -> Outcome {
    let mut server: Server<u32> = Server::new(Config::server());
    for a in acceptors {
        server.add_acceptor(a);
    }
    let mut client = Connection::client(Config::client(), client_hs, 0);
    let mut out = Outcome {
        client_cipher: None,
        server_cipher: None,
        failure: None,
        wire: Vec::new(),
    };
    let mut sent_login = false;
    let mut now = 0u64;
    while now < 15_000 {
        now += 10;
        client.tick(now);
        while let Some(d) = client.poll_transmit() {
            out.wire.push(d.clone());
            for forged in inject(&d) {
                client.handle_datagram(now, &forged);
            }
            server.handle_datagram(now, ADDR, &d);
        }
        server.tick(now);
        while server.poll_event().is_some() {}
        while let Some((_, d)) = server.poll_transmit() {
            client.handle_datagram(now, &d);
        }
        let mut finished = false;
        while let Some(ev) = client.poll_event() {
            match ev {
                Event::Connected => {
                    out.client_cipher = client.cipher_name();
                    if !sent_login {
                        client.send(&login_packet(), true);
                        sent_login = true;
                    }
                }
                Event::Disconnected(why) => {
                    out.failure = Some(why);
                    finished = true;
                }
                _ => {}
            }
        }
        out.server_cipher = out
            .server_cipher
            .or_else(|| server.connection(&ADDR).and_then(|c| c.cipher_name()));
        // Once the login has been flushed there is nothing further to learn.
        if finished || (sent_login && out.password_in_the_clear()) {
            break;
        }
        if sent_login && now > 2_000 {
            break;
        }
    }
    out
}

/// No attacker: every datagram reaches the server untouched.
fn quiet(_: &[u8]) -> Vec<Vec<u8>> {
    Vec::new()
}

/// The `00 01` a handshake emitted, as (key, protocol).
fn connect_request(d: &[u8]) -> Option<(u32, u16)> {
    (d.len() == 8 && d[0] == 0 && d[1] == 1 && d[7] == 0).then(|| {
        (
            u32::from_le_bytes([d[2], d[3], d[4], d[5]]),
            u16::from(d[6]),
        )
    })
}

/// `00 02 <key>`: an answer refusing encryption when `key` is the client's own.
fn connect_response(key: u32) -> Vec<u8> {
    let mut v = vec![0, 2];
    v.extend_from_slice(&key.to_le_bytes());
    v
}

/// A client asking for no encryption gets no answer from a VIE server, so no
/// connection is made at all. Fault (1): the acceptor used to answer it and
/// establish `NullCipher`.
#[test]
fn a_vie_server_does_not_answer_a_request_for_no_encryption() {
    let out = run(
        Box::new(VieClientHandshake::unencrypted()),
        vec![Box::new(VieAcceptor::default())],
        quiet,
    );
    assert_eq!(out.client_cipher, None, "the client must not connect");
    assert_eq!(
        out.server_cipher, None,
        "the server must make no connection"
    );
    assert!(
        matches!(out.failure, Some(DisconnectReason::HandshakeFailed(_))),
        "expected a handshake failure, got {:?}",
        out.failure
    );
    // The request itself is all that went out: nothing was answered, so the
    // login was never reached.
    assert!(!out.password_in_the_clear());
}

/// Fault (2), demonstrated and then closed. One datagram, sent by something that
/// can only watch the path and reply, used to put the whole session in the clear
/// on its first connection.
///
/// The first half of this test runs the pre-fix behaviour deliberately, through
/// `accept_refusal`, because a fix with no demonstration of what it fixes is a
/// claim. The second half is what ships.
#[test]
fn one_forged_datagram_no_longer_puts_a_client_in_the_clear() {
    // The forgery: read the key out of the client's own `00 01` and echo it
    // back. It needs no key material, no timing advantage over the server, and
    // no ability to stop the real answer.
    let forge = |d: &[u8]| match connect_request(d) {
        Some((key, _)) => vec![connect_response(key)],
        None => Vec::new(),
    };

    // As the code behaved before this change: the session is unencrypted and the
    // password goes out in a form anyone on the path can read.
    let exposed = run(
        Box::new(VieClientHandshake::new(0x1234_5678).accept_refusal()),
        vec![Box::new(VieAcceptor::default())],
        forge,
    );
    assert_eq!(exposed.client_cipher, Some("none"));
    assert!(
        exposed.password_in_the_clear(),
        "the demonstration must actually expose the password, or it proves nothing"
    );

    // As it behaves now: the answer is refused, the connection does not come up,
    // and nothing is sent that would have carried the password.
    let refused = run(
        Box::new(VieClientHandshake::new(0x1234_5678)),
        vec![Box::new(VieAcceptor::default())],
        forge,
    );
    assert_eq!(refused.client_cipher, None);
    assert!(
        matches!(refused.failure, Some(DisconnectReason::HandshakeFailed(_))),
        "expected a handshake failure, got {:?}",
        refused.failure
    );
    assert!(!refused.password_in_the_clear());
}

/// The same forgery against an undisturbed connection must not be able to
/// weaken it either: with nothing injected the pair settles on VIE and the
/// password never appears on the wire.
#[test]
fn an_ordinary_connection_still_encrypts() {
    let out = run(
        Box::new(VieClientHandshake::new(0x1234_5678)),
        vec![Box::new(VieAcceptor::default())],
        quiet,
    );
    assert_eq!(out.client_cipher, Some("vie"));
    assert_eq!(out.server_cipher, Some("vie"));
    assert_eq!(out.failure, None);
    assert!(!out.password_in_the_clear());
}

/// Both ends have to have asked. The null acceptor is registered behind VIE, so
/// it sees only the requests VIE declined, and a client that did not ask for an
/// unencrypted session refuses its answer.
#[test]
fn an_unencrypted_session_needs_both_ends_to_ask() {
    let both = || -> Vec<Box<dyn Acceptor>> {
        vec![Box::new(VieAcceptor::default()), Box::new(NullAcceptor)]
    };

    // Server allows it, client asked for it: an unencrypted session, by two
    // deliberate decisions.
    let agreed = run(Box::new(VieClientHandshake::unencrypted()), both(), quiet);
    assert_eq!(agreed.client_cipher, Some("none"));
    assert_eq!(agreed.server_cipher, Some("none"));

    // Server allows it, client did not ask: VIE, because VIE is asked first and
    // answers an ordinary key.
    let ordinary = run(
        Box::new(VieClientHandshake::new(0x1234_5678)),
        both(),
        quiet,
    );
    assert_eq!(ordinary.client_cipher, Some("vie"));
    assert_eq!(ordinary.server_cipher, Some("vie"));

    // Client asked, server does not allow it: no connection.
    let declined = run(
        Box::new(VieClientHandshake::unencrypted()),
        vec![Box::new(VieAcceptor::default())],
        quiet,
    );
    assert_eq!(declined.client_cipher, None);
}

/// Fault (3). Before a connection's session starts, a `00 01` from its address
/// re-runs the acceptors and replaces its cipher. A forged one asking for no
/// encryption now finds nothing in a default build willing to answer it, so the
/// server's half of an established VIE connection cannot be walked into the
/// clear by an attacker able to spoof the client's address.
#[test]
fn a_forged_request_cannot_rekey_a_server_connection_into_the_clear() {
    let mut server: Server<u32> = Server::new(Config::server());
    server.add_acceptor(Box::new(VieAcceptor::default()));
    let mut client = Connection::client(
        Config::client(),
        Box::new(VieClientHandshake::new(0x1234_5678)),
        0,
    );

    // Bring the connection up, but send nothing on it: `session_started` stays
    // false, which is exactly when the re-key path is open.
    let mut now = 0u64;
    let mut connected = false;
    while now < 5_000 && !connected {
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
            connected |= matches!(ev, Event::Connected);
        }
    }
    assert!(connected, "the connection must come up first");
    assert_eq!(
        server.connection(&ADDR).and_then(|c| c.cipher_name()),
        Some("vie")
    );

    // The forgery: a connection request from the client's address asking for no
    // encryption, while the window is open.
    let mut forged = vec![0u8, 1];
    forged.extend_from_slice(&0u32.to_le_bytes());
    forged.extend_from_slice(&1u16.to_le_bytes());
    server.handle_datagram(now, ADDR, &forged);

    assert_eq!(
        server.connection(&ADDR).and_then(|c| c.cipher_name()),
        Some("vie"),
        "a forged request for no encryption must not re-key the server"
    );
    // And nothing was answered, so the real client sees no stray `00 02`.
    assert!(
        server.poll_transmit().is_none(),
        "the forged request must draw no reply"
    );
}

/// The documented trap, now resolved towards encrypting. For the key
/// `0x80000000` the VIE answer and the refusal are the same six bytes; the
/// reference server keys VIE with it, so this crate does too. It used to read
/// the same answer as a refusal and run in the clear while the server encrypted.
#[test]
fn the_self_negating_key_resolves_to_vie() {
    let out = run(
        Box::new(VieClientHandshake::with_key(0x8000_0000, 0x01)),
        vec![Box::new(VieAcceptor::default())],
        quiet,
    );
    assert_eq!(out.client_cipher, Some("vie"));
    assert_eq!(out.server_cipher, Some("vie"));
    assert!(!out.password_in_the_clear());
}
