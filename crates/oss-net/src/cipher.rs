//! Encryption plug-in points: [`Cipher`] (per-connection packet transform),
//! [`Handshake`] (connection setup state machine) and [`Acceptor`] (server-side
//! recognition of a new connection from its first datagram).
//!
//! The transport never inspects key material. A cipher implementation outside
//! this crate (for example a Continuum-compatible one) plugs in by implementing
//! these traits:
//!
//! * server side: an [`Acceptor`] that recognises the client's first datagram
//!   (e.g. `00 01` with protocol `0x0011`), sends its raw replies and returns a
//!   pending [`Handshake`] that consumes the remaining setup datagrams (e.g.
//!   `00 11`) and finally yields a [`Cipher`];
//! * client side: a [`Handshake`] that emits the first datagram from
//!   [`Handshake::poll`] and yields a [`Cipher`] once the server's `00 02` arrives;
//! * in session: core packets with subtype `0x10` or above are passed to
//!   [`Cipher::handle_core`], which may send replies (e.g. key-expansion
//!   requests/responses) through [`CipherContext`].

use crate::vie::{self, VieCipher};

/// A per-connection packet transform applied to whole datagrams.
pub trait Cipher: Send {
    /// Encrypts an outgoing datagram in place (it may grow).
    fn encrypt(&mut self, datagram: &mut Vec<u8>);

    /// Decrypts an incoming datagram in place. Returning `false` drops it.
    fn decrypt(&mut self, datagram: &mut Vec<u8>) -> bool;

    /// Handles an in-session core packet with subtype `0x10` or above (after
    /// decryption and unwrapping). Packets this cipher does not use are ignored.
    fn handle_core(&mut self, _now: u64, _packet: &[u8], _ctx: &mut CipherContext<'_>) {}

    /// Called on every transport tick; lets the cipher start in-session
    /// exchanges.
    fn poll(&mut self, _now: u64, _ctx: &mut CipherContext<'_>) {}

    /// Short name for logs ("none", "vie", ...).
    fn name(&self) -> &'static str;

    /// Bytes [`Cipher::encrypt`] may add to a datagram. The connection keeps
    /// plaintext datagrams this much smaller than [`crate::Config::max_send`]
    /// and accepts this much more than [`crate::Config::max_recv`].
    fn overhead(&self) -> usize {
        0
    }

    /// The peer's long-term public key, if the cipher authenticated one (e.g. an
    /// OpenSec server key a client can pin).
    fn peer_key(&self) -> Option<[u8; 32]> {
        None
    }

    /// Which encryption family this is. Servers use it to tell SubSpace (VIE)
    /// clients from Continuum clients, e.g. for the login packet length check.
    /// External implementations should override it; the default is
    /// [`CipherKind::Other`].
    fn kind(&self) -> CipherKind {
        CipherKind::Other
    }
}

/// Encryption family of a [`Cipher`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CipherKind {
    /// No encryption.
    None,
    /// SubSpace VIE encryption.
    Vie,
    /// Continuum encryption (provided by an external implementation).
    Continuum,
    /// OpenSec (X25519 + ChaCha20-Poly1305), this project's encryption.
    OpenSec,
    /// Some other implementation.
    Other,
}

/// Lets a [`Cipher`] queue packets on its connection.
#[derive(Debug)]
pub struct CipherContext<'a> {
    pub(crate) out: &'a mut Vec<(Vec<u8>, bool)>,
}

impl CipherContext<'_> {
    /// Queues a packet (normally a core packet) for sending through the
    /// connection, reliably or not. It is encrypted like any other traffic.
    pub fn send(&mut self, packet: &[u8], reliable: bool) {
        self.out.push((packet.to_vec(), reliable));
    }
}

/// Progress of a [`Handshake`].
pub enum Step {
    /// Still negotiating.
    Pending,
    /// Done; use this cipher for the session.
    Established(Box<dyn Cipher>),
    /// Negotiation failed (e.g. the server refused with `00 07`, or a timeout).
    Failed(&'static str),
}

impl core::fmt::Debug for Step {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pending => f.write_str("Pending"),
            Self::Established(c) => write!(f, "Established({})", c.name()),
            Self::Failed(r) => write!(f, "Failed({r})"),
        }
    }
}

/// A connection-setup state machine. Datagrams it receives and sends are raw
/// (not passed through any session cipher); it may decrypt them itself if its
/// protocol encrypts part of the setup.
pub trait Handshake: Send {
    /// Handles a datagram received during setup. Raw replies go to `out`.
    fn on_datagram(&mut self, now: u64, data: &[u8], out: &mut Vec<Vec<u8>>) -> Step;

    /// Timer: send the first/next setup datagram, resend, or give up.
    fn poll(&mut self, now: u64, out: &mut Vec<Vec<u8>>) -> Step;
}

/// Tries one handshake, then switches to another if the first gets no answer
/// within a time limit. Typical use: OpenSec first, VIE for servers that do not
/// speak it. A *failure* of the first (for example a server key that does not
/// match a pinned key) ends the handshake instead of falling back, so an
/// attacker cannot force a downgrade by tampering; dropping packets still can,
/// so clients that pinned a server key should not use a fallback at all.
pub struct Fallback {
    primary: Box<dyn Handshake>,
    secondary: Box<dyn Handshake>,
    switch_after_ms: u64,
    started: Option<u64>,
    on_secondary: bool,
}

impl core::fmt::Debug for Fallback {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fallback")
            .field("switch_after_ms", &self.switch_after_ms)
            .field("on_secondary", &self.on_secondary)
            .finish_non_exhaustive()
    }
}

impl Fallback {
    /// Runs `primary` for up to `switch_after_ms`, then `secondary`.
    pub fn new(
        primary: Box<dyn Handshake>,
        secondary: Box<dyn Handshake>,
        switch_after_ms: u64,
    ) -> Self {
        Self {
            primary,
            secondary,
            switch_after_ms,
            started: None,
            on_secondary: false,
        }
    }

    /// Whether the fallback handshake is in use.
    pub fn on_secondary(&self) -> bool {
        self.on_secondary
    }
}

impl Handshake for Fallback {
    fn on_datagram(&mut self, now: u64, data: &[u8], out: &mut Vec<Vec<u8>>) -> Step {
        if self.on_secondary {
            self.secondary.on_datagram(now, data, out)
        } else {
            // A failure of the primary (e.g. a server key that does not match a
            // pinned key) ends the handshake: switching would be a downgrade.
            self.primary.on_datagram(now, data, out)
        }
    }

    fn poll(&mut self, now: u64, out: &mut Vec<Vec<u8>>) -> Step {
        let started = *self.started.get_or_insert(now);
        if !self.on_secondary && now.saturating_sub(started) >= self.switch_after_ms {
            self.on_secondary = true;
        }
        if self.on_secondary {
            self.secondary.poll(now, out)
        } else {
            self.primary.poll(now, out)
        }
    }
}

/// Outcome of [`Acceptor::accept`].
pub enum Accept {
    /// The connection is ready immediately with this cipher.
    Established(Box<dyn Cipher>),
    /// More setup datagrams are needed.
    Pending(Box<dyn Handshake>),
}

impl core::fmt::Debug for Accept {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Established(c) => write!(f, "Established({})", c.name()),
            Self::Pending(_) => f.write_str("Pending"),
        }
    }
}

/// Server side: recognises a new connection from its first datagram.
pub trait Acceptor: Send + Sync {
    /// Inspects the first raw datagram from an unknown address (or a repeated
    /// connection request from a connection that has not started its session
    /// yet). Returns `None` if this acceptor does not handle it. Raw replies
    /// (e.g. `00 02`) go to `out`.
    fn accept(&self, now: u64, first: &[u8], out: &mut Vec<Vec<u8>>) -> Option<Accept>;
}

/// No encryption.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullCipher;

impl Cipher for NullCipher {
    fn encrypt(&mut self, _datagram: &mut Vec<u8>) {}
    fn decrypt(&mut self, _datagram: &mut Vec<u8>) -> bool {
        true
    }
    fn name(&self) -> &'static str {
        "none"
    }
    fn kind(&self) -> CipherKind {
        CipherKind::None
    }
}

impl Cipher for VieCipher {
    fn encrypt(&mut self, datagram: &mut Vec<u8>) {
        VieCipher::encrypt(self, datagram);
    }
    fn decrypt(&mut self, datagram: &mut Vec<u8>) -> bool {
        VieCipher::decrypt(self, datagram);
        true
    }
    fn name(&self) -> &'static str {
        "vie"
    }
    fn kind(&self) -> CipherKind {
        CipherKind::Vie
    }
}

/// Builds the cipher for a negotiated VIE key (key 0 means no encryption).
pub fn vie_cipher(key: u32) -> Box<dyn Cipher> {
    match VieCipher::new(key) {
        Some(c) => Box::new(c),
        None => Box::new(NullCipher),
    }
}

/// `00 01` connection request: (client key, protocol), if `data` is one.
pub fn parse_connect(data: &[u8]) -> Option<(u32, u16)> {
    if data.len() == 8 && data[0] == 0 && data[1] == 1 && data[7] == 0 {
        Some((
            u32::from_le_bytes([data[2], data[3], data[4], data[5]]),
            u16::from(data[6]),
        ))
    } else {
        None
    }
}

fn connect_response(key: u32) -> Vec<u8> {
    let mut v = vec![0, 2];
    v.extend_from_slice(&key.to_le_bytes());
    v
}

/// Server-side VIE acceptor: answers `00 01` (protocol 1, and optionally the
/// Continuum protocol `0x11` as a fallback) with `00 02` carrying the negated
/// client key, and encrypts with that key.
#[derive(Debug, Clone, Copy)]
pub struct VieAcceptor {
    /// Also accept Continuum clients (protocol `0x11`) with VIE encryption.
    pub accept_continuum: bool,
}

impl Default for VieAcceptor {
    fn default() -> Self {
        Self {
            accept_continuum: true,
        }
    }
}

impl Acceptor for VieAcceptor {
    fn accept(&self, _now: u64, first: &[u8], out: &mut Vec<Vec<u8>>) -> Option<Accept> {
        let (key, proto) = parse_connect(first)?;
        if proto != 0x01 && !(self.accept_continuum && proto == 0x11) {
            return None;
        }
        let server_key = vie::server_key_for(key);
        out.push(connect_response(server_key));
        Some(Accept::Established(vie_cipher(server_key)))
    }
}

/// Server-side acceptor for unencrypted sessions: echoes the client's key, which
/// tells clients to disable encryption. Accepts both protocols.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullAcceptor;

impl Acceptor for NullAcceptor {
    fn accept(&self, _now: u64, first: &[u8], out: &mut Vec<Vec<u8>>) -> Option<Accept> {
        let (key, proto) = parse_connect(first)?;
        if proto != 0x01 && proto != 0x11 {
            return None;
        }
        out.push(connect_response(key));
        Some(Accept::Established(Box::new(NullCipher)))
    }
}

/// Datagrams a [`VieClientHandshake`] remembers for its failure message.
const REMEMBERED: usize = 2;
/// Leading bytes kept from each remembered datagram.
const REMEMBERED_PREFIX: usize = 8;

/// Client-side VIE handshake: sends `00 01` (resending every
/// [`VieClientHandshake::RESEND_MS`]) until the server answers `00 02`.
///
/// Anything else that arrives during setup is remembered rather than dropped
/// silently, so that a handshake which times out can say whether it heard nothing
/// at all or heard something it could not use. See
/// [`unrecognised`](Self::unrecognised).
#[derive(Debug, Clone)]
pub struct VieClientHandshake {
    key: u32,
    protocol: u16,
    started: Option<u64>,
    last_sent: Option<u64>,
    timeout_ms: u64,
    /// First `REMEMBERED` datagrams that were not a usable `00 02`, truncated.
    seen: [[u8; REMEMBERED_PREFIX]; REMEMBERED],
    /// How many bytes of each `seen` entry are real.
    seen_len: [u8; REMEMBERED],
    /// How many arrived in all (may exceed `REMEMBERED`).
    seen_count: u32,
}

impl VieClientHandshake {
    /// Resend interval for `00 01`.
    pub const RESEND_MS: u64 = 1000;

    /// A VIE handshake with a client key derived from `seed` (top bit set).
    pub fn new(seed: u32) -> Self {
        Self::with_key(vie::client_key_from_seed(seed), 0x01)
    }

    /// Requests an unencrypted session (client key 0).
    pub fn unencrypted() -> Self {
        Self::with_key(0, 0x01)
    }

    /// A handshake with an explicit key and protocol word (`0x01` SubSpace,
    /// `0x11` Continuum — only useful against servers that fall back to VIE).
    pub fn with_key(key: u32, protocol: u16) -> Self {
        Self {
            key,
            protocol,
            started: None,
            last_sent: None,
            timeout_ms: 10_000,
            seen: [[0; REMEMBERED_PREFIX]; REMEMBERED],
            seen_len: [0; REMEMBERED],
            seen_count: 0,
        }
    }

    /// Gives up after this long without an answer (default 10 s).
    pub fn timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    fn request(&self) -> Vec<u8> {
        let mut v = vec![0, 1];
        v.extend_from_slice(&self.key.to_le_bytes());
        v.extend_from_slice(&self.protocol.to_le_bytes());
        v
    }

    /// Datagrams that arrived during setup without answering the connection
    /// request: the first two, each truncated to its leading 8 bytes. Empty when
    /// the server really did say nothing.
    pub fn unrecognised(&self) -> impl Iterator<Item = &[u8]> {
        let n = (self.seen_count as usize).min(REMEMBERED);
        (0..n).map(move |i| &self.seen[i][..self.seen_len[i] as usize])
    }

    /// How many datagrams arrived during setup without answering the connection
    /// request. Can exceed what [`unrecognised`](Self::unrecognised) returns.
    pub fn unrecognised_count(&self) -> u32 {
        self.seen_count
    }

    fn remember(&mut self, data: &[u8]) {
        let slot = self.seen_count as usize;
        if slot < REMEMBERED {
            let n = data.len().min(REMEMBERED_PREFIX);
            self.seen[slot][..n].copy_from_slice(&data[..n]);
            self.seen_len[slot] = n as u8;
        }
        self.seen_count = self.seen_count.saturating_add(1);
    }

    /// Why the handshake ran out of time, said in terms of what actually arrived.
    /// "Nothing came back" and "something came back that I could not use" send a
    /// reader to completely different places, so they must not share a message.
    fn timed_out(&self) -> &'static str {
        let Some(first) = self.unrecognised().next() else {
            return "no answer to the connection request";
        };
        match first {
            [0, 2, ..] => {
                "no usable answer to the connection request: the server's 00 02 \
                 carried a key that is neither the client key echoed back (no \
                 encryption) nor the VIE server key derived from it"
            }
            [0, 1, ..] => {
                "no usable answer to the connection request: the server sent a \
                 connection request (00 01) of its own, not a response"
            }
            [0, 3, ..] => {
                "no usable answer to the connection request: the server sent \
                 reliable data (00 03) without answering it"
            }
            [0, 4, ..] => {
                "no usable answer to the connection request: the server sent an \
                 acknowledgement (00 04) without answering it"
            }
            [0, 5, ..] => {
                "no usable answer to the connection request: the server sent a \
                 sync request (00 05) without answering it"
            }
            [0, 6, ..] => {
                "no usable answer to the connection request: the server sent a \
                 sync response (00 06) without answering it"
            }
            [0, 7, ..] => {
                "no usable answer to the connection request: the server sent a \
                 malformed disconnect (00 07 with trailing bytes)"
            }
            [0, 8 | 9, ..] => {
                "no usable answer to the connection request: the server sent a \
                 chunk (00 08 / 00 09) without answering it"
            }
            [0, 0x0A, ..] => {
                "no usable answer to the connection request: the server sent a \
                 sized transfer (00 0A) without answering it"
            }
            [0, 0x0E, ..] => {
                "no usable answer to the connection request: the server sent a \
                 cluster (00 0E) without answering it"
            }
            [0, ..] => {
                "no usable answer to the connection request: the server sent a \
                 core (00) packet of a type this handshake does not know"
            }
            _ => {
                "no usable answer to the connection request: the server sent a \
                 game packet, not a core (00) connection response"
            }
        }
    }
}

impl Handshake for VieClientHandshake {
    fn on_datagram(&mut self, _now: u64, data: &[u8], _out: &mut Vec<Vec<u8>>) -> Step {
        match data {
            [0, 2, a, b, c, d, ..] => {
                let server_key = u32::from_le_bytes([*a, *b, *c, *d]);
                if server_key == self.key {
                    Step::Established(Box::new(NullCipher))
                } else if server_key == vie::server_key_for(self.key) {
                    Step::Established(vie_cipher(server_key))
                } else {
                    // An answer, just not one we can use: keep it for the
                    // failure message instead of waiting out the clock in
                    // silence.
                    self.remember(data);
                    Step::Pending
                }
            }
            [0, 7] => Step::Failed("server refused the connection"),
            _ => {
                self.remember(data);
                Step::Pending
            }
        }
    }

    fn poll(&mut self, now: u64, out: &mut Vec<Vec<u8>>) -> Step {
        let started = *self.started.get_or_insert(now);
        if now.saturating_sub(started) >= self.timeout_ms {
            return Step::Failed(self.timed_out());
        }
        if self
            .last_sent
            .is_none_or(|t| now.saturating_sub(t) >= Self::RESEND_MS)
        {
            out.push(self.request());
            self.last_sent = Some(now);
        }
        Step::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A handshake that hears nothing and one that hears the wrong thing must not
    /// give the same reason: the first sends a reader to the network, the second
    /// to the protocol. This is the bug this test exists for.
    #[test]
    fn silence_and_an_unusable_answer_read_differently() {
        let mut out = Vec::new();

        let mut quiet = VieClientHandshake::new(1).timeout(1000);
        assert!(matches!(quiet.poll(0, &mut out), Step::Pending));
        let Step::Failed(why) = quiet.poll(2000, &mut out) else {
            panic!("should have timed out");
        };
        assert_eq!(why, "no answer to the connection request");
        assert_eq!(quiet.unrecognised_count(), 0);
        assert_eq!(quiet.unrecognised().count(), 0);

        // The server answered every request -- with something unusable.
        let mut talked_to = VieClientHandshake::new(1).timeout(1000);
        assert!(matches!(talked_to.poll(0, &mut out), Step::Pending));
        for _ in 0..3 {
            assert!(matches!(
                talked_to.on_datagram(10, &[0, 5, 1, 2, 3, 4], &mut out),
                Step::Pending
            ));
        }
        let Step::Failed(why) = talked_to.poll(2000, &mut out) else {
            panic!("should have timed out");
        };
        assert!(
            why.contains("the server sent a sync request (00 05)"),
            "{why}"
        );
        assert!(!why.contains("no answer to"), "{why}");
        // Wrapped literals must not leave run-together or doubled spacing.
        assert!(!why.contains("  "), "{why}");
        // All three counted; the first two kept.
        assert_eq!(talked_to.unrecognised_count(), 3);
        let kept: Vec<&[u8]> = talked_to.unrecognised().collect();
        assert_eq!(kept, [&[0, 5, 1, 2, 3, 4][..], &[0, 5, 1, 2, 3, 4][..]]);
    }

    /// `00 02` with a key we can't place is an answer, not silence -- the case
    /// that is easiest to mistake for a dead server.
    #[test]
    fn a_connect_response_with_an_unknown_key_is_reported_as_an_answer() {
        let mut out = Vec::new();
        let mut c = VieClientHandshake::new(7).timeout(1000);
        assert!(matches!(c.poll(0, &mut out), Step::Pending));
        let mut reply = vec![0u8, 2];
        reply.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(matches!(c.on_datagram(10, &reply, &mut out), Step::Pending));
        let Step::Failed(why) = c.poll(2000, &mut out) else {
            panic!("should have timed out");
        };
        assert!(why.contains("00 02"), "{why}");
        assert!(!why.contains("  "), "{why}");
        assert_eq!(c.unrecognised_count(), 1);
        assert_eq!(c.unrecognised().next().unwrap(), &reply[..]);

        // A datagram that isn't a core packet at all is named as such.
        let mut c = VieClientHandshake::new(7).timeout(1000);
        assert!(matches!(c.poll(0, &mut out), Step::Pending));
        assert!(matches!(
            c.on_datagram(10, &[0x0B, 0x01], &mut out),
            Step::Pending
        ));
        let Step::Failed(why) = c.poll(2000, &mut out) else {
            panic!("should have timed out");
        };
        assert!(why.contains("game packet"), "{why}");
        assert!(!why.contains("  "), "{why}");

        // A usable answer still establishes, and is never "unrecognised".
        let mut c = VieClientHandshake::new(7);
        let key = match c.poll(0, &mut out) {
            Step::Pending => u32::from_le_bytes([out[0][2], out[0][3], out[0][4], out[0][5]]),
            _ => panic!("expected a request"),
        };
        let mut reply = vec![0u8, 2];
        reply.extend_from_slice(&vie::server_key_for(key).to_le_bytes());
        assert!(matches!(
            c.on_datagram(10, &reply, &mut out),
            Step::Established(_)
        ));
        assert_eq!(c.unrecognised_count(), 0);
    }

    #[test]
    fn vie_handshake_both_sides() {
        let mut client = VieClientHandshake::new(0x1234_5678);
        let mut out = Vec::new();
        assert!(matches!(client.poll(0, &mut out), Step::Pending));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 8);
        // No resend before the interval.
        client.poll(500, &mut out);
        assert_eq!(out.len(), 1);
        client.poll(1000, &mut out);
        assert_eq!(out.len(), 2);

        let mut replies = Vec::new();
        let Some(Accept::Established(mut server_cipher)) =
            VieAcceptor::default().accept(0, &out[0], &mut replies)
        else {
            panic!()
        };
        assert_eq!(replies[0].len(), 6);
        let Step::Established(mut client_cipher) = client.on_datagram(0, &replies[0], &mut out)
        else {
            panic!()
        };
        assert_eq!((client_cipher.name(), server_cipher.name()), ("vie", "vie"));
        let mut d = vec![0x06, 1, 2, 3, 4, 5, 6, 7];
        client_cipher.encrypt(&mut d);
        assert_ne!(d, [0x06, 1, 2, 3, 4, 5, 6, 7]);
        assert!(server_cipher.decrypt(&mut d));
        assert_eq!(d, [0x06, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn null_and_unencrypted() {
        let mut client = VieClientHandshake::unencrypted();
        let mut out = Vec::new();
        client.poll(0, &mut out);
        let mut replies = Vec::new();
        // VIE server with key 0 answers 0: no encryption.
        assert!(
            VieAcceptor::default()
                .accept(0, &out[0], &mut replies)
                .is_some()
        );
        assert!(
            matches!(client.on_datagram(0, &replies[0], &mut out), Step::Established(c) if c.name() == "none")
        );

        let mut c2 = VieClientHandshake::new(99);
        let mut o2 = Vec::new();
        c2.poll(0, &mut o2);
        let mut r2 = Vec::new();
        assert!(NullAcceptor.accept(0, &o2[0], &mut r2).is_some());
        assert!(
            matches!(c2.on_datagram(0, &r2[0], &mut o2), Step::Established(c) if c.name() == "none")
        );
    }

    #[test]
    fn refusal_and_timeout() {
        let mut c = VieClientHandshake::new(1).timeout(3000);
        let mut out = Vec::new();
        c.poll(0, &mut out);
        assert!(matches!(
            c.on_datagram(0, &[0, 7], &mut out),
            Step::Failed(_)
        ));
        assert!(matches!(c.poll(3000, &mut out), Step::Failed(_)));
        // Wrong key in 00 02 is ignored.
        let mut c = VieClientHandshake::new(1);
        assert!(matches!(
            c.on_datagram(0, &[0, 2, 9, 9, 9, 9], &mut out),
            Step::Pending
        ));
    }

    #[test]
    fn acceptors_filter() {
        let mut out = Vec::new();
        assert!(
            VieAcceptor::default()
                .accept(0, &[0, 1, 0, 0, 0, 0, 1], &mut out)
                .is_none()
        );
        assert!(
            VieAcceptor::default()
                .accept(0, &[0, 1, 0, 0, 0, 0, 2, 0], &mut out)
                .is_none()
        );
        let strict = VieAcceptor {
            accept_continuum: false,
        };
        assert!(
            strict
                .accept(0, &[0, 1, 0, 0, 0, 0x80, 0x11, 0], &mut out)
                .is_none()
        );
        assert!(out.is_empty());
    }
}
