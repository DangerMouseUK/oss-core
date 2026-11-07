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

/// Client-side VIE handshake: sends `00 01` (resending every
/// [`VieClientHandshake::RESEND_MS`]) until the server answers `00 02`.
#[derive(Debug, Clone)]
pub struct VieClientHandshake {
    key: u32,
    protocol: u16,
    started: Option<u64>,
    last_sent: Option<u64>,
    timeout_ms: u64,
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
                    Step::Pending
                }
            }
            [0, 7] => Step::Failed("server refused the connection"),
            _ => Step::Pending,
        }
    }

    fn poll(&mut self, now: u64, out: &mut Vec<Vec<u8>>) -> Step {
        let started = *self.started.get_or_insert(now);
        if now.saturating_sub(started) >= self.timeout_ms {
            return Step::Failed("no answer to connection request");
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
