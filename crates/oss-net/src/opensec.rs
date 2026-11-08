//! OpenSec: this project's transport encryption (specification in
//! `docs/protocol/opensec.md`, CC BY 4.0).
//!
//! * Handshake: X25519 ephemeral keys from both sides; if the server has a
//!   static key it is mixed in as well (the client may pin it), and the server
//!   proves it derived the session keys with an AEAD confirmation tag.
//! * Keys: HKDF-SHA256 over the shared secrets, bound to a hash of both hello
//!   packets; one ChaCha20-Poly1305 key per direction.
//! * Records: `0xF5`, a 32-bit counter, ciphertext, 16-byte tag (21 bytes of
//!   overhead), with a 64-packet replay window.
//!
//! The client hello is a 90-byte `00 01` packet, which servers that
//! only know SubSpace/Continuum ignore; clients can therefore try OpenSec first
//! and fall back to VIE ([`crate::cipher::Fallback`]).
//!
//! Randomness is supplied by the caller ([`Entropy`]); [`os_entropy`] uses the
//! operating system (feature `os-entropy`).

use std::sync::Arc;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
/// X25519 key types used by [`server_respond`] and [`client_finish`].
pub use x25519_dalek::{PublicKey, StaticSecret};

use crate::cipher::{Accept, Acceptor, Cipher, CipherKind, Handshake, Step};

/// Protocol identifier in hello packets.
pub const MAGIC: [u8; 4] = *b"OSEC";
/// Protocol version.
pub const VERSION: u8 = 1;
/// Capability: the server has a static key, sent in its hello and mixed into
/// the session keys.
pub const CAP_SERVER_AUTH: u16 = 0x0001;
/// Capability: the client has a long-term identity key, sent in its hello and
/// (when the server selects this) mixed into the session keys, so a client
/// that doesn't hold the private half can't complete the session.
pub const CAP_CLIENT_AUTH: u16 = 0x0002;
/// First byte of every encrypted datagram.
pub const RECORD_MARKER: u8 = 0xF5;
/// Bytes added to each datagram: marker, counter, tag.
pub const OVERHEAD: usize = 1 + 4 + 16;
/// Client hello length: 42 bytes of content padded with zeros to the length
/// of the largest server hello, so answering a (possibly spoofed) hello never
/// sends more bytes than it received.
pub const CLIENT_HELLO_LEN: usize = 90;
/// Server hello length without a static key.
pub const SERVER_HELLO_LEN: usize = 58;
/// Server hello length with a static key.
pub const SERVER_HELLO_AUTH_LEN: usize = 90;

const KDF_SALT: &[u8] = b"OpenSec v1 handshake";
const DIR_C2S: u32 = 1;
const DIR_S2C: u32 = 2;

/// A source of random bytes (must be cryptographically secure in production).
pub type Entropy = Arc<dyn Fn(&mut [u8]) + Send + Sync>;

/// Randomness from the operating system.
#[cfg(feature = "os-entropy")]
pub fn os_entropy() -> Entropy {
    Arc::new(|buf: &mut [u8]| {
        // Failure here means the OS has no entropy source; continuing would be
        // insecure.
        getrandom::fill(buf).expect("operating system entropy unavailable");
    })
}

/// A long-term X25519 key pair: a server's static key, or a client's identity
/// key ([`IdentityKey`]).
#[derive(Clone)]
pub struct ServerKey {
    secret: StaticSecret,
}

impl core::fmt::Debug for ServerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerKey")
            .field("public", &hex(&self.public()))
            .finish()
    }
}

impl ServerKey {
    /// A key from its 32 secret bytes (store these securely).
    pub fn from_secret(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    /// A new random key.
    pub fn generate(entropy: &Entropy) -> Self {
        let mut b = [0u8; 32];
        entropy(&mut b);
        Self::from_secret(b)
    }

    /// The secret bytes, for saving.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// The public key (the one clients pin, or a client's identity).
    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn nonce(dir: u32, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&dir.to_le_bytes());
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

/// The record AEAD (ChaCha20-Poly1305, RFC 8439). The default is RustCrypto's
/// pure-Rust implementation, which also builds for wasm. The `opensec-ring`
/// feature uses ring's assembly implementation instead: two to three times
/// faster per record (see `docs/performance.md`), but it compiles C and
/// assembly. Both compute the same function, which the published vectors check.
mod aead {
    /// A keyed AEAD.
    #[cfg(not(feature = "opensec-ring"))]
    pub(super) struct Key(chacha20poly1305::ChaCha20Poly1305);
    /// A keyed AEAD.
    #[cfg(feature = "opensec-ring")]
    pub(super) struct Key(ring::aead::LessSafeKey);

    #[cfg(not(feature = "opensec-ring"))]
    impl Key {
        pub(super) fn new(key: &[u8; 32]) -> Self {
            use chacha20poly1305::aead::KeyInit;
            Self(chacha20poly1305::ChaCha20Poly1305::new(key.into()))
        }

        /// Encrypts `buf` in place and returns the tag.
        pub(super) fn seal(&self, nonce: [u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
            use chacha20poly1305::aead::AeadInOut;
            self.0
                .encrypt_inout_detached(&nonce.into(), aad, buf.into())
                .expect("records are far below the AEAD length limit")
                .into()
        }

        /// Decrypts `buf` in place if `tag` authenticates it.
        pub(super) fn open(
            &self,
            nonce: [u8; 12],
            aad: &[u8],
            buf: &mut [u8],
            tag: &[u8; 16],
        ) -> bool {
            use chacha20poly1305::aead::AeadInOut;
            self.0
                .decrypt_inout_detached(&nonce.into(), aad, buf.into(), &(*tag).into())
                .is_ok()
        }
    }

    #[cfg(feature = "opensec-ring")]
    impl Key {
        pub(super) fn new(key: &[u8; 32]) -> Self {
            use ring::aead::{CHACHA20_POLY1305, LessSafeKey, UnboundKey};
            Self(LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, key).expect("32-byte key"),
            ))
        }

        /// Encrypts `buf` in place and returns the tag.
        pub(super) fn seal(&self, nonce: [u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
            use ring::aead::{Aad, Nonce};
            let tag = self
                .0
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(aad),
                    buf,
                )
                .expect("records are far below the AEAD length limit");
            tag.as_ref().try_into().expect("16-byte tag")
        }

        /// Decrypts `buf` in place if `tag` authenticates it.
        pub(super) fn open(
            &self,
            nonce: [u8; 12],
            aad: &[u8],
            buf: &mut [u8],
            tag: &[u8; 16],
        ) -> bool {
            use ring::aead::{Aad, Nonce, Tag};
            self.0
                .open_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(aad),
                    Tag::from(*tag),
                    buf,
                    0..,
                )
                .is_ok()
        }
    }
}

/// Session keys and transcript hash derived from a handshake.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Hash of the client hello and the server hello without its tag.
    pub transcript: [u8; 32],
    /// Client-to-server key.
    pub c2s: [u8; 32],
    /// Server-to-client key.
    pub s2c: [u8; 32],
    /// The client's identity key, when `CLIENT_AUTH` was selected. It is only
    /// *claimed* until a record from the client authenticates under these keys.
    pub client_identity: Option<[u8; 32]>,
}

/// A client's long-term identity key pair (the same type as a server's key).
/// Generate one per installation or account with [`ServerKey::generate`] and
/// keep it.
pub type IdentityKey = ServerKey;

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionKeys").finish_non_exhaustive()
    }
}

/// Derives the session keys. `extra` is `es_static || se`: each part present
/// only when its capability is selected.
fn derive(
    client_hello: &[u8],
    server_hello_body: &[u8],
    ee: &[u8; 32],
    extra: &[u8],
) -> SessionKeys {
    let mut h = Sha256::new();
    h.update(client_hello);
    h.update(server_hello_body);
    let transcript: [u8; 32] = h.finalize().into();
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(ee);
    ikm.extend_from_slice(extra);
    let mut okm = [0u8; 64];
    Hkdf::<Sha256>::new(Some(KDF_SALT), &ikm)
        .expand(&transcript, &mut okm)
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    let mut keys = SessionKeys {
        transcript,
        c2s: [0; 32],
        s2c: [0; 32],
        client_identity: None,
    };
    keys.c2s.copy_from_slice(&okm[..32]);
    keys.s2c.copy_from_slice(&okm[32..]);
    keys
}

fn confirm_tag(keys: &SessionKeys) -> [u8; 16] {
    aead::Key::new(&keys.s2c).seal(nonce(DIR_S2C, 0), &keys.transcript, &mut [])
}

/// Builds a client hello without an identity (`CAP_CLIENT_AUTH` is cleared).
pub fn client_hello(ephemeral_public: &[u8; 32], caps: u16) -> Vec<u8> {
    client_hello_with_identity(ephemeral_public, caps & !CAP_CLIENT_AUTH, None)
}

/// Builds a client hello. With `identity` (the public half of an
/// [`IdentityKey`]), it offers `CAP_CLIENT_AUTH` and carries the key at
/// offset 42, inside the padding, so the hello stays 90 bytes.
pub fn client_hello_with_identity(
    ephemeral_public: &[u8; 32],
    caps: u16,
    identity: Option<&[u8; 32]>,
) -> Vec<u8> {
    let caps = match identity {
        Some(_) => caps | CAP_CLIENT_AUTH,
        None => caps & !CAP_CLIENT_AUTH,
    };
    let mut v = Vec::with_capacity(CLIENT_HELLO_LEN);
    v.extend_from_slice(&[0, 1]);
    v.extend_from_slice(&MAGIC);
    v.push(VERSION);
    v.push(0);
    v.extend_from_slice(&caps.to_le_bytes());
    v.extend_from_slice(ephemeral_public);
    if let Some(id) = identity {
        v.extend_from_slice(id);
    }
    v.resize(CLIENT_HELLO_LEN, 0);
    v
}

/// Direction of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Client to server.
    ClientToServer,
    /// Server to client.
    ServerToClient,
}

impl Direction {
    fn nonce_dir(self) -> u32 {
        match self {
            Self::ClientToServer => DIR_C2S,
            Self::ServerToClient => DIR_S2C,
        }
    }
}

/// Seals one record with an explicit counter, outside any session: the wire
/// form `0xF5 | low 32 bits of counter | ciphertext | tag`. For tests and
/// interoperability checks; sessions use [`OpenSecCipher`].
pub fn seal_record(key: &[u8; 32], dir: Direction, counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(plaintext.len() + OVERHEAD);
    out.push(RECORD_MARKER);
    out.extend_from_slice(&(counter as u32).to_le_bytes());
    let header: [u8; 5] = out[..5].try_into().expect("5 bytes");
    let mut body = plaintext.to_vec();
    let tag = aead::Key::new(key).seal(nonce(dir.nonce_dir(), counter), &header, &mut body);
    out.extend_from_slice(&body);
    out.extend_from_slice(&tag);
    out
}

/// Opens one record sealed with `counter`; `None` if it is malformed, carries a
/// different counter, or fails authentication. The counterpart of
/// [`seal_record`].
pub fn open_record(
    key: &[u8; 32],
    dir: Direction,
    counter: u64,
    datagram: &[u8],
) -> Option<Vec<u8>> {
    if datagram.len() < OVERHEAD
        || datagram[0] != RECORD_MARKER
        || datagram[1..5] != (counter as u32).to_le_bytes()
    {
        return None;
    }
    let tag_at = datagram.len() - 16;
    let tag: [u8; 16] = datagram[tag_at..].try_into().ok()?;
    let mut body = datagram[5..tag_at].to_vec();
    aead::Key::new(key)
        .open(
            nonce(dir.nonce_dir(), counter),
            &datagram[..5],
            &mut body,
            &tag,
        )
        .then_some(body)
}

/// Whether `data` is an OpenSec client hello (any version).
pub fn is_client_hello(data: &[u8]) -> bool {
    data.len() >= 8 && data[..2] == [0, 1] && data[2..6] == MAGIC
}

/// The record cipher for an established OpenSec session.
pub struct OpenSecCipher {
    send: aead::Key,
    recv: aead::Key,
    send_dir: u32,
    recv_dir: u32,
    send_counter: u64,
    recv_highest: u64,
    recv_window: u64,
    peer_key: Option<[u8; 32]>,
    /// Whether `peer_key` is proven: at once on the client (the confirmation
    /// tag proves the server's key), after the first authenticated record on
    /// the server (only then is the client's identity more than a claim).
    peer_proven: bool,
}

impl core::fmt::Debug for OpenSecCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenSecCipher")
            .field("sent", &self.send_counter)
            .finish_non_exhaustive()
    }
}

impl OpenSecCipher {
    /// The cipher for one side of a session. On the server, `peer_key` is the
    /// client's identity ([`SessionKeys::client_identity`]); [`Cipher::peer_key`]
    /// reports it only once a record from the client has authenticated.
    pub fn new(keys: &SessionKeys, is_server: bool, peer_key: Option<[u8; 32]>) -> Self {
        let c2s = aead::Key::new(&keys.c2s);
        let s2c = aead::Key::new(&keys.s2c);
        let (send, recv, send_dir, recv_dir) = if is_server {
            (s2c, c2s, DIR_S2C, DIR_C2S)
        } else {
            (c2s, s2c, DIR_C2S, DIR_S2C)
        };
        Self {
            send,
            recv,
            send_dir,
            recv_dir,
            send_counter: 0,
            recv_highest: 0,
            recv_window: 0,
            peer_key,
            peer_proven: !is_server,
        }
    }

    /// Full counter from its low 32 bits, closest to the highest seen so far.
    fn expand_counter(&self, low: u32) -> u64 {
        let base = self.recv_highest & !0xFFFF_FFFF;
        let mut c = base | u64::from(low);
        if c + (1 << 31) < self.recv_highest {
            c += 1 << 32;
        } else if c > self.recv_highest + (1 << 31) && c >= 1 << 32 {
            c -= 1 << 32;
        }
        c
    }

    /// Whether `c` is new; does not record it.
    fn fresh(&self, c: u64) -> bool {
        if c == 0 {
            return false;
        }
        if c > self.recv_highest {
            return true;
        }
        let age = self.recv_highest - c;
        age < 64 && self.recv_window & (1 << age) == 0
    }

    fn record(&mut self, c: u64) {
        if c > self.recv_highest {
            let shift = c - self.recv_highest;
            self.recv_window = if shift >= 64 {
                0
            } else {
                self.recv_window << shift
            };
            self.recv_window |= 1;
            self.recv_highest = c;
        } else {
            self.recv_window |= 1 << (self.recv_highest - c);
        }
    }
}

impl Cipher for OpenSecCipher {
    fn encrypt(&mut self, datagram: &mut Vec<u8>) {
        self.send_counter += 1;
        let low = self.send_counter as u32;
        let mut header = [0u8; 5];
        header[0] = RECORD_MARKER;
        header[1..].copy_from_slice(&low.to_le_bytes());
        let tag = self
            .send
            .seal(nonce(self.send_dir, self.send_counter), &header, datagram);
        datagram.splice(0..0, header);
        datagram.extend_from_slice(&tag);
    }

    fn decrypt(&mut self, datagram: &mut Vec<u8>) -> bool {
        if datagram.len() < OVERHEAD || datagram[0] != RECORD_MARKER {
            return false;
        }
        let low = u32::from_le_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]);
        let counter = self.expand_counter(low);
        if !self.fresh(counter) {
            return false;
        }
        let mut header = [0u8; 5];
        header.copy_from_slice(&datagram[..5]);
        let tag_at = datagram.len() - 16;
        let tag: [u8; 16] = datagram[tag_at..].try_into().expect("16 bytes");
        let ok = self.recv.open(
            nonce(self.recv_dir, counter),
            &header,
            &mut datagram[5..tag_at],
            &tag,
        );
        if !ok {
            return false;
        }
        self.record(counter);
        self.peer_proven = true;
        datagram.truncate(tag_at);
        datagram.drain(..5);
        true
    }

    fn name(&self) -> &'static str {
        "opensec"
    }

    fn kind(&self) -> CipherKind {
        CipherKind::OpenSec
    }

    fn overhead(&self) -> usize {
        OVERHEAD
    }

    fn peer_key(&self) -> Option<[u8; 32]> {
        self.peer_key.filter(|_| self.peer_proven)
    }
}

fn random_secret(entropy: &Entropy) -> StaticSecret {
    let mut b = [0u8; 32];
    entropy(&mut b);
    StaticSecret::from(b)
}

/// The server side of the handshake, as a pure function: given the client
/// hello and the server's ephemeral (and optional static) secret, returns the
/// server hello and the session keys. `None` if the hello is invalid.
///
/// Put `CAP_CLIENT_AUTH` in `server_caps` to accept client identities: when the
/// client offers one, it is mixed into the keys and returned in
/// [`SessionKeys::client_identity`].
pub fn server_respond(
    client_hello: &[u8],
    ephemeral: &StaticSecret,
    static_key: Option<&ServerKey>,
    server_caps: u16,
) -> Option<(Vec<u8>, SessionKeys)> {
    if client_hello.len() != CLIENT_HELLO_LEN || !is_client_hello(client_hello) {
        return None;
    }
    if client_hello[6] != VERSION {
        return None;
    }
    let client_caps = u16::from_le_bytes([client_hello[8], client_hello[9]]);
    let mut e_c = [0u8; 32];
    e_c.copy_from_slice(&client_hello[10..42]);
    let e_c = PublicKey::from(e_c);
    // A v1 server knows only these two capabilities.
    let mut caps = client_caps & server_caps & (CAP_SERVER_AUTH | CAP_CLIENT_AUTH);
    if static_key.is_some() {
        caps |= CAP_SERVER_AUTH;
    } else {
        caps &= !CAP_SERVER_AUTH;
    }
    let ee = ephemeral.diffie_hellman(&e_c);
    if !ee.was_contributory() {
        return None;
    }
    let mut identity = None;
    let mut se = None;
    if caps & CAP_CLIENT_AUTH != 0 {
        let mut i_c = [0u8; 32];
        i_c.copy_from_slice(&client_hello[42..74]);
        let shared = ephemeral.diffie_hellman(&PublicKey::from(i_c));
        if !shared.was_contributory() {
            return None;
        }
        identity = Some(i_c);
        se = Some(shared);
    }
    let mut hello = Vec::with_capacity(SERVER_HELLO_AUTH_LEN);
    hello.extend_from_slice(&[0, 2]);
    hello.extend_from_slice(&MAGIC);
    hello.push(VERSION);
    hello.push(0);
    hello.extend_from_slice(&caps.to_le_bytes());
    hello.extend_from_slice(PublicKey::from(ephemeral).as_bytes());
    let mut extra = Vec::new();
    if let Some(k) = static_key {
        hello.extend_from_slice(&k.public());
        extra.extend_from_slice(k.secret.diffie_hellman(&e_c).as_bytes());
    }
    if let Some(se) = &se {
        extra.extend_from_slice(se.as_bytes());
    }
    let mut keys = derive(client_hello, &hello, ee.as_bytes(), &extra);
    keys.client_identity = identity;
    hello.extend_from_slice(&confirm_tag(&keys));
    Some((hello, keys))
}

/// Server-side acceptor for OpenSec client hellos.
pub struct OpenSecAcceptor {
    key: Option<ServerKey>,
    caps: u16,
    entropy: Entropy,
}

impl core::fmt::Debug for OpenSecAcceptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenSecAcceptor")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl OpenSecAcceptor {
    /// An acceptor; with `key`, clients can authenticate (and pin) the server.
    pub fn new(key: Option<ServerKey>, entropy: Entropy) -> Self {
        Self {
            key,
            caps: CAP_SERVER_AUTH,
            entropy,
        }
    }

    /// Also accepts client identity keys (`CAP_CLIENT_AUTH`). A connection's
    /// [`Connection::peer_key`](crate::Connection::peer_key) then returns the
    /// client's key, but only after a record from the client has authenticated,
    /// so read it when handling the login, not at the `Connected` event.
    pub fn with_client_identities(mut self) -> Self {
        self.caps |= CAP_CLIENT_AUTH;
        self
    }
}

impl Acceptor for OpenSecAcceptor {
    fn accept(&self, _now: u64, first: &[u8], out: &mut Vec<Vec<u8>>) -> Option<Accept> {
        if !is_client_hello(first) {
            return None;
        }
        let e = random_secret(&self.entropy);
        let (hello, keys) = server_respond(first, &e, self.key.as_ref(), self.caps)?;
        out.push(hello);
        let identity = keys.client_identity;
        Some(Accept::Established(Box::new(OpenSecCipher::new(
            &keys, true, identity,
        ))))
    }
}

/// The client side of the handshake, as a pure function: verifies the server
/// hello and returns the session keys and the server's static key (if any).
/// For a client without an identity key; see [`client_finish_with_identity`].
pub fn client_finish(
    client_hello: &[u8],
    ephemeral: &StaticSecret,
    server_hello: &[u8],
    pinned: Option<&[u8; 32]>,
) -> Result<(SessionKeys, Option<[u8; 32]>), &'static str> {
    client_finish_with_identity(client_hello, ephemeral, server_hello, pinned, None)
}

/// [`client_finish`] for a client that offered an identity key in its hello
/// ([`client_hello_with_identity`]).
pub fn client_finish_with_identity(
    client_hello: &[u8],
    ephemeral: &StaticSecret,
    server_hello: &[u8],
    pinned: Option<&[u8; 32]>,
    identity: Option<&IdentityKey>,
) -> Result<(SessionKeys, Option<[u8; 32]>), &'static str> {
    if server_hello.len() < SERVER_HELLO_LEN
        || server_hello[..2] != [0, 2]
        || server_hello[2..6] != MAGIC
    {
        return Err("not an OpenSec server hello");
    }
    if server_hello[6] != VERSION {
        return Err("unsupported OpenSec version");
    }
    let caps = u16::from_le_bytes([server_hello[8], server_hello[9]]);
    let offered = client_hello
        .get(8..10)
        .map_or(0, |c| u16::from_le_bytes([c[0], c[1]]));
    if caps & !offered != 0 {
        return Err("server selected a capability the client did not offer");
    }
    let auth = caps & CAP_SERVER_AUTH != 0;
    let want = if auth {
        SERVER_HELLO_AUTH_LEN
    } else {
        SERVER_HELLO_LEN
    };
    if server_hello.len() != want {
        return Err("bad OpenSec server hello length");
    }
    let mut e_s = [0u8; 32];
    e_s.copy_from_slice(&server_hello[10..42]);
    let ee = ephemeral.diffie_hellman(&PublicKey::from(e_s));
    if !ee.was_contributory() {
        return Err("invalid server key share");
    }
    let mut extra = Vec::new();
    let mut server_key = None;
    if auth {
        let mut s = [0u8; 32];
        s.copy_from_slice(&server_hello[42..74]);
        if pinned.is_some_and(|p| *p != s) {
            return Err("server key does not match the pinned key");
        }
        let shared = ephemeral.diffie_hellman(&PublicKey::from(s));
        if !shared.was_contributory() {
            return Err("invalid server static key");
        }
        extra.extend_from_slice(shared.as_bytes());
        server_key = Some(s);
    } else if pinned.is_some() {
        return Err("server did not authenticate but a key is pinned");
    }
    let mut client_identity = None;
    if caps & CAP_CLIENT_AUTH != 0 {
        // Offered (checked above), so the hello carries our key.
        let Some(id) = identity.filter(|id| client_hello.get(42..74) == Some(&id.public()[..]))
        else {
            return Err("server selected client identity but the identity key is missing");
        };
        let shared = id.secret.diffie_hellman(&PublicKey::from(e_s));
        if !shared.was_contributory() {
            return Err("invalid server key share");
        }
        extra.extend_from_slice(shared.as_bytes());
        client_identity = Some(id.public());
    }
    let body = &server_hello[..want - 16];
    let mut keys = derive(client_hello, body, ee.as_bytes(), &extra);
    keys.client_identity = client_identity;
    // Constant-time comparison: every byte is examined whatever the result.
    let diff = confirm_tag(&keys)
        .iter()
        .zip(&server_hello[want - 16..])
        .fold(0u8, |d, (a, b)| core::hint::black_box(d | (a ^ b)));
    if diff != 0 {
        return Err("server key confirmation failed");
    }
    Ok((keys, server_key))
}

/// Client-side OpenSec handshake. Resends its hello every
/// [`OpenSecClientHandshake::RESEND_MS`] until answered or timed out.
pub struct OpenSecClientHandshake {
    ephemeral: StaticSecret,
    identity: Option<IdentityKey>,
    hello: Vec<u8>,
    pinned: Option<[u8; 32]>,
    started: Option<u64>,
    last_sent: Option<u64>,
    timeout_ms: u64,
}

impl core::fmt::Debug for OpenSecClientHandshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenSecClientHandshake")
            .finish_non_exhaustive()
    }
}

impl OpenSecClientHandshake {
    /// Resend interval for the hello.
    pub const RESEND_MS: u64 = 250;

    /// A handshake; with `pinned`, only a server holding that static key is
    /// accepted.
    pub fn new(entropy: &Entropy, pinned: Option<[u8; 32]>) -> Self {
        let ephemeral = random_secret(entropy);
        let hello = client_hello(PublicKey::from(&ephemeral).as_bytes(), CAP_SERVER_AUTH);
        Self {
            ephemeral,
            identity: None,
            hello,
            pinned,
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

    /// Offers `identity` to the server (`CAP_CLIENT_AUTH`), for servers that
    /// tie bans or accounts to a key. The public key travels in the clear.
    pub fn with_identity(mut self, identity: IdentityKey) -> Self {
        self.hello = client_hello_with_identity(
            PublicKey::from(&self.ephemeral).as_bytes(),
            CAP_SERVER_AUTH,
            Some(&identity.public()),
        );
        self.identity = Some(identity);
        self
    }
}

impl Handshake for OpenSecClientHandshake {
    fn on_datagram(&mut self, _now: u64, data: &[u8], _out: &mut Vec<Vec<u8>>) -> Step {
        if data.len() < 6 || data[..2] != [0, 2] || data[2..6] != MAGIC {
            if data == [0, 7] {
                return Step::Failed("server refused the connection");
            }
            return Step::Pending;
        }
        match client_finish_with_identity(
            &self.hello,
            &self.ephemeral,
            data,
            self.pinned.as_ref(),
            self.identity.as_ref(),
        ) {
            Ok((keys, server_key)) => {
                Step::Established(Box::new(OpenSecCipher::new(&keys, false, server_key)))
            }
            Err(e) => Step::Failed(e),
        }
    }

    fn poll(&mut self, now: u64, out: &mut Vec<Vec<u8>>) -> Step {
        let started = *self.started.get_or_insert(now);
        if now.saturating_sub(started) >= self.timeout_ms {
            return Step::Failed("no answer to OpenSec hello");
        }
        if self
            .last_sent
            .is_none_or(|t| now.saturating_sub(t) >= Self::RESEND_MS)
        {
            out.push(self.hello.clone());
            self.last_sent = Some(now);
        }
        Step::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(seed: u8) -> Entropy {
        let state = std::sync::Mutex::new(seed);
        Arc::new(move |b: &mut [u8]| {
            let mut s = state.lock().unwrap();
            for x in b.iter_mut() {
                *s = s.wrapping_mul(31).wrapping_add(7);
                *x = *s;
            }
        })
    }

    fn session(auth: bool) -> (OpenSecCipher, OpenSecCipher) {
        let key = auth.then(|| ServerKey::generate(&fixed(1)));
        let acc = OpenSecAcceptor::new(key, fixed(2));
        let mut hs = OpenSecClientHandshake::new(&fixed(3), None);
        let mut out = Vec::new();
        hs.poll(0, &mut out);
        let mut replies = Vec::new();
        let Some(Accept::Established(_server)) = acc.accept(0, &out[0], &mut replies) else {
            panic!()
        };
        assert_eq!(
            replies[0].len(),
            if auth {
                SERVER_HELLO_AUTH_LEN
            } else {
                SERVER_HELLO_LEN
            }
        );
        let Step::Established(_client) = hs.on_datagram(0, &replies[0], &mut out) else {
            panic!()
        };
        // Rebuild concrete ciphers for direct testing.
        let e_c = random_secret(&fixed(3));
        let hello = client_hello(PublicKey::from(&e_c).as_bytes(), CAP_SERVER_AUTH);
        let e_s = random_secret(&fixed(2));
        let k = auth.then(|| ServerKey::generate(&fixed(1)));
        let (sh, keys) = server_respond(&hello, &e_s, k.as_ref(), CAP_SERVER_AUTH).unwrap();
        let (ck, sk) = client_finish(&hello, &e_c, &sh, None).unwrap();
        assert_eq!(ck, keys);
        assert_eq!(sk, k.map(|k| k.public()));
        (
            OpenSecCipher::new(&keys, false, sk),
            OpenSecCipher::new(&keys, true, None),
        )
    }

    #[test]
    fn round_trip_both_directions() {
        for auth in [false, true] {
            let (mut c, mut s) = session(auth);
            for i in 0..100u8 {
                let plain = vec![0x06, i, 1, 2, 3];
                let mut d = plain.clone();
                c.encrypt(&mut d);
                assert_eq!(d.len(), plain.len() + OVERHEAD);
                assert_eq!(d[0], RECORD_MARKER);
                assert!(s.decrypt(&mut d));
                assert_eq!(d, plain);
                let mut back = plain.clone();
                s.encrypt(&mut back);
                assert!(c.decrypt(&mut back));
                assert_eq!(back, plain);
            }
        }
    }

    #[test]
    fn rejects_tampering_and_replays() {
        let (mut c, mut s) = session(true);
        let mut d = vec![0x00, 0x03, 1, 2, 3, 4, 5];
        c.encrypt(&mut d);
        let copy = d.clone();
        let mut bad = d.clone();
        bad[7] ^= 1;
        assert!(!s.decrypt(&mut bad));
        assert!(s.decrypt(&mut d));
        let mut replay = copy.clone();
        assert!(!s.decrypt(&mut replay), "replayed datagram");
        // Reordered datagrams within the window are accepted once.
        let mut later: Vec<Vec<u8>> = (0..10)
            .map(|i| {
                let mut x = vec![0x10, i];
                c.encrypt(&mut x);
                x
            })
            .collect();
        later.reverse();
        for x in &mut later {
            assert!(s.decrypt(x));
        }
        // Wrong direction: a client datagram fed back to the client fails.
        let mut x = vec![1, 2, 3];
        c.encrypt(&mut x);
        assert!(!c.decrypt(&mut x));
        assert!(!s.decrypt(&mut vec![RECORD_MARKER; 5]));
    }

    #[test]
    fn counter_expansion_and_window() {
        let (mut c, mut s) = session(false);
        c.send_counter = 0xFFFF_FFF0;
        s.recv_highest = 0xFFFF_FFF0;
        for _ in 0..40 {
            let mut d = vec![7u8; 3];
            c.encrypt(&mut d);
            assert!(s.decrypt(&mut d), "across the 32-bit boundary");
        }
        assert!(s.recv_highest > 0xFFFF_FFFF);
    }

    #[test]
    fn pinning() {
        let key = ServerKey::generate(&fixed(9));
        let acc = OpenSecAcceptor::new(Some(key.clone()), fixed(2));
        let run = |pin: Option<[u8; 32]>| {
            let mut hs = OpenSecClientHandshake::new(&fixed(3), pin);
            let mut out = Vec::new();
            hs.poll(0, &mut out);
            let mut replies = Vec::new();
            acc.accept(0, &out[0], &mut replies).unwrap();
            hs.on_datagram(0, &replies[0], &mut out)
        };
        assert!(matches!(run(Some(key.public())), Step::Established(_)));
        assert!(matches!(run(Some([1; 32])), Step::Failed(_)));
        assert!(matches!(run(None), Step::Established(c) if c.peer_key() == Some(key.public())));
        // A pinned key against an unauthenticated server fails.
        let anon = OpenSecAcceptor::new(None, fixed(2));
        let mut hs = OpenSecClientHandshake::new(&fixed(3), Some(key.public()));
        let mut out = Vec::new();
        hs.poll(0, &mut out);
        let mut replies = Vec::new();
        anon.accept(0, &out[0], &mut replies).unwrap();
        assert!(matches!(
            hs.on_datagram(0, &replies[0], &mut out),
            Step::Failed(_)
        ));
    }

    #[test]
    fn client_identity_is_reported_only_after_a_record_proves_it() {
        let server_key = ServerKey::generate(&fixed(1));
        let identity = IdentityKey::generate(&fixed(5));
        let acc = OpenSecAcceptor::new(Some(server_key.clone()), fixed(2)).with_client_identities();
        let mut hs = OpenSecClientHandshake::new(&fixed(3), None).with_identity(identity.clone());
        let mut out = Vec::new();
        hs.poll(0, &mut out);
        let mut replies = Vec::new();
        let Some(Accept::Established(mut server)) = acc.accept(0, &out[0], &mut replies) else {
            panic!("server should accept");
        };
        let Step::Established(mut client) = hs.on_datagram(0, &replies[0], &mut out) else {
            panic!("client should finish");
        };
        assert_eq!(client.peer_key(), Some(server_key.public()));
        // The hello only claims the key.
        assert_eq!(server.peer_key(), None);
        let mut login = vec![0x09, 1, 2, 3];
        client.encrypt(&mut login);
        assert!(server.decrypt(&mut login));
        assert_eq!(server.peer_key(), Some(identity.public()));
    }

    #[test]
    fn a_copied_identity_never_proves_itself() {
        let victim = IdentityKey::generate(&fixed(5));
        let thief = IdentityKey::generate(&fixed(6));
        let ce = random_secret(&fixed(3));
        let se = random_secret(&fixed(2));
        // The thief sends the victim's public key...
        let hello = client_hello_with_identity(
            PublicKey::from(&ce).as_bytes(),
            CAP_SERVER_AUTH,
            Some(&victim.public()),
        );
        let (sh, keys) =
            server_respond(&hello, &se, None, CAP_SERVER_AUTH | CAP_CLIENT_AUTH).unwrap();
        assert_eq!(keys.client_identity, Some(victim.public()));
        // ... but can't compute X25519(victim, Es): its own key, or none, gives
        // different keys, and the client side refuses to pretend.
        assert!(client_finish_with_identity(&hello, &ce, &sh, None, Some(&thief)).is_err());
        let ee = ce.diffie_hellman(&PublicKey::from(&se));
        let wrong = thief.secret.diffie_hellman(&PublicKey::from(&se));
        let mut guessed = derive(
            &hello,
            &sh[..sh.len() - 16],
            ee.as_bytes(),
            wrong.as_bytes(),
        );
        guessed.client_identity = None;
        let mut thief_side = OpenSecCipher::new(&guessed, false, None);
        let mut server = OpenSecCipher::new(&keys, true, keys.client_identity);
        for _ in 0..5 {
            let mut d = vec![0x09, 0, 0];
            thief_side.encrypt(&mut d);
            assert!(!server.decrypt(&mut d));
        }
        assert_eq!(server.peer_key(), None);
    }

    #[test]
    fn identities_are_ignored_by_servers_that_dont_want_them() {
        let identity = IdentityKey::generate(&fixed(5));
        let acc = OpenSecAcceptor::new(None, fixed(2));
        let mut hs = OpenSecClientHandshake::new(&fixed(3), None).with_identity(identity);
        let mut out = Vec::new();
        hs.poll(0, &mut out);
        let mut replies = Vec::new();
        let Some(Accept::Established(mut server)) = acc.accept(0, &out[0], &mut replies) else {
            panic!("server should accept");
        };
        let Step::Established(mut client) = hs.on_datagram(0, &replies[0], &mut out) else {
            panic!("client should finish");
        };
        let mut d = vec![0x09, 1];
        client.encrypt(&mut d);
        assert!(server.decrypt(&mut d));
        assert_eq!(server.peer_key(), None);
    }

    #[test]
    fn tampered_server_hello_fails() {
        let acc = OpenSecAcceptor::new(Some(ServerKey::generate(&fixed(4))), fixed(2));
        let mut hs = OpenSecClientHandshake::new(&fixed(3), None);
        let mut out = Vec::new();
        hs.poll(0, &mut out);
        let mut replies = Vec::new();
        acc.accept(0, &out[0], &mut replies).unwrap();
        for i in [9, 20, 50, 80] {
            let mut h = replies[0].clone();
            h[i] ^= 0x40;
            let mut hs2 = OpenSecClientHandshake::new(&fixed(3), None);
            hs2.poll(0, &mut Vec::new());
            assert!(
                matches!(hs2.on_datagram(0, &h, &mut out), Step::Failed(_)),
                "byte {i}"
            );
        }
    }

    #[test]
    fn legacy_and_invalid_hellos_ignored() {
        let acc = OpenSecAcceptor::new(None, fixed(2));
        let mut out = Vec::new();
        assert!(acc.accept(0, &[0, 1, 1, 2, 3, 4, 1, 0], &mut out).is_none());
        let mut h = client_hello(&[9; 32], 0);
        h[6] = 2; // unknown version
        assert!(acc.accept(0, &h, &mut out).is_none());
        // An all-zero (low-order) key share is rejected.
        let h = client_hello(&[0; 32], 0);
        assert!(acc.accept(0, &h, &mut out).is_none());
        assert!(out.is_empty());
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn primitives_match_rfc_vectors() {
        // RFC 7748, section 6.1.
        let a: [u8; 32] = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .try_into()
            .unwrap();
        let b: [u8; 32] = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            .try_into()
            .unwrap();
        let (a, b) = (StaticSecret::from(a), StaticSecret::from(b));
        assert_eq!(
            PublicKey::from(&a).as_bytes()[..],
            unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            a.diffie_hellman(&PublicKey::from(&b)).as_bytes()[..],
            unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
        // RFC 8439, section 2.8.2.
        let key: Vec<u8> = (0x80..=0x9f).collect();
        let key: [u8; 32] = key.try_into().unwrap();
        let n: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
        let mut msg = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        // Through whichever backend this build uses.
        let tag = aead::Key::new(&key).seal(n, &unhex("50515253c0c1c2c3c4c5c6c7"), &mut msg);
        assert_eq!(msg[..16], unhex("d31a8d34648e60db7b86afbc53ef7ec2"));
        assert_eq!(tag[..], unhex("1ae10b594f09e26a7e902ecbd0600691"));
        // RFC 5869, test case 1.
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::new(Some(&unhex("000102030405060708090a0b0c")), &[0x0b; 22])
            .expand(&unhex("f0f1f2f3f4f5f6f7f8f9"), &mut okm)
            .unwrap();
        assert_eq!(
            okm[..],
            unhex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    /// Builds the published vectors from fixed inputs.
    fn vector_text() -> String {
        let secret =
            |start: u8| -> [u8; 32] { core::array::from_fn(|i| start.wrapping_add(i as u8 * 3)) };
        let mut t = String::new();
        t.push_str(
            "# OpenSec v1 test vectors (docs/protocol/opensec.md). Hex unless noted; datagrams as sent on the wire.\n\
             #\n\
             # case <name> starts a handshake; the lines after it are its inputs, packets and derived values:\n\
             #   *_secret: X25519 private keys as 32 raw bytes (the X25519 function clamps them)\n\
             #   ee, es: the X25519 outputs (es only with SERVER_AUTH); okm: the 64 HKDF output bytes\n\
             #   confirm_tag: the last 16 bytes of the server hello\n\
             # nonce <c2s|s2c> <counter, decimal> <12-byte AEAD nonce>\n\
             # record <c2s|s2c> <counter, decimal> <plaintext> <encrypted datagram>\n\
             #\n\
             # server_caps: the capabilities the server is configured with (u16, written most significant byte first)\n\
             # client_identity_*: the client's long-term identity key (CLIENT_AUTH); se: X25519(client identity, Es)\n\
             # reject-client-hello <name> <server caps> <client hello>: a server with those capabilities must not answer it\n\
             # reject-server-hello <name> <client ephemeral secret> <client hello> <pinned key or -> <server hello>:\n\
             #   a client must fail the handshake\n\
             # window <name> <step>...: one receiver from a fresh session, fed records in order. Each step is\n\
             #   <low 32 bits on the wire, decimal>[!]=<full counter the receiver must accept, decimal, or x to drop>;\n\
             #   ! marks a record whose tag fails, which must change nothing.\n",
        );
        let pubkey = |s: &StaticSecret| PublicKey::from(s).to_bytes();
        // (name, server has a static key, client has an identity, server
        // accepts identities)
        for (name, auth, has_id, wants_id) in [
            ("anonymous", false, false, false),
            ("server-auth", true, false, false),
            ("client-auth", true, true, true),
            ("client-auth-anonymous-server", false, true, true),
            ("identity-not-wanted", true, true, false),
        ] {
            let ce = StaticSecret::from(secret(0x10));
            let se = StaticSecret::from(secret(0x40));
            let ss = auth.then(|| ServerKey::from_secret(secret(0x70)));
            let ci = has_id.then(|| IdentityKey::from_secret(secret(0xD0)));
            let server_caps = CAP_SERVER_AUTH | if wants_id { CAP_CLIENT_AUTH } else { 0 };
            let hello = client_hello_with_identity(
                &pubkey(&ce),
                CAP_SERVER_AUTH,
                ci.as_ref().map(|k| k.public()).as_ref(),
            );
            let (sh, keys) = server_respond(&hello, &se, ss.as_ref(), server_caps).unwrap();
            let (ck, _) = client_finish_with_identity(
                &hello,
                &ce,
                &sh,
                ss.as_ref().map(|k| k.public()).as_ref(),
                ci.as_ref(),
            )
            .unwrap();
            assert_eq!(ck, keys);
            assert_eq!(
                keys.client_identity,
                ci.as_ref().filter(|_| wants_id).map(|k| k.public())
            );
            // Intermediate values, recomputed here from the primitives.
            let ee = ce.diffie_hellman(&PublicKey::from(pubkey(&se)));
            let es = ss
                .as_ref()
                .map(|k| ce.diffie_hellman(&PublicKey::from(k.public())).to_bytes());
            let se_shared = ci.as_ref().filter(|_| wants_id).map(|k| {
                k.secret
                    .diffie_hellman(&PublicKey::from(pubkey(&se)))
                    .to_bytes()
            });
            let mut ikm = ee.to_bytes().to_vec();
            ikm.extend_from_slice(es.as_ref().map_or(&[][..], |e| &e[..]));
            ikm.extend_from_slice(se_shared.as_ref().map_or(&[][..], |e| &e[..]));
            let mut okm = [0u8; 64];
            Hkdf::<Sha256>::new(Some(KDF_SALT), &ikm)
                .expand(&keys.transcript, &mut okm)
                .unwrap();
            assert_eq!((&okm[..32], &okm[32..]), (&keys.c2s[..], &keys.s2c[..]));

            t.push_str(&format!("case {name}\n"));
            let mut line = |k: &str, v: &[u8]| t.push_str(&format!("{k} {}\n", hex(v)));
            line("server_caps", &server_caps.to_be_bytes());
            line("client_ephemeral_secret", &ce.to_bytes());
            line("client_ephemeral_public", &pubkey(&ce));
            if let Some(k) = &ci {
                line("client_identity_secret", &k.secret_bytes());
                line("client_identity_public", &k.public());
            }
            line("server_ephemeral_secret", &se.to_bytes());
            line("server_ephemeral_public", &pubkey(&se));
            if let Some(k) = &ss {
                line("server_static_secret", &k.secret_bytes());
                line("server_static_public", &k.public());
            }
            line("client_hello", &hello);
            line("server_hello", &sh);
            line("ee", ee.as_bytes());
            if let Some(es) = &es {
                line("es", es);
            }
            if let Some(x) = &se_shared {
                line("se", x);
            }
            line("transcript", &keys.transcript);
            line("okm", &okm);
            line("key_c2s", &keys.c2s);
            line("key_s2c", &keys.s2c);
            line("confirm_tag", &sh[sh.len() - 16..]);
            let mut c = OpenSecCipher::new(&keys, false, None);
            let mut s = OpenSecCipher::new(&keys, true, keys.client_identity);
            for (dir, counter, plain) in [
                ("c2s", 1u64, vec![0x00, 0x03, 0, 0, 0, 0, 0x09, 0x00]),
                ("c2s", 2, vec![0x06, 0x02, 0x00, 0xFF, 0xFF, b'h', b'i', 0]),
                ("s2c", 1, vec![0x00, 0x04, 0, 0, 0, 0]),
                ("s2c", 0x1_0000_0005, vec![0x27]),
            ] {
                let (cipher, d) = if dir == "c2s" {
                    (&mut c, DIR_C2S)
                } else {
                    (&mut s, DIR_S2C)
                };
                cipher.send_counter = counter - 1;
                let mut wire = plain.clone();
                cipher.encrypt(&mut wire);
                t.push_str(&format!(
                    "nonce {dir} {counter} {}\n",
                    hex(&nonce(d, counter))
                ));
                t.push_str(&format!(
                    "record {dir} {counter} {} {}\n",
                    hex(&plain),
                    hex(&wire)
                ));
            }
        }

        // Client hellos a server must ignore.
        let ce = StaticSecret::from(secret(0x10));
        let good = client_hello(&pubkey(&ce), CAP_SERVER_AUTH);
        let both = CAP_SERVER_AUTH | CAP_CLIENT_AUTH;
        let mut bad_hellos: Vec<(&str, u16, Vec<u8>)> = vec![
            ("unpadded", CAP_SERVER_AUTH, good[..42].to_vec()),
            ("too-long", CAP_SERVER_AUTH, [&good[..], &[0]].concat()),
            ("version-2", CAP_SERVER_AUTH, {
                let mut h = good.clone();
                h[6] = 2;
                h
            }),
        ];
        // Low-order points: zero, one, and a point of order 8 (all give an
        // all-zero shared secret).
        for (n, point) in [
            ("low-order-zero", [0u8; 32]),
            ("low-order-one", core::array::from_fn(|i| (i == 0) as u8)),
            (
                "low-order-eight",
                unhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
                    .try_into()
                    .unwrap(),
            ),
        ] {
            bad_hellos.push((n, CAP_SERVER_AUTH, client_hello(&point, CAP_SERVER_AUTH)));
        }
        // A low-order identity key, to a server that accepts identities.
        let low_id: [u8; 32] = core::array::from_fn(|i| (i == 0) as u8);
        bad_hellos.push((
            "low-order-identity",
            both,
            client_hello_with_identity(&pubkey(&ce), CAP_SERVER_AUTH, Some(&low_id)),
        ));
        let se = StaticSecret::from(secret(0x40));
        for (n, caps, h) in &bad_hellos {
            assert!(server_respond(h, &se, None, *caps).is_none(), "{n}");
            t.push_str(&format!(
                "reject-client-hello {n} {} {}\n",
                hex(&caps.to_be_bytes()),
                hex(h)
            ));
        }
        // ... which the same server accepts from a client with a real key.
        let id = IdentityKey::from_secret(secret(0xD0));
        let with_id = client_hello_with_identity(&pubkey(&ce), CAP_SERVER_AUTH, Some(&id.public()));
        assert!(server_respond(&with_id, &se, None, both).is_some());

        // Server hellos a client must reject. Some are built with a valid
        // confirmation tag, so that only the rule under test fails.
        let forge = |caps: u16, e_s: [u8; 32], static_pub: Option<[u8; 32]>, es: &[u8]| {
            let mut body = vec![0, 2];
            body.extend_from_slice(&MAGIC);
            body.extend_from_slice(&[VERSION, 0]);
            body.extend_from_slice(&caps.to_le_bytes());
            body.extend_from_slice(&e_s);
            if let Some(p) = static_pub {
                body.extend_from_slice(&p);
            }
            let ee = ce.diffie_hellman(&PublicKey::from(e_s));
            let keys = derive(&good, &body, ee.as_bytes(), es);
            body.extend_from_slice(&confirm_tag(&keys));
            body
        };
        let static_key = ServerKey::from_secret(secret(0x70));
        let (auth_hello, _) =
            server_respond(&good, &se, Some(&static_key), CAP_SERVER_AUTH).unwrap();
        let (anon_hello, _) = server_respond(&good, &se, None, CAP_SERVER_AUTH).unwrap();
        let flip = |h: &[u8], i: usize| {
            let mut h = h.to_vec();
            h[i] ^= 1;
            h
        };
        let low_one: [u8; 32] = core::array::from_fn(|i| (i == 0) as u8);
        let other_pin = ServerKey::from_secret(secret(0xA0)).public();
        /// Name, pinned key, server hello.
        type BadServerHello<'a> = (&'a str, Option<[u8; 32]>, Vec<u8>);
        let bad_server: Vec<BadServerHello> = vec![
            ("bad-tag", None, flip(&anon_hello, 57)),
            ("tampered-ephemeral", None, flip(&anon_hello, 20)),
            ("tampered-static", None, flip(&auth_hello, 50)),
            ("tampered-flags", None, flip(&anon_hello, 7)),
            ("truncated", None, anon_hello[..57].to_vec()),
            (
                "auth-length-mismatch",
                None,
                [&anon_hello[..], &[0; 32]].concat(),
            ),
            ("version-2", None, {
                let mut h = anon_hello.clone();
                h[6] = 2;
                h
            }),
            (
                "unoffered-capability",
                None,
                forge(0x0004, pubkey(&se), None, &[]),
            ),
            (
                "unoffered-client-auth",
                None,
                forge(CAP_CLIENT_AUTH, pubkey(&se), None, &[]),
            ),
            ("low-order-ephemeral", None, forge(0, low_one, None, &[])),
            (
                "low-order-static",
                None,
                forge(CAP_SERVER_AUTH, pubkey(&se), Some(low_one), &[0; 32]),
            ),
            ("pinned-key-mismatch", Some(other_pin), auth_hello.clone()),
            (
                "pinned-but-anonymous",
                Some(static_key.public()),
                anon_hello.clone(),
            ),
        ];
        for (n, pin, h) in &bad_server {
            assert!(
                client_finish(&good, &ce, h, pin.as_ref()).is_err(),
                "{n} must be rejected"
            );
            t.push_str(&format!(
                "reject-server-hello {n} {} {} {} {}\n",
                hex(&ce.to_bytes()),
                hex(&good),
                pin.map_or("-".to_owned(), |p| hex(&p)),
                hex(h)
            ));
        }
        // The forged hellos are valid apart from the rule under test.
        assert!(client_finish(&good, &ce, &forge(0, pubkey(&se), None, &[]), None).is_ok());

        // Receiver counter reconstruction and replay window.
        let windows: [(&str, &[(u64, bool)]); 6] = [
            (
                "in-order-and-replays",
                &[(1, true), (2, true), (2, true), (1, true), (0, true)],
            ),
            (
                "reordering",
                &[(5, true), (3, true), (4, true), (3, true), (6, true)],
            ),
            (
                "window-edge",
                &[(100, true), (37, true), (36, true), (101, true), (38, true)],
            ),
            (
                "forged-records-burn-nothing",
                &[(7, false), (7, true), (8, false), (8, true)],
            ),
            (
                "across-2^32",
                &[
                    (0xFFFF_FFF0, true),
                    (0x1_0000_0005, true),
                    (0xFFFF_FFF1, true),
                    (0xFFFF_FFF0, true),
                    (0x1_0000_0004, true),
                ],
            ),
            (
                "far-jumps",
                &[
                    (1, true),
                    (0x8000_0001, true),
                    (1, true),
                    (0x8000_0002, true),
                ],
            ),
        ];
        let (_, keys) = server_respond(&good, &se, None, CAP_SERVER_AUTH).unwrap();
        for (n, steps) in windows {
            let mut rx = OpenSecCipher::new(&keys, true, None);
            t.push_str(&format!("window {n}"));
            for &(counter, valid) in steps {
                let mut wire = seal_record(&keys.c2s, Direction::ClientToServer, counter, &[1]);
                if !valid {
                    *wire.last_mut().unwrap() ^= 1;
                }
                let low = counter as u32;
                let expanded = rx.expand_counter(low);
                let accepted = rx.decrypt(&mut wire);
                t.push_str(&format!(
                    " {low}{}={}",
                    if valid { "" } else { "!" },
                    if accepted {
                        expanded.to_string()
                    } else {
                        "x".to_owned()
                    }
                ));
            }
            t.push('\n');
        }
        t
    }

    #[test]
    fn published_vectors() {
        let text = vector_text();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/opensec.txt");
        if std::env::var_os("OSS_REGEN_VECTORS").is_some() {
            std::fs::write(path, &text).unwrap();
        }
        let committed = std::fs::read_to_string(path).expect("tests/vectors/opensec.txt");
        assert_eq!(
            committed.replace("\r\n", "\n"),
            text,
            "OpenSec output changed; vectors differ"
        );
        // Every record matches seal_record and opens with open_record.
        let mut keys = (Vec::new(), Vec::new());
        for line in text.lines() {
            let f: Vec<&str> = line.split(' ').collect();
            match f[0] {
                "key_c2s" => keys.0 = unhex(f[1]),
                "key_s2c" => keys.1 = unhex(f[1]),
                "record" => {
                    let (key, dir) = if f[1] == "c2s" {
                        (&keys.0, Direction::ClientToServer)
                    } else {
                        (&keys.1, Direction::ServerToClient)
                    };
                    let key: [u8; 32] = key.as_slice().try_into().unwrap();
                    let counter: u64 = f[2].parse().unwrap();
                    let (plain, wire) = (unhex(f[3]), unhex(f[4]));
                    assert_eq!(seal_record(&key, dir, counter, &plain), wire);
                    assert_eq!(open_record(&key, dir, counter, &wire), Some(plain.clone()));
                    assert_eq!(open_record(&key, dir, counter + 1, &wire), None);
                    let mut bad = wire.clone();
                    *bad.last_mut().unwrap() ^= 1;
                    assert_eq!(open_record(&key, dir, counter, &bad), None);
                }
                _ => {}
            }
        }
    }
}
