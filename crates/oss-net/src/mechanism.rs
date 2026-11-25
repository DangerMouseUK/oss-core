//! Security mechanisms: one description of each kind of encryption a program
//! can speak, and everything that lists, orders or picks them read from it.
//!
//! A **mechanism** is one way of securing a connection: no encryption, the
//! SubSpace cipher (VIE), OpenSec, or one supplied from outside this crate. Each
//! is described once, as a [`Mechanism`]: its identifier, the name people see,
//! how strong it is, whether it may be tried automatically or only when asked
//! for by name, which era the zone should treat it as, and a constructor for
//! each of its halves. The halves are the three traits in [`crate::cipher`]: a
//! client half builds a fresh [`Handshake`] for each connection, a server half
//! builds the [`Acceptor`] a [`crate::Server`] asks about each new peer.
//!
//! Two objects are built from those descriptions, and they are kept apart on
//! purpose:
//!
//! - a [`MechanismRegistry`] is what a program **can** speak. Registration
//!   order means nothing: the registry keeps its mechanisms by strength.
//! - a [`MechanismPolicy`] is what it **prefers**, in order. By default it is
//!   derived from the strengths the mechanisms declare
//!   ([`MechanismPolicy::automatic`]); a person can replace it
//!   ([`MechanismPolicy::from_names`]).
//!
//! Everything that used to be written out by hand is read from those two: the
//! start-up line ([`MechanismRegistry::supported_line`]), the automatic order
//! and the [`Ladder`] that walks it ([`MechanismPolicy::client_handshake`]),
//! picking one mechanism by name ([`MechanismRegistry::client_handshake`]), and
//! the server's acceptors ([`MechanismPolicy::acceptors`]). **Adding a mechanism
//! is one call to [`MechanismRegistry::register`]**, and it then takes its place
//! in all of them.
//!
//! ```
//! use oss_net::mechanism::{MechanismPolicy, MechanismRegistry};
//!
//! let registry = MechanismRegistry::builtin();
//! # #[cfg(all(feature = "opensec", feature = "os-entropy"))]
//! assert_eq!(
//!     registry.supported_line(),
//!     "Mechanisms supported: None, Subspace, OpenSecurity"
//! );
//! let policy = MechanismPolicy::automatic(&registry);
//! # #[cfg(all(feature = "opensec", feature = "os-entropy"))]
//! assert_eq!(policy.automatic_line(&registry), "Automatic order: OpenSecurity, then Subspace");
//! ```
//!
//! # Identifiers
//!
//! This project's own mechanisms have short identifiers, reserved to it:
//! `none`, `vie`, `continuum` and `opensec` ([`MechanismId::RESERVED`]). Anyone
//! else names theirs `name@their-domain` (the SSH convention, RFC 4250
//! §4.6.1): no permission is needed and two names cannot collide. Short names
//! match without regard to case (`VIE` is `vie`); `name@domain` names match
//! exactly. Identifiers are for settings, logs and records only. None of this
//! puts an identifier on the wire.
//!
//! # The floor
//!
//! Nothing automatic goes below the SubSpace cipher. A mechanism weaker than it,
//! and `none` whatever strength it claims, can only be
//! [`Selection::ByNameOnly`]: the registry refuses it otherwise, and a policy
//! refuses to put one in the automatic order. A server can still serve one,
//! because an operator switched it on ([`MechanismPolicy::allow_deliberately`]).

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::cipher::{Acceptor, Handshake, NullAcceptor, Step, VieAcceptor, VieClientHandshake};
#[cfg(feature = "opensec")]
use crate::opensec::{Entropy, IdentityKey, OpenSecAcceptor, OpenSecClientHandshake, ServerKey};

/// The longest identifier allowed, as in RFC 4250 §4.6.1.
const MAX_ID_LEN: usize = 64;

/// Why a mechanism, a registration or a policy was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MechanismError {
    /// The identifier is not a valid mechanism name.
    Malformed {
        /// What was given.
        name: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A short name that is not one of this project's. Anyone else's
    /// mechanism is named `name@their-domain`.
    Unqualified(String),
    /// A mechanism with this identifier is already registered.
    DuplicateId(MechanismId),
    /// A mechanism with this display name is already registered, so the
    /// start-up line could not tell the two apart.
    DuplicateDisplayName(String),
    /// The display name is empty, or holds a comma or a control character.
    BadDisplayName {
        /// What was given.
        name: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A mechanism declared automatic is `none`, or weaker than the SubSpace
    /// cipher. Nothing automatic goes below that floor.
    BelowFloor(MechanismId),
    /// A mechanism that may only be asked for by name was put in an automatic
    /// order.
    NotAutomatic(MechanismId),
    /// No registered mechanism has this name.
    Unknown(String),
    /// The mechanism has no client half, so a client cannot use it.
    NoClientHalf(MechanismId),
    /// The same mechanism was named twice in one order.
    Repeated(MechanismId),
    /// The order, or the ladder, has nothing in it.
    Empty,
}

impl fmt::Display for MechanismError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { name, reason } => {
                write!(f, "{name:?} is not a valid mechanism name: {reason}")
            }
            Self::Unqualified(name) => write!(
                f,
                "{name:?} is not one of this project's mechanisms ({}); \
                 anyone else's is named name@their-domain",
                MechanismId::RESERVED.join(", ")
            ),
            Self::DuplicateId(id) => write!(f, "mechanism {id} is already registered"),
            Self::DuplicateDisplayName(name) => {
                write!(f, "a mechanism called {name:?} is already registered")
            }
            Self::BadDisplayName { name, reason } => {
                write!(f, "{name:?} cannot be a mechanism's display name: {reason}")
            }
            Self::BelowFloor(id) => write!(
                f,
                "mechanism {id} cannot be tried automatically: nothing automatic goes \
                 below the SubSpace cipher, so it may only be asked for by name"
            ),
            Self::NotAutomatic(id) => write!(
                f,
                "mechanism {id} may only be asked for by name, so it cannot be in an \
                 automatic order"
            ),
            Self::Unknown(name) => write!(f, "no mechanism called {name:?} is registered"),
            Self::NoClientHalf(id) => write!(f, "mechanism {id} has no client half"),
            Self::Repeated(id) => write!(f, "mechanism {id} is named twice"),
            Self::Empty => f.write_str("no mechanisms to use"),
        }
    }
}

impl std::error::Error for MechanismError {}

/// A mechanism's identifier: one of this project's short names, or
/// `name@domain` for anyone else's. Checked when it is made.
///
/// Short names are stored in lower case, so `MechanismId::new("VIE")` is `vie`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MechanismId(Box<str>);

impl MechanismId {
    /// The short names reserved to this project. No other short name is
    /// accepted; anyone else's mechanism is named `name@their-domain`.
    pub const RESERVED: [&'static str; 4] = ["none", "vie", "continuum", "opensec"];

    /// Checks `name` and makes an identifier of it.
    ///
    /// A short name must be one of [`RESERVED`](Self::RESERVED) (any case). Any
    /// other name must be `name@domain`: at most 64 characters, printable
    /// ASCII with no spaces and no commas, exactly one `@`, something before
    /// it, and a domain name after it (two or more labels of letters, digits
    /// and hyphens, none starting or ending with a hyphen).
    pub fn new(name: &str) -> Result<Self, MechanismError> {
        let malformed = |reason| MechanismError::Malformed {
            name: name.to_owned(),
            reason,
        };
        if name.is_empty() {
            return Err(malformed("it is empty"));
        }
        if name.len() > MAX_ID_LEN {
            return Err(malformed("it is longer than 64 characters"));
        }
        if !name.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(malformed(
                "it holds a space, a control character or a character outside ASCII",
            ));
        }
        if name.contains(',') {
            return Err(malformed("it holds a comma"));
        }
        let Some((local, domain)) = name.split_once('@') else {
            return match Self::RESERVED.iter().find(|r| r.eq_ignore_ascii_case(name)) {
                Some(r) => Ok(Self((*r).into())),
                None => Err(MechanismError::Unqualified(name.to_owned())),
            };
        };
        if local.is_empty() {
            return Err(malformed("nothing comes before the @"));
        }
        if domain.contains('@') {
            return Err(malformed("it holds more than one @"));
        }
        if !is_domain(domain) {
            return Err(malformed("what follows the @ is not a domain name"));
        }
        Ok(Self(name.into()))
    }

    /// The identifier as written in settings and logs.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is one of this project's short names.
    pub fn is_reserved(&self) -> bool {
        !self.0.contains('@')
    }

    /// Whether `typed` names this mechanism: a short name without regard to
    /// case, a `name@domain` name exactly.
    pub fn matches(&self, typed: &str) -> bool {
        if self.is_reserved() {
            self.0.eq_ignore_ascii_case(typed)
        } else {
            *self.0 == *typed
        }
    }
}

impl fmt::Display for MechanismId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `s` is a domain name: two or more dot-separated labels, each 1 to
/// 63 letters, digits and hyphens, not starting or ending with a hyphen.
fn is_domain(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// What the zone should treat a connection as. It decides, for example, which
/// login form the client sends and the zone expects.
///
/// An era is declared by the mechanism, not worked out from what it is called,
/// so a mechanism from outside this crate says which one it is rather than
/// being guessed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Era {
    /// The original SubSpace client's: the VIE cipher, and no encryption.
    SubSpace,
    /// The Continuum client's.
    Continuum,
    /// Newer than both, such as OpenSec.
    Modern,
}

/// Whether a mechanism may be tried automatically, or only when somebody asks
/// for it by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Selection {
    /// It may appear in the automatic order, at the place its strength gives
    /// it. Refused for `none` and for anything weaker than the SubSpace cipher.
    Automatic,
    /// Only when a person names it: `--security`, a settings file, or an
    /// operator's switch. Never reached on its own.
    ByNameOnly,
}

/// What a client half is given to build one connection's handshake.
///
/// Built with [`ClientContext::new`] and the methods after it, so that more can
/// be added without breaking anyone.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct ClientContext {
    /// The connection's seed, for handshakes that derive a key from one (the
    /// SubSpace cipher does).
    pub seed: u32,
    /// The server's long-term key, if one is on record, and the mechanism that
    /// recorded it.
    pub pinned: Option<(MechanismId, [u8; 32])>,
    /// The OpenSec identity to offer this zone, if any.
    #[cfg(feature = "opensec")]
    pub identity: Option<IdentityKey>,
}

impl fmt::Debug for ClientContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("ClientContext");
        d.field("seed", &self.seed)
            .field("pinned", &self.pinned.as_ref().map(|(id, _)| id));
        #[cfg(feature = "opensec")]
        d.field("identity", &self.identity.is_some());
        d.finish()
    }
}

impl ClientContext {
    /// A context with this seed, no key on record and no identity.
    pub fn new(seed: u32) -> Self {
        Self {
            seed,
            ..Self::default()
        }
    }

    /// The server's key is on record, recorded by `mechanism`. An automatic
    /// order then uses that mechanism and nothing else: stepping down from a
    /// key on record would be a downgrade.
    pub fn pinned(mut self, mechanism: MechanismId, key: [u8; 32]) -> Self {
        self.pinned = Some((mechanism, key));
        self
    }

    /// Offers this OpenSec identity to the zone.
    #[cfg(feature = "opensec")]
    pub fn identity(mut self, identity: IdentityKey) -> Self {
        self.identity = Some(identity);
        self
    }

    /// The key on record for `mechanism`, if the one on record is its.
    pub fn pinned_for(&self, mechanism: &MechanismId) -> Option<[u8; 32]> {
        self.pinned
            .as_ref()
            .and_then(|(id, key)| (id == mechanism).then_some(*key))
    }
}

/// Builds one connection's client handshake.
pub type ClientHalf = Arc<dyn Fn(&ClientContext) -> Box<dyn Handshake> + Send + Sync>;

/// Builds the server's acceptor for a mechanism.
pub type ServerHalf = Arc<dyn Fn() -> Box<dyn Acceptor> + Send + Sync>;

/// One mechanism, described once.
///
/// ```
/// use oss_net::mechanism::{Era, Mechanism, Selection};
/// use oss_net::{VieAcceptor, VieClientHandshake};
///
/// let m = Mechanism::new("example@example.org", "Example", Era::Modern, 2000, Selection::Automatic)
///     .unwrap()
///     .client(|ctx| Box::new(VieClientHandshake::new(ctx.seed)))
///     .server(|| Box::new(VieAcceptor::default()));
/// assert_eq!(m.display_name(), "Example");
/// ```
#[derive(Clone)]
pub struct Mechanism {
    id: MechanismId,
    display_name: Box<str>,
    era: Era,
    strength: u16,
    selection: Selection,
    client: Option<ClientHalf>,
    server: Option<ServerHalf>,
}

impl fmt::Debug for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mechanism")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("era", &self.era)
            .field("strength", &self.strength)
            .field("selection", &self.selection)
            .field("client", &self.client.is_some())
            .field("server", &self.server.is_some())
            .finish()
    }
}

impl Mechanism {
    /// `none`'s strength: the weakest there is.
    pub const STRENGTH_NONE: u16 = 0;
    /// The SubSpace cipher's (`vie`) strength. It is also the floor: nothing
    /// weaker may be tried automatically.
    pub const STRENGTH_VIE: u16 = 1000;
    /// OpenSec's (`opensec`) strength. The gaps either side leave room for
    /// mechanisms to sit between the built-in ones.
    pub const STRENGTH_OPENSEC: u16 = 3000;

    /// A mechanism with no halves yet; add them with [`client`](Self::client)
    /// and [`server`](Self::server).
    ///
    /// `display_name` is what people see, in the start-up line for one. It
    /// must not be empty and must hold no comma or control character.
    /// `strength` places it: stronger mechanisms come earlier in the automatic
    /// order and later in the start-up line, and two of equal strength are
    /// ordered by identifier.
    pub fn new(
        id: &str,
        display_name: &str,
        era: Era,
        strength: u16,
        selection: Selection,
    ) -> Result<Self, MechanismError> {
        let id = MechanismId::new(id)?;
        let bad = |reason| MechanismError::BadDisplayName {
            name: display_name.to_owned(),
            reason,
        };
        if display_name.trim().is_empty() {
            return Err(bad("it is empty"));
        }
        if display_name.contains(',') {
            return Err(bad("it holds a comma"));
        }
        if display_name.chars().any(char::is_control) {
            return Err(bad("it holds a control character"));
        }
        Ok(Self {
            id,
            display_name: display_name.into(),
            era,
            strength,
            selection,
            client: None,
            server: None,
        })
    }

    /// Gives the mechanism a client half: called once per connection.
    pub fn client(
        mut self,
        half: impl Fn(&ClientContext) -> Box<dyn Handshake> + Send + Sync + 'static,
    ) -> Self {
        self.client = Some(Arc::new(half));
        self
    }

    /// Gives the mechanism a server half: called once, when a server is set up.
    pub fn server(mut self, half: impl Fn() -> Box<dyn Acceptor> + Send + Sync + 'static) -> Self {
        self.server = Some(Arc::new(half));
        self
    }

    /// The identifier.
    pub fn id(&self) -> &MechanismId {
        &self.id
    }

    /// The name people see.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// What the zone should treat a connection using it as.
    pub fn era(&self) -> Era {
        self.era
    }

    /// How strong it is, relative to the others.
    pub fn strength(&self) -> u16 {
        self.strength
    }

    /// Whether it may be tried automatically.
    pub fn selection(&self) -> Selection {
        self.selection
    }

    /// Whether it may appear in an automatic order.
    pub fn is_automatic(&self) -> bool {
        self.selection == Selection::Automatic
    }

    /// Whether a client can use it.
    pub fn has_client(&self) -> bool {
        self.client.is_some()
    }

    /// Whether a server can use it.
    pub fn has_server(&self) -> bool {
        self.server.is_some()
    }

    /// A fresh client handshake, if it has a client half.
    pub fn handshake(&self, ctx: &ClientContext) -> Option<Box<dyn Handshake>> {
        self.client.as_ref().map(|half| half(ctx))
    }

    /// A fresh acceptor, if it has a server half.
    pub fn acceptor(&self) -> Option<Box<dyn Acceptor>> {
        self.server.as_ref().map(|half| half())
    }

    /// `none`: no encryption, only ever by name. The client half asks for an
    /// unencrypted session ([`VieClientHandshake::unencrypted`]); the server
    /// half answers one ([`NullAcceptor`]).
    pub fn none() -> Self {
        Self::new(
            "none",
            "None",
            Era::SubSpace,
            Self::STRENGTH_NONE,
            Selection::ByNameOnly,
        )
        .expect("the built-in description is valid")
        .client(|_| Box::new(VieClientHandshake::unencrypted()))
        .server(|| Box::new(NullAcceptor))
    }

    /// `vie`: the SubSpace cipher. The client half is
    /// [`VieClientHandshake::new`] with the connection's seed; the server half
    /// is [`VieAcceptor::default`].
    pub fn vie() -> Self {
        Self::vie_with(VieAcceptor::default())
    }

    /// `vie` with a server half configured differently, for example one that
    /// does not answer Continuum clients.
    pub fn vie_with(acceptor: VieAcceptor) -> Self {
        Self::new(
            "vie",
            "Subspace",
            Era::SubSpace,
            Self::STRENGTH_VIE,
            Selection::Automatic,
        )
        .expect("the built-in description is valid")
        .client(|ctx| Box::new(VieClientHandshake::new(ctx.seed)))
        .server(move || Box::new(acceptor))
    }

    /// `opensec`: this project's own encryption. The client half offers the
    /// context's identity and pins the context's key when the key on record is
    /// OpenSec's; the server half is an [`OpenSecAcceptor`] built from `setup`.
    #[cfg(feature = "opensec")]
    pub fn opensec(setup: OpenSecSetup) -> Self {
        let id = MechanismId::new("opensec").expect("a reserved name");
        let OpenSecSetup {
            entropy,
            server_key,
            client_identities,
        } = setup;
        let client_entropy = entropy.clone();
        Self::new(
            id.as_str(),
            "OpenSecurity",
            Era::Modern,
            Self::STRENGTH_OPENSEC,
            Selection::Automatic,
        )
        .expect("the built-in description is valid")
        .client(move |ctx| {
            let hs = OpenSecClientHandshake::new(&client_entropy, ctx.pinned_for(&id));
            Box::new(match ctx.identity.clone() {
                Some(identity) => hs.with_identity(identity),
                None => hs,
            })
        })
        .server(move || {
            let acceptor = OpenSecAcceptor::new(server_key.clone(), entropy.clone());
            Box::new(if client_identities {
                acceptor.with_client_identities()
            } else {
                acceptor
            })
        })
    }
}

/// What the built-in OpenSec mechanism is made from.
#[cfg(feature = "opensec")]
#[derive(Clone)]
pub struct OpenSecSetup {
    entropy: Entropy,
    server_key: Option<ServerKey>,
    client_identities: bool,
}

#[cfg(feature = "opensec")]
impl fmt::Debug for OpenSecSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenSecSetup")
            .field("server_key", &self.server_key)
            .field("client_identities", &self.client_identities)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "opensec")]
impl OpenSecSetup {
    /// Randomness from `entropy`, no server key, and no client identities.
    /// Enough for a client.
    pub fn new(entropy: Entropy) -> Self {
        Self {
            entropy,
            server_key: None,
            client_identities: false,
        }
    }

    /// The server's long-term key, so clients can authenticate and pin it.
    pub fn server_key(mut self, key: ServerKey) -> Self {
        self.server_key = Some(key);
        self
    }

    /// The server also takes client identity keys (see
    /// [`OpenSecAcceptor::with_client_identities`]).
    pub fn client_identities(mut self) -> Self {
        self.client_identities = true;
        self
    }
}

/// What a program can speak: every mechanism it has, kept weakest first.
///
/// The order mechanisms are registered in means nothing. They are kept by
/// strength (ties by identifier), so the same set gives the same order however
/// the program happened to register it. **What the program prefers is a
/// [`MechanismPolicy`]**, a separate object.
#[derive(Debug, Clone, Default)]
pub struct MechanismRegistry {
    /// Weakest first.
    mechanisms: Vec<Mechanism>,
}

impl MechanismRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// The mechanisms in this crate: `none`, `vie` and, when this crate is
    /// built with its `opensec` and `os-entropy` features (the default),
    /// `opensec` with randomness from the operating system and no server key.
    ///
    /// A server that has a long-term OpenSec key, or wants other randomness,
    /// uses [`builtin_with_opensec`](Self::builtin_with_opensec).
    pub fn builtin() -> Self {
        #[cfg(all(feature = "opensec", feature = "os-entropy"))]
        {
            Self::builtin_with_opensec(OpenSecSetup::new(crate::opensec::os_entropy()))
        }
        #[cfg(not(all(feature = "opensec", feature = "os-entropy")))]
        {
            let mut r = Self::new();
            r.register(Mechanism::none())
                .expect("the built-ins do not clash");
            r.register(Mechanism::vie())
                .expect("the built-ins do not clash");
            r
        }
    }

    /// `none`, `vie`, and `opensec` made from `setup`.
    #[cfg(feature = "opensec")]
    pub fn builtin_with_opensec(setup: OpenSecSetup) -> Self {
        let mut r = Self::new();
        for m in [
            Mechanism::none(),
            Mechanism::vie(),
            Mechanism::opensec(setup),
        ] {
            r.register(m).expect("the built-ins do not clash");
        }
        r
    }

    /// Adds a mechanism.
    ///
    /// Refused if its identifier or display name is already registered, or if
    /// it is declared [`Selection::Automatic`] and is `none` or weaker than the
    /// SubSpace cipher ([`Mechanism::STRENGTH_VIE`]).
    pub fn register(&mut self, mechanism: Mechanism) -> Result<(), MechanismError> {
        if self.mechanisms.iter().any(|m| m.id == mechanism.id) {
            return Err(MechanismError::DuplicateId(mechanism.id));
        }
        if self.mechanisms.iter().any(|m| {
            m.display_name
                .trim()
                .eq_ignore_ascii_case(mechanism.display_name.trim())
        }) {
            return Err(MechanismError::DuplicateDisplayName(
                mechanism.display_name.into(),
            ));
        }
        if mechanism.is_automatic()
            && (mechanism.id.as_str() == "none" || mechanism.strength < Mechanism::STRENGTH_VIE)
        {
            return Err(MechanismError::BelowFloor(mechanism.id));
        }
        let at = self
            .mechanisms
            .partition_point(|m| (m.strength, &m.id) < (mechanism.strength, &mechanism.id));
        self.mechanisms.insert(at, mechanism);
        Ok(())
    }

    /// Every mechanism, weakest first.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Mechanism> {
        self.mechanisms.iter()
    }

    /// How many mechanisms are registered.
    pub fn len(&self) -> usize {
        self.mechanisms.len()
    }

    /// Whether none are.
    pub fn is_empty(&self) -> bool {
        self.mechanisms.is_empty()
    }

    /// The mechanism with this identifier.
    pub fn get(&self, id: &MechanismId) -> Option<&Mechanism> {
        self.mechanisms.iter().find(|m| m.id == *id)
    }

    /// The mechanism a person typed the name of: a short name without regard to
    /// case, a `name@domain` name exactly. Display names are not accepted;
    /// only identifiers are typed.
    pub fn find(&self, typed: &str) -> Option<&Mechanism> {
        self.mechanisms.iter().find(|m| m.id.matches(typed.trim()))
    }

    /// The identifiers, weakest first: the words `--security` and a settings
    /// file accept.
    pub fn ids(&self) -> impl Iterator<Item = &MechanismId> {
        self.mechanisms.iter().map(|m| &m.id)
    }

    /// The start-up line: `Mechanisms supported: ` and every display name,
    /// weakest first, for example
    /// `Mechanisms supported: None, Subspace, OpenSecurity`.
    pub fn supported_line(&self) -> String {
        format!("Mechanisms supported: {}", join(self.iter()))
    }

    /// The handshake for the mechanism a person asked for by name, whether or
    /// not it may be tried automatically. A key on record for another
    /// mechanism does not override the choice: a person asking is explicit.
    pub fn client_handshake(
        &self,
        typed: &str,
        ctx: &ClientContext,
    ) -> Result<Box<dyn Handshake>, MechanismError> {
        let m = self
            .find(typed)
            .ok_or_else(|| MechanismError::Unknown(typed.to_owned()))?;
        m.handshake(ctx)
            .ok_or_else(|| MechanismError::NoClientHalf(m.id.clone()))
    }

    fn lookup(&self, id: &MechanismId) -> Result<&Mechanism, MechanismError> {
        self.get(id)
            .ok_or_else(|| MechanismError::Unknown(id.as_str().to_owned()))
    }
}

/// Display names joined with commas.
fn join<'a>(mechanisms: impl Iterator<Item = &'a Mechanism>) -> String {
    let names: Vec<&str> = mechanisms.map(Mechanism::display_name).collect();
    names.join(", ")
}

/// What a program prefers: the automatic order, strongest first, and on a
/// server any by-name-only mechanisms an operator switched on.
///
/// Derived from a registry by [`automatic`](Self::automatic), or written by a
/// person with [`from_names`](Self::from_names). Either way it never holds a
/// by-name-only mechanism in its automatic order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MechanismPolicy {
    /// Tried in this order, strongest first by default.
    order: Vec<MechanismId>,
    /// By-name-only mechanisms switched on by an operator: served after the
    /// automatic ones, never tried by a client on its own.
    deliberate: Vec<MechanismId>,
}

impl MechanismPolicy {
    /// Every automatic mechanism in `registry`, strongest first.
    pub fn automatic(registry: &MechanismRegistry) -> Self {
        Self {
            order: registry
                .iter()
                .rev()
                .filter(|m| m.is_automatic())
                .map(|m| m.id.clone())
                .collect(),
            deliberate: Vec::new(),
        }
    }

    /// An order a person wrote, for example from a settings key. Each name is
    /// matched as [`MechanismRegistry::find`] does.
    ///
    /// Refused if a name is unknown, named twice, or may only be asked for by
    /// name, or if there are no names.
    pub fn from_names<S: AsRef<str>>(
        registry: &MechanismRegistry,
        names: impl IntoIterator<Item = S>,
    ) -> Result<Self, MechanismError> {
        let mut order: Vec<MechanismId> = Vec::new();
        for name in names {
            let name = name.as_ref();
            let m = registry
                .find(name)
                .ok_or_else(|| MechanismError::Unknown(name.to_owned()))?;
            if !m.is_automatic() {
                return Err(MechanismError::NotAutomatic(m.id.clone()));
            }
            if order.contains(&m.id) {
                return Err(MechanismError::Repeated(m.id.clone()));
            }
            order.push(m.id.clone());
        }
        if order.is_empty() {
            return Err(MechanismError::Empty);
        }
        Ok(Self {
            order,
            deliberate: Vec::new(),
        })
    }

    /// Also serves a by-name-only mechanism, because an operator switched it on
    /// (no encryption, for development). A server asks it after every automatic
    /// one; a client's automatic order never includes it.
    pub fn allow_deliberately(
        mut self,
        registry: &MechanismRegistry,
        typed: &str,
    ) -> Result<Self, MechanismError> {
        let m = registry
            .find(typed)
            .ok_or_else(|| MechanismError::Unknown(typed.to_owned()))?;
        if self.order.contains(&m.id) || self.deliberate.contains(&m.id) {
            return Err(MechanismError::Repeated(m.id.clone()));
        }
        self.deliberate.push(m.id.clone());
        Ok(self)
    }

    /// The automatic order, first tried first.
    pub fn order(&self) -> &[MechanismId] {
        &self.order
    }

    /// The mechanisms switched on deliberately, in the order they were.
    pub fn deliberate(&self) -> &[MechanismId] {
        &self.deliberate
    }

    /// `Automatic order: ` and the display names, first tried first, joined
    /// with `, then `: for example `Automatic order: OpenSecurity, then
    /// Subspace`. Names not in `registry` are skipped.
    pub fn automatic_line(&self, registry: &MechanismRegistry) -> String {
        let names: Vec<&str> = self
            .order
            .iter()
            .filter_map(|id| registry.get(id))
            .map(Mechanism::display_name)
            .collect();
        format!("Automatic order: {}", names.join(", then "))
    }

    /// `Mechanisms enabled on this zone: ` and every mechanism this policy
    /// serves, automatic or deliberate, weakest first like
    /// [`MechanismRegistry::supported_line`].
    pub fn enabled_line(&self, registry: &MechanismRegistry) -> String {
        let enabled = registry
            .iter()
            .filter(|m| self.order.contains(&m.id) || self.deliberate.contains(&m.id));
        format!("Mechanisms enabled on this zone: {}", join(enabled))
    }

    /// The client's handshake for a connection: a [`Ladder`] down the automatic
    /// order, stepping to the next rung after `step_after_ms` of silence.
    ///
    /// **A key on record means that mechanism and nothing else**, whatever the
    /// order says: the ladder then has the one rung, so it cannot be walked
    /// down. Mechanisms with no client half are skipped.
    pub fn client_handshake(
        &self,
        registry: &MechanismRegistry,
        ctx: &ClientContext,
        step_after_ms: u64,
    ) -> Result<Ladder, MechanismError> {
        if let Some((id, _)) = &ctx.pinned {
            let m = registry.lookup(id)?;
            let hs = m
                .handshake(ctx)
                .ok_or_else(|| MechanismError::NoClientHalf(m.id.clone()))?;
            return Ladder::new(step_after_ms, vec![(m.id.clone(), m.era, hs)]);
        }
        let mut rungs = Vec::new();
        for id in &self.order {
            let m = registry.lookup(id)?;
            if !m.is_automatic() {
                return Err(MechanismError::NotAutomatic(m.id.clone()));
            }
            if let Some(hs) = m.handshake(ctx) {
                rungs.push((m.id.clone(), m.era, hs));
            }
        }
        Ladder::new(step_after_ms, rungs)
    }

    /// The server's acceptors, in the order they are asked: the automatic order,
    /// then the deliberate ones. Mechanisms with no server half are skipped.
    pub fn acceptors(
        &self,
        registry: &MechanismRegistry,
    ) -> Result<Vec<Box<dyn Acceptor>>, MechanismError> {
        let mut out = Vec::new();
        for id in self.order.iter().chain(&self.deliberate) {
            if let Some(a) = registry.lookup(id)?.acceptor() {
                out.push(a);
            }
        }
        Ok(out)
    }
}

/// A client handshake that tries several mechanisms in turn, from the first
/// rung down: the general form of [`crate::Fallback`], with the same rules.
///
/// - **It steps down on silence**: when a rung has had `step_after_ms` since
///   its first [`poll`](Handshake::poll) without reporting that the server
///   [`answered`](Handshake::answered).
/// - **It steps down at once on [`Step::StepDown`]**: the server answered in a
///   mechanism the rung recognises and does not speak.
/// - **It never steps down on a failure**: a rung's [`Step::Failed`] ends the
///   handshake, so tampering cannot force a downgrade.
/// - **A rung that has answered keeps the ladder** however long the rest of its
///   setup takes.
///
/// Each step down [abandons](Handshake::abandon) the rung being left and asks
/// for a [fresh endpoint](Handshake::take_fresh_endpoint); the next rung starts
/// on the following poll. The last rung has no clock of its own beyond its own
/// timeout, and a [`Step::StepDown`] from it is passed on, which the connection
/// treats as a failure. See [`Handshake`], "Stepping between mechanisms".
///
/// Which rung is in use, and which one won, can be read at any time through
/// [`progress`](Self::progress), including after the ladder has been handed to
/// a [`crate::Connection`].
pub struct Ladder {
    rungs: Vec<Box<dyn Handshake>>,
    progress: LadderProgress,
    step_after_ms: u64,
    /// When the current rung was first polled.
    started: Option<u64>,
    /// Stepped down since [`Handshake::take_fresh_endpoint`] was last asked.
    fresh_endpoint: bool,
}

impl fmt::Debug for Ladder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ladder")
            .field("progress", &self.progress)
            .field("step_after_ms", &self.step_after_ms)
            .finish_non_exhaustive()
    }
}

impl Ladder {
    /// A ladder over `rungs`, first tried first, each with the mechanism it
    /// belongs to. Refused if there are none.
    pub fn new(
        step_after_ms: u64,
        rungs: Vec<(MechanismId, Era, Box<dyn Handshake>)>,
    ) -> Result<Self, MechanismError> {
        if rungs.is_empty() {
            return Err(MechanismError::Empty);
        }
        let (names, rungs): (Vec<_>, Vec<_>) = rungs
            .into_iter()
            .map(|(id, era, hs)| ((id, era), hs))
            .unzip();
        Ok(Self {
            rungs,
            progress: LadderProgress(Arc::new(Progress {
                rungs: names,
                current: AtomicUsize::new(0),
                established: AtomicBool::new(false),
            })),
            step_after_ms,
            started: None,
            fresh_endpoint: false,
        })
    }

    /// A handle that reports which rung is in use and which one won. Keep it
    /// before handing the ladder to a connection.
    pub fn progress(&self) -> LadderProgress {
        self.progress.clone()
    }

    fn current(&self) -> usize {
        self.progress.0.current.load(Ordering::Acquire)
    }

    fn on_last(&self) -> bool {
        self.current() + 1 >= self.rungs.len()
    }

    fn rung(&mut self) -> &mut dyn Handshake {
        let i = self.current();
        &mut *self.rungs[i]
    }

    /// Leaves the current rung for the next: the current one closes what it
    /// can, and the next waits for its first poll, which comes after the
    /// connection's driver has had the chance to take a fresh endpoint.
    fn step_down(&mut self, now: u64, out: &mut Vec<Vec<u8>>) {
        self.rung().abandon(now, out);
        self.progress.0.current.fetch_add(1, Ordering::AcqRel);
        self.started = None;
        self.fresh_endpoint = true;
    }

    /// What a rung's step means here: a step down is taken unless this is the
    /// last rung, a success is recorded, everything else is passed on.
    fn after(&mut self, step: Step, now: u64, out: &mut Vec<Vec<u8>>) -> Step {
        match step {
            Step::StepDown(_) if !self.on_last() => {
                self.step_down(now, out);
                Step::Pending
            }
            Step::Established(cipher) => {
                self.progress.0.established.store(true, Ordering::Release);
                Step::Established(cipher)
            }
            other => other,
        }
    }
}

impl Handshake for Ladder {
    fn on_datagram(&mut self, now: u64, data: &[u8], out: &mut Vec<Vec<u8>>) -> Step {
        let step = self.rung().on_datagram(now, data, out);
        self.after(step, now, out)
    }

    fn poll(&mut self, now: u64, out: &mut Vec<Vec<u8>>) -> Step {
        let started = *self.started.get_or_insert(now);
        if !self.on_last()
            && !self.rung().answered()
            && now.saturating_sub(started) >= self.step_after_ms
        {
            self.step_down(now, out);
            return Step::Pending;
        }
        let step = self.rung().poll(now, out);
        self.after(step, now, out)
    }

    fn answered(&self) -> bool {
        self.rungs[self.current()].answered()
    }

    fn abandon(&mut self, now: u64, out: &mut Vec<Vec<u8>>) {
        self.rung().abandon(now, out);
    }

    fn take_fresh_endpoint(&mut self) -> bool {
        let own = core::mem::take(&mut self.fresh_endpoint);
        let inner = self.rung().take_fresh_endpoint();
        own || inner
    }
}

/// Which rung of a [`Ladder`] is in use, and which one won. Cheap to clone;
/// every clone sees the same ladder.
#[derive(Clone)]
pub struct LadderProgress(Arc<Progress>);

struct Progress {
    rungs: Vec<(MechanismId, Era)>,
    current: AtomicUsize,
    established: AtomicBool,
}

impl fmt::Debug for LadderProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LadderProgress")
            .field("current", self.current())
            .field("established", &self.established().is_some())
            .finish()
    }
}

impl LadderProgress {
    fn current_rung(&self) -> &(MechanismId, Era) {
        let i = self.0.current.load(Ordering::Acquire);
        &self.0.rungs[i.min(self.0.rungs.len() - 1)]
    }

    /// The mechanism of the rung in use.
    pub fn current(&self) -> &MechanismId {
        &self.current_rung().0
    }

    /// The era of the rung in use.
    pub fn current_era(&self) -> Era {
        self.current_rung().1
    }

    /// The mechanism that won, once a rung has established a session.
    pub fn established(&self) -> Option<&MechanismId> {
        self.0
            .established
            .load(Ordering::Acquire)
            .then(|| self.current())
    }

    /// The era of the mechanism that won, once a rung has established a session:
    /// what the zone will treat the connection as.
    pub fn established_era(&self) -> Option<Era> {
        self.0
            .established
            .load(Ordering::Acquire)
            .then(|| self.current_era())
    }

    /// Every rung's mechanism, first tried first.
    pub fn rungs(&self) -> impl Iterator<Item = &MechanismId> {
        self.0.rungs.iter().map(|(id, _)| id)
    }
}
