//! The sans-IO bot session: everything except the socket and the clock.

use std::collections::{BTreeMap, VecDeque};

use oss_formats::Level;
use oss_net::{
    Config, Connection, DisconnectReason, Event, Fallback, Handshake, VieClientHandshake,
};
use oss_proto::c2s::{
    self, C2SChat, GoArena, Login, MapRequest, SecurityResponse, SetFreq, SetShip, arena_type,
};
use oss_proto::checksum::{map_checksum, settings_checksum, vie_exe_checksum};
use oss_proto::common::chat_type;
use oss_proto::s2c::{ChatBody, MapFilename, login_code};
use oss_proto::wire::FixedStr;
use oss_proto::{C2SPacket, C2SPosition, S2CPacket};

use crate::text::{from_latin1, to_latin1};

/// How the bot encrypts its connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Encryption {
    /// VIE, which every SubSpace server accepts.
    #[default]
    Vie,
    /// OpenSec only, optionally requiring the server's pinned static key.
    OpenSec {
        /// The server's public key, if known.
        pinned: Option<[u8; 32]>,
    },
    /// Try OpenSec, fall back to VIE if the server does not answer it.
    OpenSecOrVie,
}

/// What the bot logs in as and where it goes.
#[derive(Debug, Clone)]
pub struct BotConfig {
    /// Player name.
    pub name: String,
    /// Password.
    pub password: String,
    /// Arena to enter; `None` for any public arena.
    pub arena: Option<String>,
    /// Ship to fly once in the arena (0-7), or 8 to stay a spectator.
    pub ship: u8,
    /// Create the account if the server does not know the name.
    pub create_account: bool,
    /// Download the map so security checks can be answered correctly.
    pub download_map: bool,
    /// Encryption.
    pub encryption: Encryption,
    /// Machine id sent at login.
    pub machine_id: u32,
}

impl BotConfig {
    /// A spectator bot entering any public arena, using VIE.
    pub fn new(name: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            password: password.into(),
            arena: None,
            ship: SPECTATOR,
            create_account: true,
            download_map: true,
            encryption: Encryption::Vie,
            machine_id: 0x0B07_0B07,
        }
    }

    /// Enter this arena instead of a public one.
    pub fn arena(mut self, arena: impl Into<String>) -> Self {
        self.arena = Some(arena.into());
        self
    }

    /// Fly this ship (0-7; 8 = spectator).
    pub fn ship(mut self, ship: u8) -> Self {
        self.ship = ship;
        self
    }

    /// Use this encryption.
    pub fn encryption(mut self, encryption: Encryption) -> Self {
        self.encryption = encryption;
        self
    }
}

/// The spectator "ship".
pub const SPECTATOR: u8 = 8;

/// A player in the bot's arena.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Player {
    /// Player id.
    pub pid: i16,
    /// Name.
    pub name: String,
    /// Squad.
    pub squad: String,
    /// Ship (0-7, 8 = spectator).
    pub ship: u8,
    /// Frequency (team).
    pub freq: i16,
    /// Last known position in pixels.
    pub x: i16,
    /// Last known position in pixels.
    pub y: i16,
    /// Bounty.
    pub bounty: u16,
    /// Kills.
    pub wins: i16,
    /// Deaths.
    pub losses: i16,
}

/// Kind of chat message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChatKind {
    /// Green arena message from the server.
    Arena,
    /// Public macro.
    PublicMacro,
    /// Public message.
    Public,
    /// Team message.
    Team,
    /// Message to another team.
    EnemyTeam,
    /// Private message from a player in the arena.
    Private,
    /// Moderator warning.
    Warning,
    /// Private message from another arena or zone.
    RemotePrivate,
    /// Server error text.
    ServerError,
    /// Chat channel message.
    Channel,
    /// A type this SDK does not know.
    Other(u8),
}

impl ChatKind {
    fn from_wire(v: u8) -> Self {
        match v {
            chat_type::ARENA => Self::Arena,
            chat_type::PUBLIC_MACRO => Self::PublicMacro,
            chat_type::PUBLIC => Self::Public,
            chat_type::FREQ => Self::Team,
            chat_type::ENEMY_FREQ => Self::EnemyTeam,
            chat_type::PRIVATE => Self::Private,
            chat_type::WARNING => Self::Warning,
            chat_type::REMOTE_PRIVATE => Self::RemotePrivate,
            chat_type::SERVER_ERROR => Self::ServerError,
            chat_type::CHANNEL => Self::Channel,
            v => Self::Other(v),
        }
    }
}

/// A chat message received by the bot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    /// Kind.
    pub kind: ChatKind,
    /// Sender's player id, for messages from a player in the arena.
    pub from: Option<i16>,
    /// Sender's name, when known (players in the arena, and remote private
    /// messages, whose text starts with `(name)>`).
    pub sender: Option<String>,
    /// Text, without the remote-private `(name)>` prefix.
    pub text: String,
}

/// Something the bot should react to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BotEvent {
    /// The transport is up; the login has been sent.
    Connected,
    /// The server accepted the login.
    LoggedIn,
    /// The server refused the login; the bot disconnects.
    LoginFailed {
        /// Login response code.
        code: u8,
        /// Description of the code.
        reason: &'static str,
    },
    /// The bot is in the arena; [`Session::players`] lists who is there.
    EnteredArena,
    /// A player entered. `initial` is true for players already in the arena
    /// when the bot arrived (including the bot itself). The player is as it
    /// was on arrival; by the time the event is handled it may have left again.
    PlayerEntered {
        /// The player.
        player: Player,
        /// Listed as part of the bot's own arrival.
        initial: bool,
    },
    /// A player left.
    PlayerLeft {
        /// Player id.
        pid: i16,
        /// Name.
        name: String,
    },
    /// A chat message.
    Chat(ChatMessage),
    /// A player's position changed (sent often; ignore it if you don't need it).
    Position {
        /// Player id.
        pid: i16,
    },
    /// A kill.
    Kill {
        /// Killer.
        killer: i16,
        /// Victim.
        killed: i16,
        /// Victim's bounty.
        bounty: i16,
    },
    /// A player changed ship (and maybe team).
    ShipChanged {
        /// Player id.
        pid: i16,
        /// New ship.
        ship: u8,
        /// New team.
        freq: i16,
    },
    /// A player changed team.
    FreqChanged {
        /// Player id.
        pid: i16,
        /// New team.
        freq: i16,
    },
    /// Any other game packet, decoded, for bots that need more than the events
    /// above.
    Packet(Box<S2CPacket>),
    /// The connection is closed; no more events follow.
    Disconnected(DisconnectReason),
}

/// The bot's own ship state, sent to the server in position packets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MyPosition {
    /// X position in pixels.
    pub x: i16,
    /// Y position in pixels.
    pub y: i16,
    /// X velocity.
    pub x_speed: i16,
    /// Y velocity.
    pub y_speed: i16,
    /// Rotation (0-39).
    pub rotation: i8,
    /// Status bits (`oss_proto::position::status`).
    pub status: u8,
    /// Energy.
    pub energy: i16,
    /// Bounty.
    pub bounty: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Connecting,
    LoggingIn,
    Entering,
    InArena,
    Closed,
}

/// One bot connection, without I/O.
///
/// Feed it datagrams ([`Session::handle_datagram`]) and the time
/// ([`Session::tick`]); send what [`Session::poll_transmit`] returns; react to
/// [`Session::poll_event`]. [`crate::run`] does all of that over UDP.
pub struct Session {
    config: BotConfig,
    conn: Connection,
    stage: Stage,
    events: VecDeque<BotEvent>,
    pid: Option<i16>,
    players: BTreeMap<i16, Player>,
    settings_packet: Option<Vec<u8>>,
    map: Option<oss_formats::TileGrid>,
    map_wanted: Option<u32>,
    weapons_received: u32,
    me: MyPosition,
    ship: u8,
    freq: i16,
    last_position: Option<u64>,
    now: u64,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("name", &self.config.name)
            .field("stage", &self.stage)
            .field("pid", &self.pid)
            .field("players", &self.players.len())
            .finish_non_exhaustive()
    }
}

fn handshake(enc: &Encryption) -> Box<dyn Handshake> {
    let seed = {
        let mut b = [0u8; 4];
        oss_net::opensec::os_entropy()(&mut b);
        u32::from_le_bytes(b)
    };
    let vie: Box<dyn Handshake> = Box::new(VieClientHandshake::new(seed));
    match enc {
        Encryption::Vie => vie,
        Encryption::OpenSec { pinned } => Box::new(oss_net::opensec::OpenSecClientHandshake::new(
            &oss_net::opensec::os_entropy(),
            *pinned,
        )),
        Encryption::OpenSecOrVie => Box::new(Fallback::new(
            Box::new(oss_net::opensec::OpenSecClientHandshake::new(
                &oss_net::opensec::os_entropy(),
                None,
            )),
            vie,
            1_000,
        )),
    }
}

/// Position update interval while flying, and while spectating.
const POSITION_MS_SHIP: u64 = 100;
const POSITION_MS_SPEC: u64 = 1_000;

fn login_reason(code: u8) -> &'static str {
    match code {
        login_code::OK => "ok",
        login_code::NEW_USER => "unknown name",
        login_code::BAD_PASSWORD => "wrong password",
        login_code::FULL => "zone full",
        login_code::LOCKED => "locked out",
        login_code::NO_PERMISSION | login_code::NO_PERMISSION2 => "no permission",
        login_code::SPEC_ONLY => "spectator only",
        login_code::TOO_MANY_POINTS => "too many points",
        login_code::TOO_SLOW => "connection too slow",
        login_code::NO_NEW_CONNECTIONS => "not accepting new connections",
        login_code::BAD_NAME => "bad name",
        login_code::OFFENSIVE_NAME => "offensive name",
        login_code::NO_SCORES => "no scores kept",
        login_code::SERVER_BUSY => "server busy",
        login_code::TOO_LOW_USAGE => "usage too low",
        login_code::NO_NAME => "no name",
        login_code::TOO_MANY_DEMO => "too many demo users",
        login_code::NO_DEMO => "no demo users",
        login_code::CUSTOM_TEXT => "refused (see chat)",
        _ => "refused",
    }
}

impl Session {
    /// Starts connecting at time `now` (milliseconds on any monotonic clock).
    pub fn new(config: BotConfig, now: u64) -> Self {
        let conn = Connection::client(Config::client(), handshake(&config.encryption), now);
        Self::with_connection(config, conn)
    }

    /// Wraps an existing client connection (for custom handshakes or tests).
    pub fn with_connection(config: BotConfig, conn: Connection) -> Self {
        Self {
            config,
            conn,
            stage: Stage::Connecting,
            events: VecDeque::new(),
            pid: None,
            players: BTreeMap::new(),
            settings_packet: None,
            map: None,
            map_wanted: None,
            weapons_received: 0,
            me: MyPosition {
                x: 512 * 16,
                y: 512 * 16,
                ..MyPosition::default()
            },
            ship: SPECTATOR,
            freq: 0,
            last_position: None,
            now: 0,
        }
    }

    // ---- I/O plumbing -------------------------------------------------------

    /// Handles a datagram from the server.
    pub fn handle_datagram(&mut self, now: u64, data: &[u8]) {
        self.now = now;
        self.conn.handle_datagram(now, data);
        self.pump();
    }

    /// Advances timers; call every 10 ms or so.
    pub fn tick(&mut self, now: u64) {
        self.now = now;
        self.conn.tick(now);
        self.pump();
        if self.stage == Stage::InArena {
            let interval = if self.ship == SPECTATOR {
                POSITION_MS_SPEC
            } else {
                POSITION_MS_SHIP
            };
            if self
                .last_position
                .is_none_or(|t| now.saturating_sub(t) >= interval)
            {
                self.send_position_now();
            }
        }
    }

    /// The next datagram to send to the server.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.conn.poll_transmit()
    }

    /// Returns a sent datagram's buffer for reuse (optional).
    pub fn recycle(&mut self, buf: Vec<u8>) {
        self.conn.recycle(buf);
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<BotEvent> {
        self.events.pop_front()
    }

    /// When [`Session::tick`] next has work to do.
    pub fn next_timeout(&self) -> Option<u64> {
        self.conn.next_timeout()
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.stage == Stage::Closed
    }

    /// The underlying transport connection (statistics, cipher, ...).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    // ---- state ---------------------------------------------------------------

    /// The configuration.
    pub fn config(&self) -> &BotConfig {
        &self.config
    }

    /// The bot's own player id, once known.
    pub fn pid(&self) -> Option<i16> {
        self.pid
    }

    /// Whether the bot is in an arena.
    pub fn in_arena(&self) -> bool {
        self.stage == Stage::InArena
    }

    /// Players in the arena (including the bot), by id.
    pub fn players(&self) -> impl Iterator<Item = &Player> {
        self.players.values()
    }

    /// A player by id.
    pub fn player(&self, pid: i16) -> Option<&Player> {
        self.players.get(&pid)
    }

    /// A player by name (case-insensitive, as SubSpace compares names).
    pub fn player_by_name(&self, name: &str) -> Option<&Player> {
        self.players
            .values()
            .find(|p| p.name.eq_ignore_ascii_case(name))
    }

    /// The bot's position as last set.
    pub fn position(&self) -> MyPosition {
        self.me
    }

    // ---- actions --------------------------------------------------------------

    fn send(&mut self, p: impl Into<C2SPacket>, reliable: bool) {
        let bytes = p.into().to_bytes();
        self.conn.send(&bytes, reliable);
    }

    fn chat(&mut self, kind: u8, pid: i16, text: &str) {
        // Clients keep messages under 250 bytes including the header.
        let mut bytes = to_latin1(text);
        bytes.truncate(240);
        self.send(
            C2SChat(ChatBody {
                kind,
                sound: 0,
                pid,
                text: bytes,
            }),
            true,
        );
    }

    /// Sends a public message (also how `?commands` are sent).
    pub fn send_public(&mut self, text: &str) {
        self.chat(chat_type::PUBLIC, -1, text);
    }

    /// Sends a message to the bot's team.
    pub fn send_team(&mut self, text: &str) {
        self.chat(chat_type::FREQ, -1, text);
    }

    /// Sends a private message to a player in the arena.
    pub fn send_private(&mut self, pid: i16, text: &str) {
        self.chat(chat_type::PRIVATE, pid, text);
    }

    /// Sends a private message by name: in-arena if the player is here, else a
    /// remote message (`:name:text`) the server routes across arenas.
    pub fn send_private_to(&mut self, name: &str, text: &str) {
        match self.player_by_name(name).map(|p| p.pid) {
            Some(pid) => self.send_private(pid, text),
            None => self.chat(chat_type::REMOTE_PRIVATE, -1, &format!(":{name}:{text}")),
        }
    }

    /// Replies to a message: privately to its sender if there is one, else in
    /// the same channel.
    pub fn reply(&mut self, to: &ChatMessage, text: &str) {
        match (to.from, &to.sender) {
            (Some(pid), _) if to.kind != ChatKind::RemotePrivate => self.send_private(pid, text),
            (_, Some(name)) => {
                let name = name.clone();
                self.send_private_to(&name, text)
            }
            _ => self.send_public(text),
        }
    }

    /// Changes ship (0-7, 8 = spectator).
    pub fn set_ship(&mut self, ship: u8) {
        self.send(SetShip { ship }, true);
    }

    /// Changes team.
    pub fn set_freq(&mut self, freq: i16) {
        self.send(SetFreq { freq }, true);
    }

    /// Moves the bot; the new state is sent with the next position update.
    pub fn set_position(&mut self, pos: MyPosition) {
        self.me = pos;
    }

    /// Sends a position update now.
    pub fn send_position_now(&mut self) {
        let p = C2SPosition {
            rotation: self.me.rotation,
            time: self.conn.server_ticks(self.now),
            x_speed: self.me.x_speed,
            y: self.me.y,
            checksum: 0,
            status: self.me.status,
            x: self.me.x,
            y_speed: self.me.y_speed,
            bounty: self.me.bounty,
            energy: self.me.energy,
            weapon: Default::default(),
            extra: None,
        };
        // Spectator updates are reliable-insensitive; ships send unreliably.
        self.send(p, false);
        self.last_position = Some(self.now);
    }

    /// Leaves the arena and enters another (`None` = any public arena).
    pub fn go_arena(&mut self, arena: Option<&str>) {
        if self.stage == Stage::InArena || self.stage == Stage::Entering {
            self.send(c2s::LeaveArena {}, true);
        }
        self.players.clear();
        self.config.arena = arena.map(str::to_owned);
        self.enter_arena();
    }

    /// Sends any packet.
    pub fn send_packet(&mut self, packet: impl Into<C2SPacket>, reliable: bool) {
        self.send(packet, reliable);
    }

    /// Disconnects politely.
    pub fn disconnect(&mut self) {
        if self.stage == Stage::InArena {
            self.send(c2s::LeaveArena {}, true);
        }
        self.conn.disconnect();
        self.pump();
    }

    // ---- protocol -------------------------------------------------------------

    fn login(&mut self, new_user: bool) {
        let login = Login {
            flags: u8::from(new_user),
            name: FixedStr::new(&to_latin1(&self.config.name)),
            password: FixedStr::new(&to_latin1(&self.config.password)),
            machine_id: self.config.machine_id,
            ..Login::default()
        };
        self.send(login, true);
        self.stage = Stage::LoggingIn;
    }

    fn enter_arena(&mut self) {
        let (arena_type, arena) = match &self.config.arena {
            Some(name) => match name.parse::<i16>() {
                Ok(n) if n >= 0 => (n, FixedStr::default()),
                _ => (arena_type::NAMED, FixedStr::new(&to_latin1(name))),
            },
            None => (arena_type::ANY_PUBLIC, FixedStr::default()),
        };
        self.send(
            GoArena {
                ship: SPECTATOR,
                allow_audio: 1,
                obscenity_filter: 0,
                x_res: 1024,
                y_res: 768,
                arena_type,
                arena,
                optional_graphics: None,
            },
            true,
        );
        self.stage = Stage::Entering;
    }

    fn pump(&mut self) {
        while let Some(e) = self.conn.poll_event() {
            match e {
                Event::Connected => {
                    self.events.push_back(BotEvent::Connected);
                    self.login(false);
                }
                Event::Packet(p) => {
                    self.on_packet(&p);
                    self.conn.recycle(p);
                }
                Event::Disconnected(reason) => {
                    self.stage = Stage::Closed;
                    self.events.push_back(BotEvent::Disconnected(reason));
                }
                _ => {}
            }
        }
    }

    fn on_packet(&mut self, raw: &[u8]) {
        let Ok(packet) = S2CPacket::decode(raw) else {
            return;
        };
        match packet {
            S2CPacket::LoginResponse(r) => match r.code {
                login_code::OK | login_code::SPEC_ONLY | login_code::NO_SCORES => {
                    self.events.push_back(BotEvent::LoggedIn);
                    self.enter_arena();
                }
                login_code::NEW_USER if self.config.create_account => self.login(true),
                code => {
                    self.events.push_back(BotEvent::LoginFailed {
                        code,
                        reason: login_reason(code),
                    });
                    self.conn.disconnect();
                }
            },
            S2CPacket::PlayerId(p) => {
                self.pid = Some(p.pid);
                self.players.clear();
            }
            S2CPacket::Settings(_) => self.settings_packet = Some(raw.to_vec()),
            S2CPacket::PlayerEntering(e) => {
                let initial = self.stage != Stage::InArena;
                for d in e.players {
                    let player = Player {
                        pid: d.pid,
                        name: from_latin1(d.name.as_bytes()),
                        squad: from_latin1(d.squad.as_bytes()),
                        ship: d.ship as u8,
                        freq: d.freq,
                        x: 0,
                        y: 0,
                        bounty: 0,
                        wins: d.wins,
                        losses: d.losses,
                    };
                    if Some(d.pid) == self.pid {
                        self.ship = player.ship;
                        self.freq = player.freq;
                    }
                    self.players.insert(d.pid, player.clone());
                    self.events
                        .push_back(BotEvent::PlayerEntered { player, initial });
                }
            }
            S2CPacket::PlayerLeaving(l) => {
                if let Some(p) = self.players.remove(&l.pid) {
                    self.events.push_back(BotEvent::PlayerLeft {
                        pid: l.pid,
                        name: p.name,
                    });
                }
            }
            S2CPacket::EnteringArena(_) => {
                self.stage = Stage::InArena;
                self.events.push_back(BotEvent::EnteredArena);
                if self.config.ship != SPECTATOR {
                    let ship = self.config.ship;
                    self.set_ship(ship);
                }
                self.send_position_now();
            }
            S2CPacket::MapFilename(m) => {
                let checksum = match &m {
                    MapFilename::Single { checksum, .. } => Some(*checksum),
                    MapFilename::Files(f) => f.first().map(|f| f.checksum),
                };
                self.map = None;
                if self.config.download_map
                    && let Some(c) = checksum
                {
                    self.map_wanted = Some(c);
                    self.send(MapRequest { index: None }, true);
                }
            }
            S2CPacket::MapData(m) => {
                if let Some(want) = self.map_wanted.take()
                    && let Ok(lvl) =
                        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&m.data, 16 << 20)
                    && oss_proto::checksum::crc32(&lvl) == want
                    && let Ok(level) = Level::parse(&lvl)
                {
                    self.map = Some(level.server_tile_grid().0);
                }
            }
            S2CPacket::Security(s) => {
                if s.key != 0 {
                    self.answer_security(s.key);
                }
            }
            S2CPacket::Chat(c) => self.on_chat(c.0),
            S2CPacket::Kill(k) => {
                if let Some(p) = self.players.get_mut(&k.killer) {
                    p.wins = p.wins.wrapping_add(1);
                }
                if let Some(p) = self.players.get_mut(&k.killed) {
                    p.losses = p.losses.wrapping_add(1);
                }
                self.events.push_back(BotEvent::Kill {
                    killer: k.killer,
                    killed: k.killed,
                    bounty: k.bounty,
                });
            }
            S2CPacket::ShipChange(s) => {
                let ship = s.ship as u8;
                if let Some(p) = self.players.get_mut(&s.pid) {
                    p.ship = ship;
                    p.freq = s.freq;
                }
                if Some(s.pid) == self.pid {
                    self.ship = ship;
                    self.freq = s.freq;
                }
                self.events.push_back(BotEvent::ShipChanged {
                    pid: s.pid,
                    ship,
                    freq: s.freq,
                });
            }
            S2CPacket::FreqChange(f) => {
                if let Some(p) = self.players.get_mut(&f.pid) {
                    p.freq = f.freq;
                }
                if Some(f.pid) == self.pid {
                    self.freq = f.freq;
                }
                self.events.push_back(BotEvent::FreqChanged {
                    pid: f.pid,
                    freq: f.freq,
                });
            }
            S2CPacket::Position(p) => {
                // The short form carries only the low byte of the player id.
                if let Some(pl) = self
                    .players
                    .values_mut()
                    .find(|pl| pl.pid as u8 == p.player_id)
                {
                    pl.x = p.x;
                    pl.y = p.y;
                    pl.bounty = u16::from(p.bounty);
                    let pid = pl.pid;
                    self.events.push_back(BotEvent::Position { pid });
                }
            }
            S2CPacket::Weapon(w) => {
                self.weapons_received = self.weapons_received.wrapping_add(1);
                let pid = w.player_id as i16;
                if let Some(pl) = self.players.get_mut(&pid) {
                    pl.x = w.x;
                    pl.y = w.y;
                    pl.bounty = w.bounty;
                    self.events.push_back(BotEvent::Position { pid });
                }
            }
            other => self.events.push_back(BotEvent::Packet(Box::new(other))),
        }
    }

    fn on_chat(&mut self, body: ChatBody) {
        let kind = ChatKind::from_wire(body.kind);
        let mut text = from_latin1(&body.text);
        let from = (body.pid >= 0 && kind != ChatKind::RemotePrivate).then_some(body.pid);
        let mut sender = from.and_then(|pid| self.players.get(&pid).map(|p| p.name.clone()));
        if kind == ChatKind::RemotePrivate
            && let Some(rest) = text.strip_prefix('(')
            && let Some((name, msg)) = rest.split_once(")>")
        {
            sender = Some(name.to_owned());
            text = msg.trim_start().to_owned();
        }
        self.events.push_back(BotEvent::Chat(ChatMessage {
            kind,
            from,
            sender,
            text,
        }));
    }

    fn answer_security(&mut self, key: u32) {
        let settings = self
            .settings_packet
            .as_deref()
            .map_or(0, |s| settings_checksum(key, s));
        let map = self
            .map
            .as_ref()
            .map_or(0, |g| map_checksum(key, |x, y| g.get(x as u32, y as u32)));
        let stats = self.conn.stats();
        self.send(
            SecurityResponse {
                weapon_count: self.weapons_received,
                settings_checksum: settings,
                exe_checksum: vie_exe_checksum(key),
                map_checksum: map,
                s2c_slow_total: 0,
                s2c_fast_total: stats.datagrams_received as u32,
                s2c_slow_current: 0,
                s2c_fast_current: 0,
                s2c_reliable_out: 0,
                ping_last: 0,
                ping_average: 0,
                ping_low: 0,
                ping_high: 0,
                slow_frame: 0,
                continuum: None,
            },
            true,
        );
    }
}
