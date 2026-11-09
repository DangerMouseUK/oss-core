//! Billing server ("biller") protocol between a zone server and a central
//! billing server: logins, scores, cross-zone chat and administration.
//!
//! It runs over the normal transport (the zone connects like a client).
//! [`ServerToBiller`] covers zone-to-biller packets and [`BillerToServer`] the
//! replies and pushes. Text fields are NUL-terminated and run to the end of the
//! packet; servers cap them at about 250 bytes.

use alloc::vec::Vec;

use crate::DecodeError;
use crate::wire::{FixedStr, Raw, Reader, Wire, Writer};

/// A player's score as exchanged with the biller (14 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlayerScore {
    /// Kills.
    pub kills: u16,
    /// Deaths.
    pub deaths: u16,
    /// Flags (goals).
    pub flags: u16,
    /// Kill points.
    pub points: u32,
    /// Flag points.
    pub flag_points: u32,
}

impl Wire for PlayerScore {
    const SIZE: usize = 14;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            kills: r.u16()?,
            deaths: r.u16()?,
            flags: r.u16()?,
            points: r.u32()?,
            flag_points: r.u32()?,
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.put_u16(self.kills);
        out.put_u16(self.deaths);
        out.put_u16(self.flags);
        out.put_u32(self.points);
        out.put_u32(self.flag_points);
    }
}

/// Login result codes in [`BillerLogin::result`].
pub mod login_result {
    /// Accepted.
    pub const OK: u8 = 0;
    /// Unknown name; may be created.
    pub const NEW_USER: u8 = 1;
    /// Wrong password.
    pub const INVALID_PASSWORD: u8 = 2;
    /// Banned.
    pub const BANNED: u8 = 3;
    /// Not accepting new connections.
    pub const NO_NEW_CONNECTIONS: u8 = 4;
    /// Bad name.
    pub const BAD_NAME: u8 = 5;
    /// Demo version.
    pub const DEMO: u8 = 6;
    /// Busy.
    pub const BUSY: u8 = 7;
    /// Wants demographics (registration form).
    pub const ASK_DEMOGRAPHICS: u8 = 8;
}

/// Zone-to-biller user login (type `0x04`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserLogin {
    /// 1 to create the account.
    pub make_new: u8,
    /// Player's IPv4 address bytes.
    pub ip: [u8; 4],
    /// Name.
    pub name: FixedStr<32>,
    /// Password.
    pub password: FixedStr<32>,
    /// The zone's id for this connection.
    pub connection_id: u32,
    /// Machine id from the client's login.
    pub machine_id: u32,
    /// Timezone bias (minutes).
    pub timezone: i16,
    /// Upper half of the timezone word (0, or sign bits when sent as `i32`).
    pub timezone_high: u16,
    /// Unknown byte (possibly ban related).
    pub unknown: u8,
    /// 1 if the player is a sysop.
    pub sysop: u8,
    /// Client version.
    pub client_version: u16,
    /// Client-specific data to the end of the packet (the Continuum id: 64
    /// bytes; empty for SubSpace clients).
    pub extra: Vec<u8>,
}

/// Biller-to-zone login response (type `0x01`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BillerLogin {
    /// [`login_result`] code.
    pub result: u8,
    /// Connection id from the request.
    pub connection_id: u32,
    /// Name (as stored by the biller).
    pub name: FixedStr<24>,
    /// Squad.
    pub squad: FixedStr<24>,
    /// Banner.
    pub banner: Raw<96>,
    /// Total seconds played.
    pub seconds_played: u32,
    /// Account creation: year, month, day, hour, minute, second.
    pub first_login: [u16; 6],
    /// Unused.
    pub unused0: u32,
    /// Biller's user id.
    pub user_id: u32,
    /// Unused.
    pub unused1: u32,
    /// Stored score; present when the login succeeded.
    pub score: Option<PlayerScore>,
}

/// The `kind` byte that turns S2B `0x06` and B2S `0x03` into a permit entry: a
/// player name with no sound byte in front of it. Every other value is a message
/// (`0x02` in practice) with a sound byte, then the text.
pub const PERMIT_KIND: u8 = 0x01;

/// B2S `0x33` split into its parts. The packet is a 128-byte SSC id, then a `u32`
/// identity value the biller rotates (SSC billers use it to key Continuum
/// password hashes, so a zone hands it on to its Continuum clients). Billers also
/// send short forms, often as a keepalive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingIdentity {
    /// The SSC id, when the payload holds at least 128 bytes.
    pub id: Option<[u8; Self::ID_LEN]>,
    /// The rotating identity value, when 4 more bytes follow the id.
    pub value: Option<u32>,
}

impl BillingIdentity {
    /// Size of the SSC id.
    pub const ID_LEN: usize = 128;

    /// Splits a `0x33` payload (the bytes after the type byte, as held by
    /// [`BillerToServer::Identity`]). Bytes past the value are ignored.
    pub fn parse(payload: &[u8]) -> Self {
        let id = payload
            .get(..Self::ID_LEN)
            .map(|b| <[u8; Self::ID_LEN]>::try_from(b).expect("128 bytes"));
        let value = payload
            .get(Self::ID_LEN..Self::ID_LEN + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        Self { id, value }
    }
}

/// Packets from the zone to the biller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServerToBiller {
    /// `0x01`: keep-alive.
    Ping,
    /// `0x02`: the zone identifies itself.
    ServerConnect {
        /// Server id.
        server_id: u32,
        /// Group id.
        group_id: u32,
        /// Score id (zones sharing it share scores).
        score_id: u32,
        /// Server name.
        name: FixedStr<126>,
        /// Game port.
        port: u16,
        /// Biller password.
        password: FixedStr<32>,
    },
    /// `0x03`: the zone is going away.
    ServerDisconnect,
    /// `0x04`: a player logs in.
    UserLogin(UserLogin),
    /// `0x05`: a player left; final statistics.
    UserLogoff {
        /// Connection id.
        connection_id: u32,
        /// Disconnect reason.
        reason: u16,
        /// Latency.
        latency: u16,
        /// Ping.
        ping: u16,
        /// Server-to-client packet loss.
        loss_s2c: u16,
        /// Client-to-server packet loss.
        loss_c2s: u16,
        /// Final score; `None` when the zone has no saved score (the packet then
        /// ends after the loss counters, 15 bytes).
        score: Option<PlayerScore>,
    },
    /// `0x06`: a message for another zone. A `kind` of
    /// [`PERMIT_KIND`] is decoded as [`ServerToBiller::RemotePermit`] instead.
    RemoteZoneMessage {
        /// Sender.
        connection_id: u32,
        /// Destination server id.
        server_id: u32,
        /// Message type.
        kind: u8,
        /// Sound.
        sound: u8,
        /// Text.
        text: Vec<u8>,
    },
    /// `0x06` with kind [`PERMIT_KIND`]: asks the biller to tell the zone whose
    /// server id is `server_id` to add `name` to its permit list. This layout has
    /// no sound byte.
    RemotePermit {
        /// Sender (not interpreted by billers).
        connection_id: u32,
        /// Server id of the zone that should receive the permit.
        server_id: u32,
        /// Player name.
        name: Vec<u8>,
    },
    /// `0x07`: a remote private message (`:name:(from)>text` or `:#squad:...`).
    UserRemotePrivate {
        /// Sender (often `0xFFFFFFFF`; the name is in the text).
        connection_id: u32,
        /// Group id.
        group_id: u32,
        /// Message type.
        kind: u8,
        /// Sound.
        sound: u8,
        /// Text.
        text: Vec<u8>,
    },
    /// `0x08`: ask the biller for a file.
    RequestFile {
        /// File name.
        name: Vec<u8>,
    },
    /// `0x0D`: registration form data.
    UserDemographics {
        /// Connection id.
        connection_id: u32,
        /// The form (C2S `0x17` without its type byte, up to 765 bytes).
        data: Vec<u8>,
    },
    /// `0x0E`: a private message between players (already delivered unless it
    /// starts with `*`; destination `0xFFFFFFFF` for a `*` command at nobody).
    UserPrivateChat {
        /// Sender.
        source: u32,
        /// Recipient.
        destination: u32,
        /// Text.
        text: Vec<u8>,
    },
    /// `0x0F`: log a security violation.
    SecurityViolation {
        /// Connection id.
        connection_id: u32,
        /// Description.
        text: Vec<u8>,
    },
    /// `0x10`: a player's banner changed.
    UserBanner {
        /// Connection id.
        connection_id: u32,
        /// Banner.
        banner: Raw<96>,
    },
    /// `0x11`: a player's score.
    UserScore {
        /// Connection id.
        connection_id: u32,
        /// Score.
        score: PlayerScore,
    },
    /// `0x12`: a message to every zone with this score id.
    UserScoreMessage {
        /// Sender.
        connection_id: u32,
        /// Score id.
        score_id: u32,
        /// Message type.
        kind: u8,
        /// Sound.
        sound: u8,
        /// Text.
        text: Vec<u8>,
    },
    /// `0x13`: a `?command` for the biller.
    UserCommand {
        /// Sender.
        connection_id: u32,
        /// Command text.
        text: Vec<u8>,
    },
    /// `0x14`: a chat channel message.
    UserChannelChat {
        /// Sender.
        connection_id: u32,
        /// Channel (name or number as text).
        channel: FixedStr<32>,
        /// Text.
        text: Vec<u8>,
    },
    /// `0x15`: what this zone supports (bit 0: multicast channel chat).
    ServerCapabilities {
        /// Capability bits.
        flags: u32,
    },
    /// Any other type, kept raw.
    Unknown {
        /// Type byte.
        kind: u8,
        /// The whole packet.
        data: Vec<u8>,
    },
}

/// Packets from the biller to the zone.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BillerToServer {
    /// `0x01`: login response.
    UserLogin(BillerLogin),
    /// `0x02`: shut the zone down.
    Shutdown,
    /// `0x03`: a zone-wide message, or a remote private message if the text has
    /// the form `:target:(from)>message`. A `kind` of [`PERMIT_KIND`] is decoded
    /// as [`BillerToServer::Permit`] instead.
    ZoneMessage {
        /// Originating server id.
        source_server: u32,
        /// Message type.
        kind: u8,
        /// Sound.
        sound: u8,
        /// Text.
        text: Vec<u8>,
    },
    /// `0x03` with kind [`PERMIT_KIND`]: add `name` to this zone's permit list
    /// (conventionally `permit.txt`). This layout has no sound byte. The biller
    /// sends it on behalf of another zone's [`ServerToBiller::RemotePermit`].
    Permit {
        /// Originating id, copied from the request's connection id.
        source_server: u32,
        /// Player name.
        name: Vec<u8>,
    },
    /// `0x04`: recycle (restart) the zone.
    Recycle,
    /// `0x05`: a file for the zone.
    FileTransfer {
        /// File name.
        name: FixedStr<16>,
        /// Contents.
        data: Vec<u8>,
    },
    /// `0x08`: kick a player.
    Kick {
        /// Connection id.
        connection_id: u32,
        /// Reason code.
        reason: u16,
    },
    /// `0x09`: a green arena message for one player.
    ArenaMessage {
        /// Connection id.
        connection_id: u32,
        /// Text.
        text: Vec<u8>,
    },
    /// `0x0A`: a chat channel message for one player.
    ChannelMessage {
        /// Connection id.
        connection_id: u32,
        /// Channel number.
        channel: u8,
        /// Text.
        text: Vec<u8>,
    },
    /// `0x31`: reset scores.
    ScoreReset {
        /// Score id.
        score_id: u32,
        /// Negated score id (a consistency check).
        score_id_neg: u32,
    },
    /// `0x32`: a raw game packet to forward to a player.
    UserPacket {
        /// Connection id.
        connection_id: u32,
        /// Packet.
        data: Vec<u8>,
    },
    /// `0x33`: the biller's identity data, kept raw. [`BillingIdentity::parse`]
    /// splits it into the SSC id and the rotating identity value.
    Identity(Vec<u8>),
    /// `0x34`: one channel message for several players.
    MultiChannelChat {
        /// (connection id, channel number) per recipient.
        recipients: Vec<(u32, u8)>,
        /// Text.
        text: Vec<u8>,
    },
    /// Any other type, kept raw.
    Unknown {
        /// Type byte.
        kind: u8,
        /// The whole packet.
        data: Vec<u8>,
    },
}

fn first(data: &[u8]) -> Result<(u8, Reader<'_>), DecodeError> {
    let kind = *data.first().ok_or(DecodeError::Empty)?;
    let mut r = Reader::new(data, kind);
    r.u8()?;
    Ok((kind, r))
}

impl ServerToBiller {
    /// Decodes a zone-to-biller packet.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let (kind, mut r) = first(data)?;
        Ok(match kind {
            0x01 => Self::Ping,
            0x02 => Self::ServerConnect {
                server_id: r.u32()?,
                group_id: r.u32()?,
                score_id: r.u32()?,
                name: r.fixed()?,
                port: r.u16()?,
                password: r.fixed()?,
            },
            0x03 => Self::ServerDisconnect,
            0x04 => Self::UserLogin(UserLogin {
                make_new: r.u8()?,
                ip: r.array()?,
                name: r.fixed()?,
                password: r.fixed()?,
                connection_id: r.u32()?,
                machine_id: r.u32()?,
                timezone: r.i16()?,
                timezone_high: r.u16()?,
                unknown: r.u8()?,
                sysop: r.u8()?,
                client_version: r.u16()?,
                extra: r.rest().to_vec(),
            }),
            0x05 => Self::UserLogoff {
                connection_id: r.u32()?,
                reason: r.u16()?,
                latency: r.u16()?,
                ping: r.u16()?,
                loss_s2c: r.u16()?,
                loss_c2s: r.u16()?,
                // The reference server omits the score when it has none saved.
                score: if r.remaining() == 0 {
                    None
                } else {
                    Some(PlayerScore::read(&mut r)?)
                },
            },
            0x06 => {
                let connection_id = r.u32()?;
                let server_id = r.u32()?;
                let kind = r.u8()?;
                if kind == PERMIT_KIND {
                    Self::RemotePermit {
                        connection_id,
                        server_id,
                        name: r.cstr(),
                    }
                } else {
                    Self::RemoteZoneMessage {
                        connection_id,
                        server_id,
                        kind,
                        sound: r.u8()?,
                        text: r.cstr(),
                    }
                }
            }
            0x07 => Self::UserRemotePrivate {
                connection_id: r.u32()?,
                group_id: r.u32()?,
                kind: r.u8()?,
                sound: r.u8()?,
                text: r.cstr(),
            },
            0x08 => Self::RequestFile { name: r.cstr() },
            0x0D => Self::UserDemographics {
                connection_id: r.u32()?,
                data: r.rest().to_vec(),
            },
            0x0E => Self::UserPrivateChat {
                source: r.u32()?,
                destination: r.u32()?,
                text: r.cstr(),
            },
            0x0F => Self::SecurityViolation {
                connection_id: r.u32()?,
                text: r.cstr(),
            },
            0x10 => Self::UserBanner {
                connection_id: r.u32()?,
                banner: Raw::read(&mut r)?,
            },
            0x11 => Self::UserScore {
                connection_id: r.u32()?,
                score: PlayerScore::read(&mut r)?,
            },
            0x12 => Self::UserScoreMessage {
                connection_id: r.u32()?,
                score_id: r.u32()?,
                kind: r.u8()?,
                sound: r.u8()?,
                text: r.cstr(),
            },
            0x13 => Self::UserCommand {
                connection_id: r.u32()?,
                text: r.cstr(),
            },
            0x14 => Self::UserChannelChat {
                connection_id: r.u32()?,
                channel: r.fixed()?,
                text: r.cstr(),
            },
            0x15 => Self::ServerCapabilities { flags: r.u32()? },
            _ => Self::Unknown {
                kind,
                data: data.to_vec(),
            },
        })
    }

    /// Appends the encoded packet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Ping => out.put_u8(0x01),
            Self::ServerConnect {
                server_id,
                group_id,
                score_id,
                name,
                port,
                password,
            } => {
                out.put_u8(0x02);
                out.put_u32(*server_id);
                out.put_u32(*group_id);
                out.put_u32(*score_id);
                name.write(out);
                out.put_u16(*port);
                password.write(out);
            }
            Self::ServerDisconnect => out.put_u8(0x03),
            Self::UserLogin(l) => {
                out.put_u8(0x04);
                out.put_u8(l.make_new);
                out.put_bytes(&l.ip);
                l.name.write(out);
                l.password.write(out);
                out.put_u32(l.connection_id);
                out.put_u32(l.machine_id);
                out.put_i16(l.timezone);
                out.put_u16(l.timezone_high);
                out.put_u8(l.unknown);
                out.put_u8(l.sysop);
                out.put_u16(l.client_version);
                out.put_bytes(&l.extra);
            }
            Self::UserLogoff {
                connection_id,
                reason,
                latency,
                ping,
                loss_s2c,
                loss_c2s,
                score,
            } => {
                out.put_u8(0x05);
                out.put_u32(*connection_id);
                for v in [*reason, *latency, *ping, *loss_s2c, *loss_c2s] {
                    out.put_u16(v);
                }
                if let Some(score) = score {
                    score.write(out);
                }
            }
            Self::RemoteZoneMessage {
                connection_id,
                server_id,
                kind,
                sound,
                text,
            } => {
                out.put_u8(0x06);
                out.put_u32(*connection_id);
                out.put_u32(*server_id);
                out.put_u8(*kind);
                out.put_u8(*sound);
                out.put_cstr(text);
            }
            Self::RemotePermit {
                connection_id,
                server_id,
                name,
            } => {
                out.put_u8(0x06);
                out.put_u32(*connection_id);
                out.put_u32(*server_id);
                out.put_u8(PERMIT_KIND);
                out.put_cstr(name);
            }
            Self::UserRemotePrivate {
                connection_id,
                group_id,
                kind,
                sound,
                text,
            } => {
                out.put_u8(0x07);
                out.put_u32(*connection_id);
                out.put_u32(*group_id);
                out.put_u8(*kind);
                out.put_u8(*sound);
                out.put_cstr(text);
            }
            Self::RequestFile { name } => {
                out.put_u8(0x08);
                out.put_cstr(name);
            }
            Self::UserDemographics {
                connection_id,
                data,
            } => {
                out.put_u8(0x0D);
                out.put_u32(*connection_id);
                out.put_bytes(data);
            }
            Self::UserPrivateChat {
                source,
                destination,
                text,
            } => {
                out.put_u8(0x0E);
                out.put_u32(*source);
                out.put_u32(*destination);
                out.put_cstr(text);
            }
            Self::SecurityViolation {
                connection_id,
                text,
            } => {
                out.put_u8(0x0F);
                out.put_u32(*connection_id);
                out.put_cstr(text);
            }
            Self::UserBanner {
                connection_id,
                banner,
            } => {
                out.put_u8(0x10);
                out.put_u32(*connection_id);
                banner.write(out);
            }
            Self::UserScore {
                connection_id,
                score,
            } => {
                out.put_u8(0x11);
                out.put_u32(*connection_id);
                score.write(out);
            }
            Self::UserScoreMessage {
                connection_id,
                score_id,
                kind,
                sound,
                text,
            } => {
                out.put_u8(0x12);
                out.put_u32(*connection_id);
                out.put_u32(*score_id);
                out.put_u8(*kind);
                out.put_u8(*sound);
                out.put_cstr(text);
            }
            Self::UserCommand {
                connection_id,
                text,
            } => {
                out.put_u8(0x13);
                out.put_u32(*connection_id);
                out.put_cstr(text);
            }
            Self::UserChannelChat {
                connection_id,
                channel,
                text,
            } => {
                out.put_u8(0x14);
                out.put_u32(*connection_id);
                channel.write(out);
                out.put_cstr(text);
            }
            Self::ServerCapabilities { flags } => {
                out.put_u8(0x15);
                out.put_u32(*flags);
            }
            Self::Unknown { data, .. } => out.put_bytes(data),
        }
    }

    /// The encoded packet.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode(&mut v);
        v
    }
}

impl BillerToServer {
    /// Decodes a biller-to-zone packet.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let (kind, mut r) = first(data)?;
        Ok(match kind {
            0x01 => {
                let mut l = BillerLogin {
                    result: r.u8()?,
                    connection_id: r.u32()?,
                    name: r.fixed()?,
                    squad: r.fixed()?,
                    banner: Raw::read(&mut r)?,
                    seconds_played: r.u32()?,
                    ..Default::default()
                };
                for v in &mut l.first_login {
                    *v = r.u16()?;
                }
                l.unused0 = r.u32()?;
                l.user_id = r.u32()?;
                l.unused1 = r.u32()?;
                if r.remaining() >= PlayerScore::SIZE {
                    l.score = Some(PlayerScore::read(&mut r)?);
                }
                Self::UserLogin(l)
            }
            0x02 => Self::Shutdown,
            0x03 => {
                let source_server = r.u32()?;
                let kind = r.u8()?;
                if kind == PERMIT_KIND {
                    Self::Permit {
                        source_server,
                        name: r.cstr(),
                    }
                } else {
                    Self::ZoneMessage {
                        source_server,
                        kind,
                        sound: r.u8()?,
                        text: r.cstr(),
                    }
                }
            }
            0x04 => Self::Recycle,
            0x05 => Self::FileTransfer {
                name: r.fixed()?,
                data: r.rest().to_vec(),
            },
            0x08 => Self::Kick {
                connection_id: r.u32()?,
                reason: r.u16()?,
            },
            0x09 => Self::ArenaMessage {
                connection_id: r.u32()?,
                text: r.cstr(),
            },
            0x0A => Self::ChannelMessage {
                connection_id: r.u32()?,
                channel: r.u8()?,
                text: r.cstr(),
            },
            0x31 => Self::ScoreReset {
                score_id: r.u32()?,
                score_id_neg: r.u32()?,
            },
            0x32 => Self::UserPacket {
                connection_id: r.u32()?,
                data: r.rest().to_vec(),
            },
            0x33 => Self::Identity(r.rest().to_vec()),
            0x34 => {
                let count = r.u8()?;
                let mut recipients = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    recipients.push((r.u32()?, r.u8()?));
                }
                Self::MultiChannelChat {
                    recipients,
                    text: r.cstr(),
                }
            }
            _ => Self::Unknown {
                kind,
                data: data.to_vec(),
            },
        })
    }

    /// Appends the encoded packet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::UserLogin(l) => {
                out.put_u8(0x01);
                out.put_u8(l.result);
                out.put_u32(l.connection_id);
                l.name.write(out);
                l.squad.write(out);
                l.banner.write(out);
                out.put_u32(l.seconds_played);
                l.first_login.iter().for_each(|&v| out.put_u16(v));
                out.put_u32(l.unused0);
                out.put_u32(l.user_id);
                out.put_u32(l.unused1);
                if let Some(s) = &l.score {
                    s.write(out);
                }
            }
            Self::Shutdown => out.put_u8(0x02),
            Self::ZoneMessage {
                source_server,
                kind,
                sound,
                text,
            } => {
                out.put_u8(0x03);
                out.put_u32(*source_server);
                out.put_u8(*kind);
                out.put_u8(*sound);
                out.put_cstr(text);
            }
            Self::Permit {
                source_server,
                name,
            } => {
                out.put_u8(0x03);
                out.put_u32(*source_server);
                out.put_u8(PERMIT_KIND);
                out.put_cstr(name);
            }
            Self::Recycle => out.put_u8(0x04),
            Self::FileTransfer { name, data } => {
                out.put_u8(0x05);
                name.write(out);
                out.put_bytes(data);
            }
            Self::Kick {
                connection_id,
                reason,
            } => {
                out.put_u8(0x08);
                out.put_u32(*connection_id);
                out.put_u16(*reason);
            }
            Self::ArenaMessage {
                connection_id,
                text,
            } => {
                out.put_u8(0x09);
                out.put_u32(*connection_id);
                out.put_cstr(text);
            }
            Self::ChannelMessage {
                connection_id,
                channel,
                text,
            } => {
                out.put_u8(0x0A);
                out.put_u32(*connection_id);
                out.put_u8(*channel);
                out.put_cstr(text);
            }
            Self::ScoreReset {
                score_id,
                score_id_neg,
            } => {
                out.put_u8(0x31);
                out.put_u32(*score_id);
                out.put_u32(*score_id_neg);
            }
            Self::UserPacket {
                connection_id,
                data,
            } => {
                out.put_u8(0x32);
                out.put_u32(*connection_id);
                out.put_bytes(data);
            }
            Self::Identity(d) => {
                out.put_u8(0x33);
                out.put_bytes(d);
            }
            Self::MultiChannelChat { recipients, text } => {
                out.put_u8(0x34);
                out.put_u8(recipients.len().min(255) as u8);
                for (c, ch) in recipients.iter().take(255) {
                    out.put_u32(*c);
                    out.put_u8(*ch);
                }
                out.put_cstr(text);
            }
            Self::Unknown { data, .. } => out.put_bytes(data),
        }
    }

    /// The encoded packet.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode(&mut v);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn text() -> Vec<u8> {
        b"hello there".to_vec()
    }

    #[test]
    fn server_to_biller_round_trips() {
        let score = PlayerScore {
            kills: 1,
            deaths: 2,
            flags: 3,
            points: 4,
            flag_points: 5,
        };
        let cases = vec![
            ServerToBiller::Ping,
            ServerToBiller::ServerConnect {
                server_id: 1,
                group_id: 2,
                score_id: 3,
                name: "Zone".into(),
                port: 5000,
                password: "pw".into(),
            },
            ServerToBiller::ServerDisconnect,
            ServerToBiller::UserLogin(UserLogin {
                make_new: 1,
                ip: [1, 2, 3, 4],
                name: "Pilot".into(),
                password: "x".into(),
                connection_id: 9,
                machine_id: 10,
                timezone: -300,
                timezone_high: 0xFFFF,
                unknown: 0,
                sysop: 1,
                client_version: 40,
                extra: vec![7; 64],
            }),
            ServerToBiller::UserLogoff {
                connection_id: 1,
                reason: 2,
                latency: 3,
                ping: 4,
                loss_s2c: 5,
                loss_c2s: 6,
                score: Some(score),
            },
            ServerToBiller::UserLogoff {
                connection_id: 1,
                reason: 2,
                latency: 3,
                ping: 4,
                loss_s2c: 5,
                loss_c2s: 6,
                score: None,
            },
            ServerToBiller::RemoteZoneMessage {
                connection_id: 1,
                server_id: 2,
                kind: 3,
                sound: 4,
                text: text(),
            },
            ServerToBiller::RemotePermit {
                connection_id: u32::MAX,
                server_id: 7,
                name: b"Pilot".to_vec(),
            },
            ServerToBiller::UserRemotePrivate {
                connection_id: u32::MAX,
                group_id: 1,
                kind: 2,
                sound: 0,
                text: b":x:(y)>hi".to_vec(),
            },
            ServerToBiller::RequestFile {
                name: b"news.txt".to_vec(),
            },
            ServerToBiller::UserDemographics {
                connection_id: 1,
                data: vec![1; 765],
            },
            ServerToBiller::UserPrivateChat {
                source: 1,
                destination: 2,
                text: text(),
            },
            ServerToBiller::SecurityViolation {
                connection_id: 1,
                text: text(),
            },
            ServerToBiller::UserBanner {
                connection_id: 1,
                banner: Raw([5; 96]),
            },
            ServerToBiller::UserScore {
                connection_id: 1,
                score,
            },
            ServerToBiller::UserScoreMessage {
                connection_id: 1,
                score_id: 2,
                kind: 3,
                sound: 0,
                text: text(),
            },
            ServerToBiller::UserCommand {
                connection_id: 1,
                text: b"?find x".to_vec(),
            },
            ServerToBiller::UserChannelChat {
                connection_id: 1,
                channel: "1".into(),
                text: text(),
            },
            ServerToBiller::ServerCapabilities { flags: 1 },
            ServerToBiller::Unknown {
                kind: 0x09,
                data: vec![0x09, 1],
            },
        ];
        for c in cases {
            let b = c.to_bytes();
            assert_eq!(ServerToBiller::decode(&b).unwrap(), c, "{b:02x?}");
        }
    }

    #[test]
    fn biller_to_server_round_trips() {
        let login = BillerLogin {
            result: login_result::OK,
            connection_id: 9,
            name: "Pilot".into(),
            squad: "Sq".into(),
            banner: Raw([3; 96]),
            seconds_played: 3600,
            first_login: [2001, 2, 3, 4, 5, 6],
            user_id: 77,
            score: Some(PlayerScore {
                kills: 9,
                ..Default::default()
            }),
            ..Default::default()
        };
        let cases = vec![
            BillerToServer::UserLogin(login.clone()),
            BillerToServer::UserLogin(BillerLogin {
                score: None,
                result: 2,
                ..login
            }),
            BillerToServer::Shutdown,
            BillerToServer::ZoneMessage {
                source_server: 1,
                kind: 2,
                sound: 2,
                text: text(),
            },
            BillerToServer::Permit {
                source_server: u32::MAX,
                name: b"Pilot".to_vec(),
            },
            BillerToServer::Recycle,
            BillerToServer::FileTransfer {
                name: "news.txt".into(),
                data: vec![1, 2],
            },
            BillerToServer::Kick {
                connection_id: 1,
                reason: 2,
            },
            BillerToServer::ArenaMessage {
                connection_id: 1,
                text: text(),
            },
            BillerToServer::ChannelMessage {
                connection_id: 1,
                channel: 3,
                text: text(),
            },
            BillerToServer::ScoreReset {
                score_id: 5,
                score_id_neg: 5u32.wrapping_neg(),
            },
            BillerToServer::UserPacket {
                connection_id: 1,
                data: vec![0x07, 1],
            },
            BillerToServer::Identity(vec![9; 128]),
            BillerToServer::MultiChannelChat {
                recipients: vec![(1, 2), (3, 4)],
                text: text(),
            },
            BillerToServer::Unknown {
                kind: 0x40,
                data: vec![0x40],
            },
        ];
        for c in cases {
            let b = c.to_bytes();
            assert_eq!(BillerToServer::decode(&b).unwrap(), c, "{b:02x?}");
        }
    }

    /// A permit entry has no sound byte: the name starts straight after the kind,
    /// so reading it with the message layout would eat its first letter.
    #[test]
    fn permit_entries_have_no_sound_byte() {
        let b = [
            0x03,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            PERMIT_KIND,
            b'B',
            b'o',
            b'b',
            0,
        ];
        assert_eq!(
            BillerToServer::decode(&b).unwrap(),
            BillerToServer::Permit {
                source_server: u32::MAX,
                name: b"Bob".to_vec(),
            }
        );
        let b = [0x03, 1, 0, 0, 0, 0x02, 5, b'h', b'i', 0];
        assert_eq!(
            BillerToServer::decode(&b).unwrap(),
            BillerToServer::ZoneMessage {
                source_server: 1,
                kind: 2,
                sound: 5,
                text: b"hi".to_vec(),
            }
        );
        let b = ServerToBiller::RemotePermit {
            connection_id: u32::MAX,
            server_id: 4,
            name: b"Bob".to_vec(),
        }
        .to_bytes();
        assert_eq!(
            b,
            [
                0x06, 0xFF, 0xFF, 0xFF, 0xFF, 4, 0, 0, 0, 1, b'B', b'o', b'b', 0
            ]
        );
    }

    #[test]
    fn billing_identity_forms() {
        let none = BillingIdentity::parse(&[]);
        assert_eq!((none.id, none.value), (None, None));
        let short = BillingIdentity::parse(&[1; 100]);
        assert_eq!((short.id, short.value), (None, None));
        let id_only = BillingIdentity::parse(&[7; 130]);
        assert_eq!((id_only.id, id_only.value), (Some([7; 128]), None));
        let mut full = vec![7; 128];
        full.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        full.extend_from_slice(&[0xEE; 8]);
        let full = BillingIdentity::parse(&full);
        assert_eq!((full.id, full.value), (Some([7; 128]), Some(0x1234_5678)));
    }

    #[test]
    fn layouts() {
        let b = BillerToServer::UserLogin(BillerLogin::default()).to_bytes();
        assert_eq!(b.len(), 178);
        let b = BillerToServer::UserLogin(BillerLogin {
            score: Some(PlayerScore::default()),
            ..Default::default()
        })
        .to_bytes();
        assert_eq!(b.len(), 192);
        let b = ServerToBiller::UserLogin(UserLogin::default()).to_bytes();
        assert_eq!(b.len(), 1 + 1 + 4 + 32 + 32 + 4 + 4 + 2 + 2 + 1 + 1 + 2);
        let b = ServerToBiller::ServerConnect {
            server_id: 0,
            group_id: 0,
            score_id: 0,
            name: FixedStr::default(),
            port: 0,
            password: FixedStr::default(),
        }
        .to_bytes();
        assert_eq!(b.len(), 173);
        assert!(BillerToServer::decode(&[0x34, 5, 1, 0]).is_err());
        assert!(ServerToBiller::decode(&[]).is_err());
    }
}
