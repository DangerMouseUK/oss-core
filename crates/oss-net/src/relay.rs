//! Framing for the WebSocket relay (`oss-relay.1`), which lets browser clients
//! reach a zone. Browsers cannot send UDP, so they send each SubSpace datagram
//! as one WebSocket binary message to a relay, which forwards it over UDP (or
//! straight into the server's [`crate::Server`]) unchanged.
//!
//! This module is only the codec: [`Frame`] for message-based carriers
//! (WebSocket: one frame per binary message) and [`StreamDecoder`] /
//! [`write_stream_frame`] for byte streams (raw TCP, WebTransport streams), where
//! each frame gets a `u16` length prefix. The protocol is specified in
//! `docs/protocol/websocket-relay.md`.
//!
//! ```
//! use oss_net::relay::{Frame, StreamDecoder, write_stream_frame};
//!
//! // Browser → relay over WebSocket: one frame per message.
//! let mut msg = Vec::new();
//! Frame::Hello { version: 1, zone: "" }.encode(&mut msg).unwrap();
//! assert_eq!(Frame::decode(&msg), Ok(Frame::Hello { version: 1, zone: "" }));
//!
//! // Over a byte stream, frames are length-prefixed.
//! let mut stream = Vec::new();
//! write_stream_frame(&Frame::Datagram(&[0x00, 0x01, 1, 2, 3, 4, 1, 0]), &mut stream).unwrap();
//! let mut dec = StreamDecoder::new();
//! dec.push(&stream[..3]);
//! assert!(dec.next_frame().is_none()); // incomplete
//! dec.push(&stream[3..]);
//! assert!(matches!(dec.next_frame(), Some(Ok(Frame::Datagram(_)))));
//! ```

use core::fmt;

/// WebSocket subprotocol name (`Sec-WebSocket-Protocol`).
pub const SUBPROTOCOL: &str = "oss-relay.1";
/// Relay protocol version carried in [`Frame::Hello`] and [`Frame::Welcome`].
pub const VERSION: u8 = 1;
/// Largest datagram a frame may carry. SubSpace datagrams are at most 520
/// bytes, plus 21 for OpenSec; the rest is headroom.
pub const MAX_DATAGRAM: usize = 1024;
/// Largest encoded frame.
pub const MAX_FRAME: usize = 1 + MAX_DATAGRAM;
/// Longest zone name in [`Frame::Hello`], in bytes.
pub const MAX_ZONE_NAME: usize = 64;
/// Longest message in [`Frame::Close`], in bytes (so a frame fits a WebSocket
/// close reason too).
pub const MAX_CLOSE_MESSAGE: usize = 120;

/// Frame type bytes.
pub mod kind {
    /// One SubSpace datagram.
    pub const DATAGRAM: u8 = 0x01;
    /// Client → relay: the first frame, naming the zone.
    pub const HELLO: u8 = 0x02;
    /// Relay → client: the session is open.
    pub const WELCOME: u8 = 0x03;
    /// Either way: the session is over.
    pub const CLOSE: u8 = 0x04;
}

/// Why a relay session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// Normal shutdown.
    Normal,
    /// The relay does not speak the client's version.
    UnsupportedVersion,
    /// The relay does not serve the requested zone.
    UnknownZone,
    /// Too many sessions (in total or from this address).
    Busy,
    /// No traffic for the idle timeout.
    Idle,
    /// A malformed or unexpected frame, or a rate limit was exceeded.
    ProtocolError,
    /// The client's address is banned.
    Banned,
    /// The zone stopped answering.
    ZoneUnreachable,
    /// A reason this version does not know.
    Other(u8),
}

impl CloseReason {
    /// Wire value.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::UnsupportedVersion => 1,
            Self::UnknownZone => 2,
            Self::Busy => 3,
            Self::Idle => 4,
            Self::ProtocolError => 5,
            Self::Banned => 6,
            Self::ZoneUnreachable => 7,
            Self::Other(v) => v,
        }
    }

    /// From the wire value.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Normal,
            1 => Self::UnsupportedVersion,
            2 => Self::UnknownZone,
            3 => Self::Busy,
            4 => Self::Idle,
            5 => Self::ProtocolError,
            6 => Self::Banned,
            7 => Self::ZoneUnreachable,
            v => Self::Other(v),
        }
    }
}

/// A relay frame. Borrowed from the buffer it was decoded from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// One SubSpace datagram, passed through unchanged (1..=[`MAX_DATAGRAM`] bytes).
    Datagram(&'a [u8]),
    /// Client → relay, first frame: protocol version and the zone to reach
    /// (empty for the relay's default zone).
    Hello {
        /// [`VERSION`].
        version: u8,
        /// Zone name, at most [`MAX_ZONE_NAME`] bytes of UTF-8.
        zone: &'a str,
    },
    /// Relay → client: the session is open and datagrams may flow.
    Welcome {
        /// The version the relay will speak.
        version: u8,
        /// Largest datagram the relay forwards.
        max_datagram: u16,
        /// The relay closes the session after this long without traffic.
        idle_timeout_ms: u32,
    },
    /// Either way: the session is over; the sender closes the carrier next.
    Close {
        /// Why.
        reason: CloseReason,
        /// Human-readable detail, at most [`MAX_CLOSE_MESSAGE`] bytes of UTF-8.
        message: &'a str,
    },
}

/// A frame that could not be decoded or encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// No bytes.
    Empty,
    /// An unknown frame type.
    UnknownKind(u8),
    /// Too short for its type, or an empty datagram.
    Truncated(u8),
    /// Longer than the limit for its type (or a stream length prefix out of
    /// range).
    TooLong,
    /// A text field is not UTF-8.
    NotUtf8,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty relay frame"),
            Self::UnknownKind(k) => write!(f, "unknown relay frame type {k:#04x}"),
            Self::Truncated(k) => write!(f, "truncated relay frame of type {k:#04x}"),
            Self::TooLong => f.write_str("relay frame too long"),
            Self::NotUtf8 => f.write_str("relay frame text is not UTF-8"),
        }
    }
}

impl std::error::Error for FrameError {}

fn text(bytes: &[u8], max: usize) -> Result<&str, FrameError> {
    if bytes.len() > max {
        return Err(FrameError::TooLong);
    }
    core::str::from_utf8(bytes).map_err(|_| FrameError::NotUtf8)
}

impl<'a> Frame<'a> {
    /// Decodes one frame (a whole WebSocket message, or a stream frame without
    /// its length prefix). Fields added by later versions after the known ones
    /// are ignored.
    pub fn decode(data: &'a [u8]) -> Result<Self, FrameError> {
        let (&k, body) = data.split_first().ok_or(FrameError::Empty)?;
        match k {
            kind::DATAGRAM => {
                if body.is_empty() {
                    Err(FrameError::Truncated(k))
                } else if body.len() > MAX_DATAGRAM {
                    Err(FrameError::TooLong)
                } else {
                    Ok(Self::Datagram(body))
                }
            }
            kind::HELLO => {
                let [version, _flags, len, rest @ ..] = body else {
                    return Err(FrameError::Truncated(k));
                };
                let name = rest
                    .get(..usize::from(*len))
                    .ok_or(FrameError::Truncated(k))?;
                Ok(Self::Hello {
                    version: *version,
                    zone: text(name, MAX_ZONE_NAME)?,
                })
            }
            kind::WELCOME => {
                let [version, m0, m1, t0, t1, t2, t3, ..] = body else {
                    return Err(FrameError::Truncated(k));
                };
                Ok(Self::Welcome {
                    version: *version,
                    max_datagram: u16::from_le_bytes([*m0, *m1]),
                    idle_timeout_ms: u32::from_le_bytes([*t0, *t1, *t2, *t3]),
                })
            }
            kind::CLOSE => {
                let (&reason, message) = body.split_first().ok_or(FrameError::Truncated(k))?;
                Ok(Self::Close {
                    reason: CloseReason::from_u8(reason),
                    message: text(message, MAX_CLOSE_MESSAGE)?,
                })
            }
            other => Err(FrameError::UnknownKind(other)),
        }
    }

    /// Appends the encoded frame. Fails (appending nothing) if a field is over
    /// its limit or the datagram is empty.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        match *self {
            Self::Datagram(d) => {
                if d.is_empty() {
                    return Err(FrameError::Truncated(kind::DATAGRAM));
                }
                if d.len() > MAX_DATAGRAM {
                    return Err(FrameError::TooLong);
                }
                out.push(kind::DATAGRAM);
                out.extend_from_slice(d);
            }
            Self::Hello { version, zone } => {
                if zone.len() > MAX_ZONE_NAME {
                    return Err(FrameError::TooLong);
                }
                out.extend_from_slice(&[kind::HELLO, version, 0, zone.len() as u8]);
                out.extend_from_slice(zone.as_bytes());
            }
            Self::Welcome {
                version,
                max_datagram,
                idle_timeout_ms,
            } => {
                out.extend_from_slice(&[kind::WELCOME, version]);
                out.extend_from_slice(&max_datagram.to_le_bytes());
                out.extend_from_slice(&idle_timeout_ms.to_le_bytes());
            }
            Self::Close { reason, message } => {
                if message.len() > MAX_CLOSE_MESSAGE {
                    return Err(FrameError::TooLong);
                }
                out.extend_from_slice(&[kind::CLOSE, reason.to_u8()]);
                out.extend_from_slice(message.as_bytes());
            }
        }
        Ok(())
    }
}

/// Appends a length-prefixed frame for a byte-stream carrier: `u16` LE length,
/// then the frame.
pub fn write_stream_frame(frame: &Frame<'_>, out: &mut Vec<u8>) -> Result<(), FrameError> {
    let at = out.len();
    out.extend_from_slice(&[0, 0]);
    if let Err(e) = frame.encode(out) {
        out.truncate(at);
        return Err(e);
    }
    let len = (out.len() - at - 2) as u16;
    out[at..at + 2].copy_from_slice(&len.to_le_bytes());
    Ok(())
}

/// Splits a byte stream back into frames. Feed received bytes with
/// [`StreamDecoder::push`], then call [`StreamDecoder::next_frame`] until it
/// returns `None`.
///
/// A length prefix of 0 or over [`MAX_FRAME`] means the peer is not speaking
/// this protocol: the decoder returns [`FrameError::TooLong`] from then on and
/// the caller should close the stream. Other errors affect only their frame.
#[derive(Debug, Default, Clone)]
pub struct StreamDecoder {
    buf: Vec<u8>,
    start: usize,
    broken: bool,
}

impl StreamDecoder {
    /// An empty decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends received bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes received but not yet returned as frames.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    /// Whether the stream had an invalid length prefix; the caller should
    /// close it.
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// The next complete frame, if any.
    pub fn next_frame(&mut self) -> Option<Result<Frame<'_>, FrameError>> {
        if self.broken {
            return Some(Err(FrameError::TooLong));
        }
        let pending = &self.buf[self.start..];
        let [l0, l1, ..] = *pending else {
            return None;
        };
        let len = usize::from(u16::from_le_bytes([l0, l1]));
        if len == 0 || len > MAX_FRAME {
            self.broken = true;
            return Some(Err(FrameError::TooLong));
        }
        if pending.len() < 2 + len {
            return None;
        }
        let begin = self.start + 2;
        self.start = begin + len;
        Some(Frame::decode(&self.buf[begin..begin + len]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Frame<'static>> {
        vec![
            Frame::Datagram(&[0x00, 0x01, 1, 2, 3, 4, 1, 0]),
            Frame::Datagram(&[0x42; MAX_DATAGRAM]),
            Frame::Hello {
                version: VERSION,
                zone: "",
            },
            Frame::Hello {
                version: VERSION,
                zone: "Trench Wars — test",
            },
            Frame::Welcome {
                version: VERSION,
                max_datagram: 1024,
                idle_timeout_ms: 60_000,
            },
            Frame::Close {
                reason: CloseReason::Busy,
                message: "zone full",
            },
            Frame::Close {
                reason: CloseReason::Other(200),
                message: "",
            },
        ]
    }

    #[test]
    fn frames_round_trip() {
        for f in samples() {
            let mut b = Vec::new();
            f.encode(&mut b).unwrap();
            assert_eq!(Frame::decode(&b), Ok(f));
        }
    }

    #[test]
    fn exact_layouts() {
        let mut b = Vec::new();
        Frame::Hello {
            version: 1,
            zone: "ab",
        }
        .encode(&mut b)
        .unwrap();
        assert_eq!(b, [0x02, 1, 0, 2, b'a', b'b']);
        b.clear();
        Frame::Welcome {
            version: 1,
            max_datagram: 0x0400,
            idle_timeout_ms: 0x0001_D4C0,
        }
        .encode(&mut b)
        .unwrap();
        assert_eq!(b, [0x03, 1, 0x00, 0x04, 0xC0, 0xD4, 0x01, 0x00]);
        b.clear();
        Frame::Close {
            reason: CloseReason::Idle,
            message: "x",
        }
        .encode(&mut b)
        .unwrap();
        assert_eq!(b, [0x04, 4, b'x']);
    }

    #[test]
    fn limits() {
        let mut b = Vec::new();
        assert_eq!(
            Frame::Datagram(&[]).encode(&mut b),
            Err(FrameError::Truncated(kind::DATAGRAM))
        );
        assert_eq!(
            Frame::Datagram(&[0; MAX_DATAGRAM + 1]).encode(&mut b),
            Err(FrameError::TooLong)
        );
        let long = "z".repeat(MAX_ZONE_NAME + 1);
        assert_eq!(
            Frame::Hello {
                version: 1,
                zone: &long
            }
            .encode(&mut b),
            Err(FrameError::TooLong)
        );
        assert!(b.is_empty(), "failed encodes append nothing");

        assert_eq!(Frame::decode(&[]), Err(FrameError::Empty));
        assert_eq!(Frame::decode(&[0x01]), Err(FrameError::Truncated(1)));
        assert_eq!(Frame::decode(&[0x09, 1]), Err(FrameError::UnknownKind(9)));
        assert_eq!(
            Frame::decode(&[0x02, 1, 0, 5, b'a']),
            Err(FrameError::Truncated(2))
        );
        assert_eq!(
            Frame::decode(&[0x02, 1, 0, 1, 0xFF]),
            Err(FrameError::NotUtf8)
        );
        assert_eq!(
            Frame::decode(&[0x03, 1, 0, 4]),
            Err(FrameError::Truncated(3))
        );
        let mut big = vec![0x01];
        big.resize(MAX_FRAME + 1, 0);
        assert_eq!(Frame::decode(&big), Err(FrameError::TooLong));
        // Later versions may append fields.
        assert_eq!(
            Frame::decode(&[0x03, 2, 0, 4, 0, 0, 0, 0, 0xAA]),
            Ok(Frame::Welcome {
                version: 2,
                max_datagram: 1024,
                idle_timeout_ms: 0
            })
        );
    }

    #[test]
    fn stream_split_at_every_byte() {
        let mut stream = Vec::new();
        for f in samples() {
            write_stream_frame(&f, &mut stream).unwrap();
        }
        for step in [1, 2, 3, 7, 100, stream.len()] {
            let mut dec = StreamDecoder::new();
            let mut got = Vec::new();
            for chunk in stream.chunks(step) {
                dec.push(chunk);
                while let Some(f) = dec.next_frame() {
                    let mut b = Vec::new();
                    f.unwrap().encode(&mut b).unwrap();
                    got.push(b);
                }
            }
            let want: Vec<Vec<u8>> = samples()
                .iter()
                .map(|f| {
                    let mut b = Vec::new();
                    f.encode(&mut b).unwrap();
                    b
                })
                .collect();
            assert_eq!(got, want, "chunk size {step}");
            assert_eq!(dec.buffered(), 0);
        }
    }

    #[test]
    fn stream_rejects_bad_lengths() {
        let mut dec = StreamDecoder::new();
        dec.push(&[0, 0]);
        assert_eq!(dec.next_frame(), Some(Err(FrameError::TooLong)));
        assert_eq!(
            dec.next_frame(),
            Some(Err(FrameError::TooLong)),
            "stays broken"
        );

        let mut dec = StreamDecoder::new();
        dec.push(&((MAX_FRAME + 1) as u16).to_le_bytes());
        assert_eq!(dec.next_frame(), Some(Err(FrameError::TooLong)));

        // A bad frame inside a good length only affects that frame.
        let mut dec = StreamDecoder::new();
        dec.push(&[1, 0, 0x09, 2, 0, 0x04, 0]);
        assert_eq!(dec.next_frame(), Some(Err(FrameError::UnknownKind(9))));
        assert_eq!(
            dec.next_frame(),
            Some(Ok(Frame::Close {
                reason: CloseReason::Normal,
                message: ""
            }))
        );
        assert_eq!(dec.next_frame(), None);

        let mut out = Vec::new();
        assert!(write_stream_frame(&Frame::Datagram(&[]), &mut out).is_err());
        assert!(out.is_empty());
    }

    #[test]
    fn close_reasons_round_trip() {
        for v in 0..=255u8 {
            assert_eq!(CloseReason::from_u8(v).to_u8(), v);
        }
    }
}
