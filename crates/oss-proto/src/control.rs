//! Core (transport/control) packets: type byte `0x00` followed by a subtype byte.
//!
//! These carry connection setup, reliability, framing and time sync. The
//! transport state machine lives in `oss-net`; this module only defines the
//! wire shapes. Payload-carrying variants borrow from the input buffer.

use alloc::vec::Vec;

use crate::DecodeError;
use crate::wire::{Reader, Writer};

/// Core packet subtypes (second byte).
pub mod subtype {
    /// Connection request (client key + protocol version).
    pub const CONNECT: u8 = 0x01;
    /// Connection response (server key).
    pub const CONNECT_RESPONSE: u8 = 0x02;
    /// Reliable message.
    pub const RELIABLE: u8 = 0x03;
    /// Acknowledgement of a reliable message.
    pub const ACK: u8 = 0x04;
    /// Time sync request.
    pub const SYNC_REQUEST: u8 = 0x05;
    /// Time sync response.
    pub const SYNC_RESPONSE: u8 = 0x06;
    /// Disconnect.
    pub const DISCONNECT: u8 = 0x07;
    /// Big-data chunk (more follows).
    pub const CHUNK_BODY: u8 = 0x08;
    /// Big-data chunk (last piece).
    pub const CHUNK_TAIL: u8 = 0x09;
    /// Sized (streamed) transfer piece.
    pub const STREAM: u8 = 0x0A;
    /// Cancel a sized transfer.
    pub const STREAM_CANCEL: u8 = 0x0B;
    /// Acknowledge a sized-transfer cancel.
    pub const STREAM_CANCEL_ACK: u8 = 0x0C;
    /// Cluster of several packets in one datagram.
    pub const CLUSTER: u8 = 0x0E;
}

/// Protocol version sent in [`CorePacket::Connect`] by SubSpace (VIE) clients.
pub const PROTOCOL_VIE: u16 = 0x0001;
/// Protocol version sent in [`CorePacket::Connect`] by Continuum clients.
pub const PROTOCOL_CONTINUUM: u16 = 0x0011;

/// Largest element a cluster can carry (its length prefix is one byte).
pub const CLUSTER_MAX_ELEMENT: usize = 255;

/// A decoded core packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorePacket<'a> {
    /// `00 01 key:u32 protocol:u16`.
    Connect {
        /// Client's proposed key.
        key: u32,
        /// [`PROTOCOL_VIE`] or [`PROTOCOL_CONTINUUM`].
        protocol: u16,
    },
    /// `00 02 key:u32 [extra:u8]`.
    ConnectResponse {
        /// Server's key.
        key: u32,
        /// Optional trailing byte some servers send.
        extra: Option<u8>,
    },
    /// `00 03 seq:u32 payload`.
    Reliable {
        /// Sequence number.
        seq: u32,
        /// The wrapped packet.
        payload: &'a [u8],
    },
    /// `00 04 seq:u32`.
    Ack {
        /// Sequence number being acknowledged.
        seq: u32,
    },
    /// `00 05 time:u32 [sent:u32 received:u32]`.
    SyncRequest {
        /// Sender's clock (ticks).
        time: u32,
        /// Packets sent and received so far, if included.
        counts: Option<(u32, u32)>,
    },
    /// `00 06 client_time:u32 server_time:u32`.
    SyncResponse {
        /// The `time` from the request being answered.
        client_time: u32,
        /// Responder's clock (ticks).
        server_time: u32,
    },
    /// `00 07`.
    Disconnect,
    /// `00 08 data`: a piece of a big packet; more follow.
    ChunkBody(&'a [u8]),
    /// `00 09 data`: the last piece of a big packet.
    ChunkTail(&'a [u8]),
    /// `00 0A total:u32 data`: a piece of a sized transfer of `total` bytes.
    Stream {
        /// Total size of the transfer.
        total: u32,
        /// This piece.
        data: &'a [u8],
    },
    /// `00 0B`.
    StreamCancel,
    /// `00 0C`.
    StreamCancelAck,
    /// `00 0E (len:u8 data)*`: several packets in one datagram.
    Cluster(Cluster<'a>),
    /// Any other subtype (e.g. Continuum key exchange), kept raw.
    Other {
        /// Subtype byte.
        subtype: u8,
        /// Everything after the subtype byte.
        body: &'a [u8],
    },
}

/// The elements of a cluster, iterated lazily.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cluster<'a>(pub &'a [u8]);

impl<'a> Cluster<'a> {
    /// Iterates over the contained packets. A length prefix that runs past the end
    /// yields an error and stops iteration; a zero length is skipped.
    pub fn iter(&self) -> ClusterIter<'a> {
        ClusterIter {
            rest: self.0,
            failed: false,
        }
    }
}

/// Iterator over [`Cluster`] elements.
#[derive(Debug, Clone)]
pub struct ClusterIter<'a> {
    rest: &'a [u8],
    failed: bool,
}

impl<'a> Iterator for ClusterIter<'a> {
    type Item = Result<&'a [u8], DecodeError>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.failed || self.rest.is_empty() {
                return None;
            }
            let n = usize::from(self.rest[0]);
            if self.rest.len() < 1 + n {
                self.failed = true;
                return Some(Err(DecodeError::Truncated {
                    kind: 0,
                    need: 1 + n,
                    have: self.rest.len(),
                }));
            }
            let (elem, rest) = self.rest[1..].split_at(n);
            self.rest = rest;
            if n > 0 {
                return Some(Ok(elem));
            }
        }
    }
}

impl<'a> CorePacket<'a> {
    /// Decodes a core packet (`data[0]` must be `0x00`).
    pub fn decode(data: &'a [u8]) -> Result<Self, DecodeError> {
        let found = *data.first().ok_or(DecodeError::Empty)?;
        if found != 0 {
            return Err(DecodeError::WrongType { expected: 0, found });
        }
        let mut r = Reader::new(data, 0);
        r.u8()?;
        let sub = r.u8()?;
        Ok(match sub {
            subtype::CONNECT => Self::Connect {
                key: r.u32()?,
                protocol: r.u16()?,
            },
            subtype::CONNECT_RESPONSE => {
                let key = r.u32()?;
                let extra = if r.remaining() > 0 {
                    Some(r.u8()?)
                } else {
                    None
                };
                Self::ConnectResponse { key, extra }
            }
            subtype::RELIABLE => Self::Reliable {
                seq: r.u32()?,
                payload: r.rest(),
            },
            subtype::ACK => Self::Ack { seq: r.u32()? },
            subtype::SYNC_REQUEST => {
                let time = r.u32()?;
                let counts = if r.remaining() >= 8 {
                    Some((r.u32()?, r.u32()?))
                } else {
                    None
                };
                Self::SyncRequest { time, counts }
            }
            subtype::SYNC_RESPONSE => Self::SyncResponse {
                client_time: r.u32()?,
                server_time: r.u32()?,
            },
            subtype::DISCONNECT => Self::Disconnect,
            subtype::CHUNK_BODY => Self::ChunkBody(r.rest()),
            subtype::CHUNK_TAIL => Self::ChunkTail(r.rest()),
            subtype::STREAM => Self::Stream {
                total: r.u32()?,
                data: r.rest(),
            },
            subtype::STREAM_CANCEL => Self::StreamCancel,
            subtype::STREAM_CANCEL_ACK => Self::StreamCancelAck,
            subtype::CLUSTER => Self::Cluster(Cluster(r.rest())),
            other => Self::Other {
                subtype: other,
                body: r.rest(),
            },
        })
    }

    /// Appends the encoded packet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(0);
        match self {
            Self::Connect { key, protocol } => {
                out.put_u8(subtype::CONNECT);
                out.put_u32(*key);
                out.put_u16(*protocol);
            }
            Self::ConnectResponse { key, extra } => {
                out.put_u8(subtype::CONNECT_RESPONSE);
                out.put_u32(*key);
                if let Some(e) = extra {
                    out.put_u8(*e);
                }
            }
            Self::Reliable { seq, payload } => {
                out.put_u8(subtype::RELIABLE);
                out.put_u32(*seq);
                out.put_bytes(payload);
            }
            Self::Ack { seq } => {
                out.put_u8(subtype::ACK);
                out.put_u32(*seq);
            }
            Self::SyncRequest { time, counts } => {
                out.put_u8(subtype::SYNC_REQUEST);
                out.put_u32(*time);
                if let Some((s, r)) = counts {
                    out.put_u32(*s);
                    out.put_u32(*r);
                }
            }
            Self::SyncResponse {
                client_time,
                server_time,
            } => {
                out.put_u8(subtype::SYNC_RESPONSE);
                out.put_u32(*client_time);
                out.put_u32(*server_time);
            }
            Self::Disconnect => out.put_u8(subtype::DISCONNECT),
            Self::ChunkBody(d) => {
                out.put_u8(subtype::CHUNK_BODY);
                out.put_bytes(d);
            }
            Self::ChunkTail(d) => {
                out.put_u8(subtype::CHUNK_TAIL);
                out.put_bytes(d);
            }
            Self::Stream { total, data } => {
                out.put_u8(subtype::STREAM);
                out.put_u32(*total);
                out.put_bytes(data);
            }
            Self::StreamCancel => out.put_u8(subtype::STREAM_CANCEL),
            Self::StreamCancelAck => out.put_u8(subtype::STREAM_CANCEL_ACK),
            Self::Cluster(c) => {
                out.put_u8(subtype::CLUSTER);
                out.put_bytes(c.0);
            }
            Self::Other { subtype, body } => {
                out.put_u8(*subtype);
                out.put_bytes(body);
            }
        }
    }

    /// The encoded packet.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode(&mut v);
        v
    }
}

/// Builds the body of a cluster packet (`00 0E` + elements). Returns `false` and
/// leaves `out` unchanged if `element` is empty or longer than
/// [`CLUSTER_MAX_ELEMENT`].
pub fn push_cluster_element(out: &mut Vec<u8>, element: &[u8]) -> bool {
    if element.is_empty() || element.len() > CLUSTER_MAX_ELEMENT {
        return false;
    }
    if out.is_empty() {
        out.extend_from_slice(&[0, subtype::CLUSTER]);
    }
    out.push(element.len() as u8);
    out.extend_from_slice(element);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let cluster_body = [2, 0x27, 0x00, 3, 1, 2, 3];
        let cases = [
            CorePacket::Connect {
                key: 0x8765_4321,
                protocol: PROTOCOL_VIE,
            },
            CorePacket::ConnectResponse {
                key: 0x789A_BCDF,
                extra: None,
            },
            CorePacket::ConnectResponse {
                key: 1,
                extra: Some(1),
            },
            CorePacket::Reliable {
                seq: 7,
                payload: &[0x06, 1, 2],
            },
            CorePacket::Ack { seq: 0xFFFF_FFFF },
            CorePacket::SyncRequest {
                time: 100,
                counts: None,
            },
            CorePacket::SyncRequest {
                time: 100,
                counts: Some((5, 6)),
            },
            CorePacket::SyncResponse {
                client_time: 1,
                server_time: 2,
            },
            CorePacket::Disconnect,
            CorePacket::ChunkBody(&[1, 2, 3]),
            CorePacket::ChunkTail(&[]),
            CorePacket::Stream {
                total: 1000,
                data: &[9; 20],
            },
            CorePacket::StreamCancel,
            CorePacket::StreamCancelAck,
            CorePacket::Cluster(Cluster(&cluster_body)),
            CorePacket::Other {
                subtype: 0x10,
                body: &[1, 2, 3, 4],
            },
        ];
        for c in cases {
            let b = c.to_bytes();
            assert_eq!(CorePacket::decode(&b).unwrap(), c, "{b:02x?}");
        }
        assert_eq!(
            CorePacket::Connect {
                key: 1,
                protocol: 1
            }
            .to_bytes()
            .len(),
            8
        );
        assert_eq!(
            CorePacket::SyncRequest {
                time: 1,
                counts: Some((1, 1))
            }
            .to_bytes()
            .len(),
            14
        );
    }

    #[test]
    fn cluster_iteration() {
        let mut out = Vec::new();
        assert!(push_cluster_element(&mut out, &[0x27]));
        assert!(push_cluster_element(&mut out, &[0x00, 0x04, 1, 0, 0, 0]));
        assert!(!push_cluster_element(&mut out, &[]));
        assert!(!push_cluster_element(&mut out, &[0; 256]));
        let CorePacket::Cluster(c) = CorePacket::decode(&out).unwrap() else {
            panic!()
        };
        let items: Vec<_> = c.iter().map(Result::unwrap).collect();
        assert_eq!(items, [&[0x27][..], &[0x00, 0x04, 1, 0, 0, 0][..]]);
        // Truncated element.
        let bad = Cluster(&[5, 1, 2]);
        let r: Vec<_> = bad.iter().collect();
        assert_eq!(r.len(), 1);
        assert!(r[0].is_err());
    }

    #[test]
    fn short_packets_fail() {
        assert!(CorePacket::decode(&[]).is_err());
        assert!(CorePacket::decode(&[0]).is_err());
        assert!(CorePacket::decode(&[0, 3, 1, 2]).is_err());
        assert!(CorePacket::decode(&[1, 3]).is_err());
    }
}
