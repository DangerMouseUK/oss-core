//! Decode errors.

use core::fmt;

/// Why a packet could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The packet is shorter than its layout requires.
    Truncated {
        /// Packet type byte (0 for core packets, see `kind` for the subtype).
        kind: u8,
        /// Bytes needed.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// The packet is empty.
    Empty,
    /// The type byte is not the one this decoder handles.
    WrongType {
        /// Expected type byte.
        expected: u8,
        /// Actual type byte.
        found: u8,
    },
    /// A field holds a value the protocol does not allow.
    Invalid {
        /// Packet type byte.
        kind: u8,
        /// Which field.
        field: &'static str,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { kind, need, have } => {
                write!(
                    f,
                    "packet 0x{kind:02X} truncated: need {need} bytes, have {have}"
                )
            }
            Self::Empty => f.write_str("empty packet"),
            Self::WrongType { expected, found } => {
                write!(f, "expected packet 0x{expected:02X}, found 0x{found:02X}")
            }
            Self::Invalid { kind, field } => write!(f, "packet 0x{kind:02X}: invalid {field}"),
        }
    }
}

impl core::error::Error for DecodeError {}
