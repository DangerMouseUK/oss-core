//! Error type shared by the format parsers.

use core::fmt;

/// Why a file could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatError {
    /// The input ended before a structure was complete.
    Truncated {
        /// What was being read.
        what: &'static str,
        /// Byte offset where the structure starts.
        offset: usize,
    },
    /// A magic number or signature did not match.
    BadMagic {
        /// What was being read.
        what: &'static str,
        /// Byte offset of the magic value.
        offset: usize,
    },
    /// A length or offset field points outside the data.
    BadLength {
        /// What was being read.
        what: &'static str,
        /// Byte offset of the field.
        offset: usize,
    },
    /// Region tile data (`rTIL`) is malformed.
    BadRegionTiles {
        /// Byte offset inside the `rTIL` data.
        offset: usize,
    },
    /// A compressed section failed to inflate, or inflated to the wrong size.
    Decompress {
        /// Byte offset of the section.
        offset: usize,
    },
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { what, offset } => write!(f, "truncated {what} at offset {offset}"),
            Self::BadMagic { what, offset } => write!(f, "bad {what} signature at offset {offset}"),
            Self::BadLength { what, offset } => {
                write!(f, "{what} length out of range at offset {offset}")
            }
            Self::BadRegionTiles { offset } => {
                write!(f, "malformed region tile data at offset {offset}")
            }
            Self::Decompress { offset } => {
                write!(f, "compressed section at offset {offset} is corrupt")
            }
        }
    }
}

impl core::error::Error for FormatError {}

pub(crate) fn u32_at(data: &[u8], offset: usize, what: &'static str) -> Result<u32, FormatError> {
    data.get(
        offset
            ..offset
                .checked_add(4)
                .ok_or(FormatError::Truncated { what, offset })?,
    )
    .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    .ok_or(FormatError::Truncated { what, offset })
}
