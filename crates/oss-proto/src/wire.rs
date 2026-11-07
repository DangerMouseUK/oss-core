//! Little-endian reader/writer helpers and fixed-size string fields.

use alloc::vec::Vec;
use core::fmt;

use crate::DecodeError;

/// A bounds-checked little-endian cursor over a packet.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    kind: u8,
}

impl<'a> Reader<'a> {
    /// Starts reading `data`; `kind` is the packet type used in error reports.
    pub fn new(data: &'a [u8], kind: u8) -> Self {
        Self { data, pos: 0, kind }
    }

    /// Bytes not yet read.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Current offset.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Takes the next `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.data.len())
            .ok_or(DecodeError::Truncated {
                kind: self.kind,
                need: self.pos + n,
                have: self.data.len(),
            })?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Takes the next `N` bytes as an array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut a = [0; N];
        a.copy_from_slice(self.bytes(N)?);
        Ok(a)
    }

    /// Takes everything that is left.
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.data[self.pos..];
        self.pos = self.data.len();
        s
    }

    /// Reads a `u8`.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }
    /// Reads an `i8`.
    pub fn i8(&mut self) -> Result<i8, DecodeError> {
        Ok(self.u8()? as i8)
    }
    /// Reads a `u16`.
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    /// Reads an `i16`.
    pub fn i16(&mut self) -> Result<i16, DecodeError> {
        Ok(i16::from_le_bytes(self.array()?))
    }
    /// Reads a `u32`.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    /// Reads an `i32`.
    pub fn i32(&mut self) -> Result<i32, DecodeError> {
        Ok(i32::from_le_bytes(self.array()?))
    }
    /// Reads a fixed-size string field.
    pub fn fixed<const N: usize>(&mut self) -> Result<FixedStr<N>, DecodeError> {
        Ok(FixedStr(self.array()?))
    }
    /// Reads a NUL-terminated string; without a NUL, takes the rest of the packet.
    pub fn cstr(&mut self) -> Vec<u8> {
        let rest = &self.data[self.pos..];
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        self.pos += (end + 1).min(rest.len());
        rest[..end].to_vec()
    }
}

/// Little-endian append helpers for `Vec<u8>`.
pub trait Writer {
    /// Appends a `u8`.
    fn put_u8(&mut self, v: u8);
    /// Appends an `i8`.
    fn put_i8(&mut self, v: i8) {
        self.put_u8(v as u8)
    }
    /// Appends a `u16`.
    fn put_u16(&mut self, v: u16);
    /// Appends an `i16`.
    fn put_i16(&mut self, v: i16) {
        self.put_u16(v as u16)
    }
    /// Appends a `u32`.
    fn put_u32(&mut self, v: u32);
    /// Appends an `i32`.
    fn put_i32(&mut self, v: i32) {
        self.put_u32(v as u32)
    }
    /// Appends raw bytes.
    fn put_bytes(&mut self, b: &[u8]);
    /// Appends bytes followed by a NUL.
    fn put_cstr(&mut self, b: &[u8]) {
        self.put_bytes(b);
        self.put_u8(0);
    }
}

impl Writer for Vec<u8> {
    fn put_u8(&mut self, v: u8) {
        self.push(v);
    }
    fn put_u16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_u32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_le_bytes());
    }
    fn put_bytes(&mut self, b: &[u8]) {
        self.extend_from_slice(b);
    }
}

/// A fixed-size, NUL-padded text field (names, squads, arena names, file names).
///
/// The raw bytes are kept as received, so bytes after the first NUL survive a
/// round-trip. Text is Windows-1252 in practice; [`FixedStr::as_bytes`] gives the
/// bytes up to the first NUL.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FixedStr<const N: usize>(pub [u8; N]);

impl<const N: usize> FixedStr<N> {
    /// Builds a field from bytes, truncating to `N` and NUL-padding.
    pub fn new(s: &[u8]) -> Self {
        let mut a = [0; N];
        let n = s.len().min(N);
        a[..n].copy_from_slice(&s[..n]);
        Self(a)
    }

    /// The text up to the first NUL (or all `N` bytes if there is none).
    pub fn as_bytes(&self) -> &[u8] {
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(N);
        &self.0[..end]
    }

    /// The text as UTF-8, if it is valid UTF-8.
    pub fn to_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }
}

impl<const N: usize> Default for FixedStr<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> From<&str> for FixedStr<N> {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes())
    }
}

impl<const N: usize> fmt::Debug for FixedStr<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}",
            alloc::string::String::from_utf8_lossy(self.as_bytes())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_bounds() {
        let mut r = Reader::new(&[1, 2, 3], 9);
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert!(r.u16().is_err());
        assert_eq!(r.u8().unwrap(), 3);
        assert!(r.u8().is_err());
        assert!(Reader::new(&[], 0).bytes(usize::MAX).is_err());
    }

    #[test]
    fn fixed_str() {
        let s: FixedStr<4> = "abcdef".into();
        assert_eq!(s.as_bytes(), b"abcd");
        let s: FixedStr<4> = "ab".into();
        assert_eq!(s.0, *b"ab\0\0");
        assert_eq!(s.to_str(), Some("ab"));
    }

    #[test]
    fn cstr() {
        let mut r = Reader::new(b"hi\0yo", 0);
        assert_eq!(r.cstr(), b"hi");
        assert_eq!(r.cstr(), b"yo");
        assert_eq!(r.remaining(), 0);
    }
}

/// A fixed-size field that can be read from and written to the wire.
pub trait Wire: Sized {
    /// Encoded size in bytes.
    const SIZE: usize;
    /// Reads the field.
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError>;
    /// Appends the field.
    fn write(&self, out: &mut Vec<u8>);
}

macro_rules! wire_int {
    ($($t:ty => $get:ident, $put:ident;)*) => {$(
        impl Wire for $t {
            const SIZE: usize = core::mem::size_of::<$t>();
            fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
                r.$get()
            }
            fn write(&self, out: &mut Vec<u8>) {
                out.$put(*self)
            }
        }
    )*};
}

wire_int! {
    u8 => u8, put_u8;
    i8 => i8, put_i8;
    u16 => u16, put_u16;
    i16 => i16, put_i16;
    u32 => u32, put_u32;
    i32 => i32, put_i32;
}

impl<const N: usize> Wire for [u8; N] {
    const SIZE: usize = N;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.array()
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.put_bytes(self)
    }
}

impl<const N: usize> Wire for FixedStr<N> {
    const SIZE: usize = N;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.fixed()
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.put_bytes(&self.0)
    }
}

/// A packet with a type byte and a codec. `decode` takes the whole packet, type
/// byte included; `encode` writes it, type byte included.
pub trait Packet: Sized {
    /// The packet's type byte.
    const TYPE: u8;
    /// Decodes a whole packet (type byte first).
    fn decode(data: &[u8]) -> Result<Self, DecodeError>;
    /// Appends the whole packet (type byte first).
    fn encode(&self, out: &mut Vec<u8>);
    /// The encoded packet.
    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode(&mut v);
        v
    }
}

/// Checks the type byte and returns a reader positioned after it.
pub fn expect_type(data: &[u8], ty: u8) -> Result<Reader<'_>, DecodeError> {
    let found = *data.first().ok_or(DecodeError::Empty)?;
    if found != ty {
        return Err(DecodeError::WrongType {
            expected: ty,
            found,
        });
    }
    let mut r = Reader::new(data, ty);
    r.u8()?;
    Ok(r)
}

/// Defines a packet whose body is a fixed sequence of [`Wire`] fields. Trailing
/// bytes beyond the fixed layout are ignored when decoding.
#[macro_export]
#[doc(hidden)]
macro_rules! fixed_packet {
    (
        $(#[$m:meta])*
        pub struct $name:ident = $ty:expr;
        { $( $(#[$fm:meta])* pub $f:ident : $t:ty ),* $(,)? }
    ) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            $( $(#[$fm])* pub $f: $t, )*
        }

        impl $name {
            /// Encoded length, type byte included.
            pub const LEN: usize = 1 $( + <$t as $crate::wire::Wire>::SIZE )*;
        }

        impl $crate::wire::Packet for $name {
            const TYPE: u8 = $ty;
            #[allow(unused_mut, unused_variables)]
            fn decode(data: &[u8]) -> Result<Self, $crate::DecodeError> {
                let mut r = $crate::wire::expect_type(data, $ty)?;
                Ok(Self { $( $f: <$t as $crate::wire::Wire>::read(&mut r)?, )* })
            }
            #[allow(unused_variables)]
            fn encode(&self, out: &mut alloc::vec::Vec<u8>) {
                out.push($ty);
                $( <$t as $crate::wire::Wire>::write(&self.$f, out); )*
            }
        }
    };
}
