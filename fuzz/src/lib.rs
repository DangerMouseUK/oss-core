//! Shared helpers for the oss-core fuzz targets.

use core::fmt::Debug;

/// Checks that a decoded value survives encode → decode unchanged. Decoders may
/// be lenient (ignore trailing bytes, normalise padding), so the original bytes
/// need not come back, but whatever we produce must read back as the same value.
pub fn assert_stable<T, E>(
    value: &T,
    encode: impl Fn(&T) -> Vec<u8>,
    decode: impl Fn(&[u8]) -> Result<T, E>,
) where
    T: PartialEq + Debug,
    E: Debug,
{
    let bytes = encode(value);
    match decode(&bytes) {
        Ok(again) => assert_eq!(
            &again, value,
            "re-decoded value differs; bytes {bytes:02x?}"
        ),
        Err(e) => {
            panic!("re-encoded value does not decode: {e:?}; value {value:?}; bytes {bytes:02x?}")
        }
    }
}

/// One step of a transport scenario, read from fuzz input.
#[derive(Debug)]
pub struct Step<'a> {
    /// Milliseconds to advance before this step (0..=1023).
    pub advance: u64,
    /// Which peer the datagram comes from (servers use it as the address).
    pub peer: u8,
    /// Extra action selector for the target.
    pub action: u8,
    /// The datagram.
    pub data: &'a [u8],
}

/// Splits fuzz input into steps: `u16 header` (advance: 10 bits, peer: 2 bits,
/// action: 4 bits), `u16 len` (masked to 0..=1023), then `len` bytes.
pub fn steps(mut input: &[u8]) -> impl Iterator<Item = Step<'_>> {
    core::iter::from_fn(move || {
        if input.len() < 4 {
            return None;
        }
        let header = u16::from_le_bytes([input[0], input[1]]);
        let len = (u16::from_le_bytes([input[2], input[3]]) & 0x3FF) as usize;
        input = &input[4..];
        let len = len.min(input.len());
        let (data, rest) = input.split_at(len);
        input = rest;
        Some(Step {
            advance: u64::from(header & 0x3FF),
            peer: ((header >> 10) & 3) as u8,
            action: (header >> 12) as u8,
            data,
        })
    })
}
