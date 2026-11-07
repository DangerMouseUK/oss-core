//! Region tile sets and the compact run-length encoding used by eLVL `rTIL` chunks.
//!
//! A region is any subset of the 1024x1024 map tiles. The encoding walks the map
//! row by row; each code byte's top three bits pick an operation and the low five
//! bits (plus an optional second byte when bit 5 is set) give a count `n + 1`:
//!
//! | top bits | meaning                          |
//! |----------|----------------------------------|
//! | `00`     | run of empty tiles in this row   |
//! | `01`     | run of present tiles in this row |
//! | `10`     | whole empty rows                 |
//! | `11`     | repeat the previous row          |
//!
//! Every row must sum to exactly 1024 tiles and the data must describe exactly
//! 1024 rows.

use alloc::vec;
use alloc::vec::Vec;

use crate::FormatError;
use crate::lvl::MAP_SIZE;

const WORDS_PER_ROW: usize = MAP_SIZE / 64;

/// A set of map tiles, one bit per tile (128 KiB).
#[derive(Clone, PartialEq, Eq)]
pub struct RegionBitmap {
    bits: Vec<u64>,
}

impl core::fmt::Debug for RegionBitmap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegionBitmap")
            .field("tiles", &self.count())
            .finish()
    }
}

impl Default for RegionBitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl RegionBitmap {
    /// An empty region.
    pub fn new() -> Self {
        Self {
            bits: vec![0; WORDS_PER_ROW * MAP_SIZE],
        }
    }

    /// Whether tile (`x`, `y`) is in the region. Out-of-range coordinates are not.
    pub fn contains(&self, x: u32, y: u32) -> bool {
        let (x, y) = (x as usize, y as usize);
        if x >= MAP_SIZE || y >= MAP_SIZE {
            return false;
        }
        self.bits[y * WORDS_PER_ROW + x / 64] & (1 << (x % 64)) != 0
    }

    /// Adds or removes tile (`x`, `y`). Out-of-range coordinates are ignored.
    pub fn set(&mut self, x: u32, y: u32, present: bool) {
        let (x, y) = (x as usize, y as usize);
        if x >= MAP_SIZE || y >= MAP_SIZE {
            return;
        }
        let word = &mut self.bits[y * WORDS_PER_ROW + x / 64];
        if present {
            *word |= 1 << (x % 64);
        } else {
            *word &= !(1 << (x % 64));
        }
    }

    /// Number of tiles in the region.
    pub fn count(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Whether the region has no tiles.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }

    /// Iterates over the tiles in the region, row by row.
    pub fn iter(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.bits.iter().enumerate().flat_map(|(i, &w)| {
            let y = (i / WORDS_PER_ROW) as u32;
            let x0 = ((i % WORDS_PER_ROW) * 64) as u32;
            BitIter(w).map(move |b| (x0 + b, y))
        })
    }

    fn row(&self, y: usize) -> &[u64] {
        &self.bits[y * WORDS_PER_ROW..(y + 1) * WORDS_PER_ROW]
    }

    fn set_run(&mut self, y: usize, x0: usize, n: usize) {
        for x in x0..x0 + n {
            self.bits[y * WORDS_PER_ROW + x / 64] |= 1 << (x % 64);
        }
    }

    /// Decodes `rTIL` data.
    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        let mut out = Self::new();
        let (mut cx, mut cy, mut i) = (0usize, 0usize, 0usize);
        while i < data.len() {
            let at = i;
            let bad = FormatError::BadRegionTiles { offset: at };
            if cy >= MAP_SIZE {
                return Err(bad);
            }
            let b = data[i];
            i += 1;
            let n = if b & 0x20 != 0 {
                // Long form: bits 3-4 of the first byte must be zero.
                if b & 0x1C != 0 {
                    return Err(bad);
                }
                let lo = *data.get(i).ok_or(bad.clone())?;
                i += 1;
                ((usize::from(b & 0x03)) << 8 | usize::from(lo)) + 1
            } else {
                usize::from(b & 0x1F) + 1
            };
            match b >> 6 {
                0 | 1 => {
                    if cx + n > MAP_SIZE {
                        return Err(bad);
                    }
                    if b >> 6 == 1 {
                        out.set_run(cy, cx, n);
                    }
                    cx += n;
                    if cx == MAP_SIZE {
                        cx = 0;
                        cy += 1;
                    }
                }
                2 => {
                    if cx != 0 || cy + n > MAP_SIZE {
                        return Err(bad);
                    }
                    cy += n;
                }
                _ => {
                    if cx != 0 || cy == 0 || cy + n > MAP_SIZE {
                        return Err(bad);
                    }
                    let (prev, rest) = out.bits.split_at_mut(cy * WORDS_PER_ROW);
                    let prev = &prev[(cy - 1) * WORDS_PER_ROW..];
                    for row in rest[..n * WORDS_PER_ROW].as_chunks_mut::<WORDS_PER_ROW>().0 {
                        row.copy_from_slice(prev);
                    }
                    cy += n;
                }
            }
        }
        if cx != 0 || cy != MAP_SIZE {
            return Err(FormatError::BadRegionTiles { offset: data.len() });
        }
        Ok(out)
    }

    /// Encodes the region as `rTIL` data, using the shortest codes this encoder knows
    /// (empty-row and repeat-row codes where they apply).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut y = 0;
        while y < MAP_SIZE {
            let row = self.row(y);
            if row.iter().all(|&w| w == 0) {
                let mut n = 1;
                while y + n < MAP_SIZE && self.row(y + n).iter().all(|&w| w == 0) {
                    n += 1;
                }
                push_code(&mut out, 0b100, n);
                y += n;
                continue;
            }
            if y > 0 && self.row(y - 1) == row {
                let mut n = 1;
                while y + n < MAP_SIZE && self.row(y + n) == row {
                    n += 1;
                }
                push_code(&mut out, 0b110, n);
                y += n;
                continue;
            }
            let mut x = 0;
            while x < MAP_SIZE {
                let present = self.contains(x as u32, y as u32);
                let mut n = 1;
                while x + n < MAP_SIZE && self.contains((x + n) as u32, y as u32) == present {
                    n += 1;
                }
                push_code(&mut out, if present { 0b010 } else { 0b000 }, n);
                x += n;
            }
            y += 1;
        }
        out
    }
}

/// Emits one code (`op` is the top three bits with bit 5 clear) for a count of `n`
/// (1..=1024).
fn push_code(out: &mut Vec<u8>, op: u8, n: usize) {
    debug_assert!((1..=MAP_SIZE).contains(&n));
    let v = n - 1;
    if v < 32 {
        out.push(op << 5 | v as u8);
    } else {
        out.push(op << 5 | 0x20 | (v >> 8) as u8);
        out.push(v as u8);
    }
}

struct BitIter(u64);

impl Iterator for BitIter {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.0 == 0 {
            return None;
        }
        let b = self.0.trailing_zeros();
        self.0 &= self.0 - 1;
        Some(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_region_is_two_bytes() {
        let r = RegionBitmap::new();
        assert_eq!(r.encode(), [163, 255]);
        assert_eq!(RegionBitmap::decode(&[163, 255]).unwrap(), r);
    }

    #[test]
    fn spec_examples() {
        // A run of 10 present tiles is 73; 300 empty tiles is 33 43.
        let mut v = Vec::new();
        push_code(&mut v, 0b010, 10);
        push_code(&mut v, 0b000, 300);
        assert_eq!(v, [73, 33, 43]);
    }

    #[test]
    fn round_trip_shapes() {
        let mut r = RegionBitmap::new();
        for y in 10..40 {
            for x in 100..600 {
                r.set(x, y, true);
            }
        }
        r.set(0, 0, true);
        r.set(1023, 1023, true);
        r.set(512, 700, true);
        let enc = r.encode();
        let dec = RegionBitmap::decode(&enc).unwrap();
        assert_eq!(dec, r);
        assert_eq!(dec.count(), 30 * 500 + 3);
        assert!(dec.contains(1023, 1023) && !dec.contains(1022, 1023));
        assert_eq!(dec.iter().count(), dec.count());
    }

    #[test]
    fn rejects_bad_data() {
        // Too few rows.
        assert!(RegionBitmap::decode(&[0x80]).is_err());
        // Repeat with no previous row.
        assert!(RegionBitmap::decode(&[0xC0]).is_err());
        // Run past end of row.
        assert!(RegionBitmap::decode(&[0x23, 0xFF, 0x00]).is_err());
        // Truncated long code.
        assert!(RegionBitmap::decode(&[0x23]).is_err());
        // Reserved bits set.
        assert!(RegionBitmap::decode(&[0xBC, 0xFF]).is_err());
        // Extra codes after 1024 rows.
        assert!(RegionBitmap::decode(&[163, 255, 0x80]).is_err());
        // Row empty code mid-row.
        assert!(RegionBitmap::decode(&[0x00, 0x80]).is_err());
    }
}
