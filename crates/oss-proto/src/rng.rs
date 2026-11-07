//! The game's deterministic random number generator.
//!
//! Clients and servers seed it from S2C `0x18` (prize seed, door seed) and must
//! step it identically so prize positions, prize types and door states agree.
//! It is a Park-Miller "minimal standard" generator (multiplier 16807, modulus
//! 2^31 - 1, computed with Schrage's method) with 123 added each step, on a
//! signed 32-bit state. Follows nullspace's `VieRNG::GetNext`
//! (`src/null/Random.h`; MIT licence, Copyright (c) 2021 plushmonkey).

/// Generator state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VieRng {
    /// Current state (the last value returned, or the seed).
    pub seed: i32,
}

impl VieRng {
    /// A generator seeded with `seed` (as received in S2C `0x18`).
    pub fn new(seed: u32) -> Self {
        Self { seed: seed as i32 }
    }

    /// Advances the generator and returns the new state (1..=2^31-1, or values
    /// near it for unusual negative seeds).
    pub fn next_u32(&mut self) -> u32 {
        let s = self.seed;
        let mut n = (s % 127_773)
            .wrapping_mul(16_807)
            .wrapping_sub((s / 127_773).wrapping_mul(2_836))
            .wrapping_add(123);
        if n < 1 {
            n = n.wrapping_add(0x7FFF_FFFF);
        }
        self.seed = n;
        n as u32
    }
}

impl Iterator for VieRng {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        Some(self.next_u32())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Literal Park-Miller-with-offset recurrence computed in 64-bit arithmetic,
    /// which Schrage's method must match for non-negative seeds.
    fn reference(seed: i64) -> i64 {
        let r = (seed % 127_773) * 16_807 - (seed / 127_773) * 2_836 + 123;
        if r < 1 { r + 0x7FFF_FFFF } else { r }
    }

    #[test]
    fn matches_wide_arithmetic() {
        for seed in [
            0u32,
            1,
            42,
            127_773,
            0x1234_5678,
            0x7FFF_FFFF,
            0xFFFF_FFFF,
            0x8000_0000,
        ] {
            let mut r = VieRng::new(seed);
            let mut s = i64::from(seed as i32);
            for _ in 0..1000 {
                s = reference(s);
                assert_eq!(i64::from(r.next_u32() as i32), s, "seed {seed:#x}");
            }
        }
    }

    #[test]
    fn known_sequence() {
        // 1 -> 16807 + 123 = 16930 -> 16930 * 16807 + 123 = 284542633.
        let v: alloc::vec::Vec<u32> = VieRng::new(1).take(2).collect();
        assert_eq!(v, [16_930, 284_542_633]);
    }
}
