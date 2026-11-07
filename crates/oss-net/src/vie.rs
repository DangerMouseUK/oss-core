//! The VIE cipher used by SubSpace 1.34/1.35 clients and by Continuum clients
//! that connect without Continuum encryption.
//!
//! A session key (a non-zero 32-bit value) seeds a Park-Miller style generator
//! that fills a 520-byte table. Packets are then processed as little-endian
//! 32-bit words after the type byte (after the first two bytes for core `0x00`
//! packets), each word XORed with its table word and the previous *ciphertext*
//! word (the key for the first word). A trailing partial word is treated as if
//! padded with zeros. Key 0 means "no encryption".

/// Number of table words (520 bytes).
const TABLE_WORDS: usize = 130;

/// Expanded VIE key.
#[derive(Clone)]
pub struct VieCipher {
    key: u32,
    table: [u32; TABLE_WORDS],
}

impl core::fmt::Debug for VieCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VieCipher")
            .field("key", &format_args!("{:#010x}", self.key))
            .finish()
    }
}

/// One step of the table generator: roughly `k * 16807 mod (2^31 - 1) + 123`
/// (Park-Miller via Schrage's method), folded back into the positive range.
///
/// Quirk: the quotient `k / 127773` is computed with a multiply-and-shift that
/// is exact for non-negative `k` but, for negative `k` (only possible for the
/// first step, when the session key has its top bit set), gives the floor minus
/// one rather than the truncated quotient. Servers derived from the original
/// behave this way, so it is reproduced exactly. Clients normally send a key with
/// the top bit set and receive its (positive) negation, which avoids the case.
fn next(k: i32) -> i32 {
    let mut q = ((i64::from(k) * 0x834E_0B5F) >> 48) as i32;
    q = q.wrapping_add(q >> 31);
    let mut k = (k % 127_773)
        .wrapping_mul(16_807)
        .wrapping_sub(q.wrapping_mul(2_836))
        .wrapping_add(123);
    if k <= 0 {
        k = k.wrapping_add(0x7FFF_FFFF);
    }
    k
}

impl VieCipher {
    /// Expands `key`. Returns `None` for key 0, which disables encryption.
    pub fn new(key: u32) -> Option<Self> {
        if key == 0 {
            return None;
        }
        let mut halves = [0u16; TABLE_WORDS * 2];
        let mut k = key as i32;
        for h in &mut halves {
            k = next(k);
            *h = k as u16;
        }
        let mut table = [0u32; TABLE_WORDS];
        for (t, pair) in table.iter_mut().zip(halves.as_chunks::<2>().0) {
            *t = u32::from(pair[0]) | u32::from(pair[1]) << 16;
        }
        Some(Self { key, table })
    }

    /// The session key.
    pub fn key(&self) -> u32 {
        self.key
    }

    /// The 520-byte keystream table (little-endian words), for diagnostics and
    /// test vectors.
    pub fn table_bytes(&self) -> [u8; 520] {
        let mut out = [0; 520];
        for (o, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(&self.table) {
            *o = w.to_le_bytes();
        }
        out
    }

    fn start(data: &[u8]) -> usize {
        if data.first() == Some(&0) { 2 } else { 1 }
    }

    fn table(&self, i: usize) -> u32 {
        // Datagrams never exceed 520 bytes, so i < 130 in practice.
        self.table[i % TABLE_WORDS]
    }

    /// Encrypts a datagram in place.
    pub fn encrypt(&self, data: &mut [u8]) {
        let start = Self::start(data);
        if data.len() <= start {
            return;
        }
        let mut work = self.key;
        for (i, chunk) in data[start..].chunks_mut(4).enumerate() {
            let mut w = [0u8; 4];
            w[..chunk.len()].copy_from_slice(chunk);
            work ^= u32::from_le_bytes(w) ^ self.table(i);
            chunk.copy_from_slice(&work.to_le_bytes()[..chunk.len()]);
        }
    }

    /// Decrypts a datagram in place.
    pub fn decrypt(&self, data: &mut [u8]) {
        let start = Self::start(data);
        if data.len() <= start {
            return;
        }
        let mut work = self.key;
        for (i, chunk) in data[start..].chunks_mut(4).enumerate() {
            let mut w = [0u8; 4];
            w[..chunk.len()].copy_from_slice(chunk);
            let c = u32::from_le_bytes(w);
            let p = c ^ work ^ self.table(i);
            work = c;
            chunk.copy_from_slice(&p.to_le_bytes()[..chunk.len()]);
        }
    }
}

/// Generates a client key the way VIE clients do: any value with the top bit set
/// (so the server's reply, the key negated, is positive). `seed` should be
/// unpredictable (e.g. from the clock or an RNG).
pub fn client_key_from_seed(seed: u32) -> u32 {
    let k = seed | 0x8000_0000;
    // Avoid the degenerate value whose negation is itself.
    if k == 0x8000_0000 { 0x8000_0001 } else { k }
}

/// The key a server answers a VIE `0x00 0x01` request with: the client key
/// negated.
pub fn server_key_for(client_key: u32) -> u32 {
    client_key.wrapping_neg()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn table_matches_reference() {
        let c = VieCipher::new(0x1234_5678).unwrap();
        assert_eq!(
            &c.table[..4],
            &[0x2561_ea19, 0x30ce_298e, 0x188c_539b, 0x6e89_d02d]
        );
        assert_eq!(c.table[129], 0xb042_b9ed);
    }

    /// Vectors generated from a literal model of the server-side reference
    /// behaviour (C integer semantics, including its whole-word processing of a
    /// trailing partial word).
    const VECTORS: &[(u32, &str, &str)] = &[
        (
            0x1234_5678,
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d",
            "0163bf5132eb91970b7ac9171e59168e610fe0c07babee4b73682be7f8",
        ),
        (
            0x0f0f_0f0f,
            "000300070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a1118",
            "0003f2a1d42e9c1ecb2936db4bf527ef46aab77fbb6fe06b6ab7f7823beb8865008c9166a7b5796d3fd73f",
        ),
        (0xdb97_5320, "000401020304", "0004f70c1b7c"),
        (0x0000_0001, "05", "05"),
        (0x0000_1000, "0007", "0007"),
    ];

    #[test]
    fn reference_vectors() {
        for &(key, p, c) in VECTORS {
            let cipher = VieCipher::new(key).unwrap();
            let mut buf = hex(p);
            cipher.encrypt(&mut buf);
            assert_eq!(buf, hex(c), "encrypt key {key:#x}");
            cipher.decrypt(&mut buf);
            assert_eq!(buf, hex(p), "decrypt key {key:#x}");
        }
    }

    #[test]
    fn max_size_packet_vector() {
        // 520-byte packet: type 0x0F then zeros, key 0x7fffffff. Check the start
        // and end of the ciphertext.
        let cipher = VieCipher::new(0x7FFF_FFFF).unwrap();
        let mut buf = vec![0u8; 520];
        buf[0] = 0x0F;
        cipher.encrypt(&mut buf);
        assert_eq!(buf[..8], hex("0f84ff47f4172274"));
        assert_eq!(buf[514..], hex("8d1536447e7f")[..]);
    }

    #[test]
    fn keys() {
        assert!(VieCipher::new(0).is_none());
        let ck = client_key_from_seed(0x1234);
        assert!(ck & 0x8000_0000 != 0);
        assert_eq!(server_key_for(ck) as i32, -(ck as i32));
    }
}
