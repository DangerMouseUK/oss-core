//! Checksums used by the game protocol.
//!
//! * [`crc32`]: standard CRC-32 (IEEE, as in zlib). Used for file checksums in
//!   the map/news file-name packets.
//! * [`position_checksum`]: XOR of a position packet's bytes.
//! * [`settings_checksum`], [`map_checksum`], [`map_crc32`], [`vie_exe_checksum`]:
//!   the values a client reports in its security response (C2S `0x1A`) for a key
//!   chosen by the server.
//!
//! The settings, map, map-CRC and VIE exe checksum algorithms follow nullspace
//! (`src/null/net/security/Checksum.cpp`, `src/null/Map.cpp`; MIT licence,
//! Copyright (c) 2021 plushmonkey), re-expressed in Rust.

const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = make_crc_table();

/// Continues a CRC-32 computation (`crc` is the previous result, 0 to start).
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c = CRC_TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// Standard CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0, data)
}

/// XOR of all bytes; position and weapon packets carry this in their checksum
/// byte (computed with the checksum byte set to 0).
pub fn position_checksum(data: &[u8]) -> u8 {
    data.iter().fold(0, |a, &b| a ^ b)
}

/// Settings checksum: the sum of `word ^ key` over the settings packet read as
/// little-endian `u32` words (1428 bytes = 357 words, type byte included).
pub fn settings_checksum(key: u32, settings_packet: &[u8]) -> u32 {
    let (words, _) = settings_packet.as_chunks::<4>();
    words.iter().fold(0u32, |sum, w| {
        sum.wrapping_add(u32::from_le_bytes(*w) ^ key)
    })
}

/// Whether a tile type counts towards [`map_checksum`] and [`map_crc32`]: normal
/// tiles 1-160 and the safe-zone tile 171.
pub fn counts_for_map_checksum(tile: u8) -> bool {
    (1..=160).contains(&tile) || tile == 171
}

/// Map checksum for the security response.
///
/// Samples every 31st column and 32nd row, starting at offsets derived from the
/// key, and adds `key ^ tile` for each counted tile. The key is treated as a
/// signed integer, so for keys with the top bit set the start offsets are
/// negative; like the reference server, coordinates then wrap modulo 1024, so
/// `tile(x, y)` is always called with `0 <= x, y < 1024`. Big map objects must
/// already be expanded into the grid (see `oss_formats::Level::server_tile_grid`).
pub fn map_checksum(key: u32, mut tile: impl FnMut(i32, i32) -> u8) -> u32 {
    let base = key as i32;
    let mut sum = key;
    let mut y = base % 32;
    while y < 1024 {
        let mut x = base % 31;
        while x < 1024 {
            let t = tile(x & 1023, y & 1023);
            if counts_for_map_checksum(t) {
                sum = sum.wrapping_add(key ^ u32::from(t));
            }
            x += 31;
        }
        y += 32;
    }
    sum
}

/// CRC over the dense 1024x1024 tile grid (row-major) as reported by Continuum
/// clients: only tiles 1-160 and 171 contribute, initial value `0xFFFFFFFF`, no
/// final inversion.
pub fn map_crc32(grid: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &t in grid {
        if counts_for_map_checksum(t) {
            crc = (crc >> 8) ^ CRC_TABLE[((crc & 0xFF) ^ u32::from(t)) as usize];
        }
    }
    crc
}

/// One group of the VIE exe checksum: a start value, then alternating
/// `+= (add | key)` and `^= (xor ^ key)` steps.
type Group = (u32, &'static [(u32, u32)]);

const VIE_GROUPS: [Group; 7] = [
    (
        0xc98e_d41f,
        &[
            (0x0003_e1bc, 0x4243_5942),
            (0x1d89_5300, 0x6b5c_4032),
            (0x0046_7e44, 0x516c_7eda),
            (0x8b0c_708b, 0x6b3e_3429),
            (0x5606_74c9, 0xf4e6_b721),
            (0xe90c_c483, 0x80ec_e15a),
            (0x728b_ce33, 0x1fc5_d1e6),
            (0x8b0c_518b, 0x24f1_a96e),
            (0x030a_e0c1, 0x8858_741b),
        ],
    ),
    (
        0x9c15_857d,
        &[(0x0424_448b, 0xcd04_55ee), (0x0000_0727, 0x8d7f_29cd)],
    ),
    (
        0x824b_9278,
        &[
            (0x0000_6590, 0x8e16_169a),
            (0x8b52_4914, 0x82dc_e03a),
            (0xfa83_d733, 0xb095_5349),
            (0xe800_0003, 0x7cfe_3604),
        ],
    ),
    (
        0xe3f8_d2af,
        &[(0x2de8_5024, 0xbed0_296b), (0x5875_01f8, 0xada7_0f65)],
    ),
    (
        0xcb54_d8a0,
        &[
            (0x0f00_0001, 0x330f_19ff),
            (0x9090_90c3, 0xd20f_9f9f),
            (0x5300_4add, 0x5d81_256b),
            (0x8b00_4b65, 0xa531_2749),
            (0xb800_4b67, 0x8adf_8fb1),
            (0x8901_e283, 0x8ec9_4507),
            (0x89d2_3300, 0x1ff8_e1dc),
            (0x108a_004a, 0xc73d_6304),
            (0x0043_d2d3, 0x6f78_e4ff),
        ],
    ),
    (
        0x045c_23f9,
        &[
            (0x47d8_6097, 0x7cb5_88bd),
            (0x0000_9286, 0x21d7_00f8),
            (0xdf8e_0fd9, 0x4279_6c9e),
            (0x8b00_0003, 0x3ad3_2a21),
        ],
    ),
    (0xb229_a3d0, &[(0x0047_d708, 0x010b_0a91)]),
];

fn vie_group(key: u32, (start, steps): Group) -> u32 {
    steps.iter().fold(start, |part, &(add, xor)| {
        part.wrapping_add(add | key) ^ xor ^ key
    })
}

/// The executable checksum a VIE (SubSpace 1.34/1.35) client reports for `key`.
pub fn vie_exe_checksum(key: u32) -> u32 {
    let mut csum = VIE_GROUPS
        .iter()
        .fold(0u32, |c, &g| c.wrapping_add(vie_group(key, g)));
    // The eighth group ends with an add and an xor that leaves the key out.
    let last: Group = (
        0x466e_55a7,
        &[
            (0xc788_0d8b, 0x44ce_7067),
            (0x0000_00e4, 0x923a_6d44),
            (0x6400_47d6, 0xa62d_606c),
            (0x2bd1_f7ae, 0x2f56_21fb),
        ],
    );
    let part = vie_group(key, last).wrapping_add(0x8b0f_74ff | key) ^ 0x2928_b332;
    csum = csum.wrapping_add(part);
    csum.wrapping_add(0x62cf_369a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_standard_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
        assert_eq!(crc32_update(crc32(b"1234"), b"56789"), 0xCBF4_3926);
    }

    #[test]
    fn position_checksum_xor() {
        assert_eq!(position_checksum(&[0x03, 0x10, 0x01]), 0x12);
    }

    #[test]
    fn settings_checksum_sums_words() {
        let data = [1, 0, 0, 0, 2, 0, 0, 0];
        assert_eq!(settings_checksum(0, &data), 3);
        assert_eq!(settings_checksum(1, &data), 3);
        assert_eq!(
            settings_checksum(0xFFFF_FFFF, &data),
            0xFFFF_FFFEu32.wrapping_add(0xFFFF_FFFD)
        );
    }

    #[test]
    fn map_checksum_samples_grid() {
        // Empty map: the checksum is the key.
        assert_eq!(map_checksum(12345, |_, _| 0), 12345);
        // One counted tile at a sampled position (key 33: x from 2, y from 1).
        let key = 33u32;
        let at = |t| move |x, y| if (x, y) == (2, 1) { t } else { 0 };
        assert_eq!(map_checksum(key, at(5)), key + (key ^ 5));
        assert_eq!(map_checksum(key, at(170)), key);
        assert_eq!(map_checksum(key, at(171)), key + (key ^ 171));
        assert_eq!(
            map_checksum(key, |x, y| if (x, y) == (3, 1) { 5 } else { 0 }),
            key
        );
        // Keys with the top bit set start at negative offsets, which wrap.
        let mut seen = (1024, 1024, 0, 0);
        map_checksum(0x8000_0001, |x, y| {
            seen = (seen.0.min(x), seen.1.min(y), seen.2.max(x), seen.3.max(y));
            0
        });
        assert!(seen.0 >= 0 && seen.1 >= 0 && seen.2 < 1024 && seen.3 < 1024);
        // 0x80000001 as i32 % 31 == -1, so column 1023 is sampled first.
        let c = map_checksum(0x8000_0001, |x, _| u8::from(x == 1023));
        assert_ne!(c, 0x8000_0001);
    }

    #[test]
    fn map_crc32_filters_tiles() {
        let mut g = [0u8; 8];
        assert_eq!(map_crc32(&g), 0xFFFF_FFFF);
        g[3] = 1;
        let one = map_crc32(&g);
        g[5] = 0xA1; // ignored
        assert_eq!(map_crc32(&g), one);
        g[6] = 0xAB; // counted
        assert_ne!(map_crc32(&g), one);
    }

    #[test]
    fn vie_exe_checksum_vectors() {
        // Vectors from a straight transcription of the reference C routine.
        for &(key, want) in VIE_VECTORS {
            assert_eq!(vie_exe_checksum(key), want, "key {key:#x}");
        }
    }

    const VIE_VECTORS: &[(u32, u32)] = &[
        (0x0000_0000, 0x281c_c948),
        (0x0000_0001, 0x281d_1a69),
        (0x1234_5678, 0xaaf3_6798),
        (0xdead_beef, 0x7463_a3cf),
        (0xffff_ffff, 0x92fe_563f),
        (0x7fff_ffff, 0x92fe_563f),
    ];
}
