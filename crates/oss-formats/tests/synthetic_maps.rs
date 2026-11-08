//! Map checksum vectors for synthetic maps.
//!
//! The maps are generated here by a port of the seeded generator that produced
//! the vectors (splitmix64; algorithm described in the vectors' README). Each
//! regenerated file is checked against the recorded size and CRC-32 before its
//! checksums are compared, so the port and the vectors cannot drift apart
//! silently. `smallmap.lvl` (the reference server's default map) is a committed
//! fixture with its own vectors.

use std::collections::HashSet;

use oss_formats::Level;
use oss_proto::checksum::{crc32, map_checksum};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn size_of(t: u32) -> u32 {
    match t {
        217 => 2,
        219 => 6,
        220 => 5,
        _ => 1,
    }
}

fn rec(out: &mut Vec<u8>, x: u32, y: u32, t: u32) {
    out.extend_from_slice(&((x & 0xFFF) | (y & 0xFFF) << 12 | (t & 0xFF) << 24).to_le_bytes());
}

/// Rejection-samples `count` non-overlapping, in-range objects.
fn place(
    rng: &mut Rng,
    occ: &mut HashSet<(u32, u32)>,
    count: usize,
    ylo: u32,
    yspan: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut placed = 0;
    while placed < count {
        let x = rng.below(1024) as u32;
        let y = ylo + rng.below(yspan) as u32;
        let t = 1 + rng.below(220) as u32;
        let s = size_of(t);
        if x + s > 1024 || y + s > 1024 {
            continue;
        }
        let cells: Vec<(u32, u32)> = (0..s)
            .flat_map(|i| (0..s).map(move |j| (x + i, y + j)))
            .collect();
        if cells.iter().any(|c| occ.contains(c)) {
            continue;
        }
        occ.extend(cells);
        rec(&mut out, x, y, t);
        placed += 1;
    }
    out
}

fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut v = kind.to_vec();
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v.extend_from_slice(data);
    v.resize(v.len() + (4 - data.len() % 4) % 4, 0);
    v
}

fn map_a() -> Vec<u8> {
    let (mut rng, mut occ) = (Rng(0x5EED_0001), HashSet::new());
    place(&mut rng, &mut occ, 3000, 0, 1024)
}

fn map_b() -> Vec<u8> {
    let mut out = Vec::new();
    for x in 0..1024 {
        rec(&mut out, x, 0, 1 + (x * 7) % 216);
    }
    for x in 0..1024 {
        rec(&mut out, x, 1023, 1 + (x * 5) % 216);
    }
    for y in 1..1023 {
        rec(&mut out, 0, y, 1 + (y * 11) % 216);
    }
    for y in 1..1023 {
        rec(&mut out, 1023, y, 1 + (y * 13) % 216);
    }
    for i in 1..172 {
        rec(&mut out, i + 100, i + 100, i);
    }
    rec(&mut out, 1017, 500, 219);
    rec(&mut out, 1, 1, 220);
    rec(&mut out, 1021, 1021, 217);
    rec(&mut out, 1024, 10, 1);
    rec(&mut out, 4095, 4095, 255);
    out
}

fn map_c() -> Vec<u8> {
    let (mut rng, mut occ) = (Rng(0x5EED_0003), HashSet::new());
    let mut palette = Vec::new();
    for _ in 0..256 {
        let (r, g, b) = (
            rng.below(256) as u8,
            rng.below(256) as u8,
            rng.below(256) as u8,
        );
        palette.extend_from_slice(&[r, g, b, 0]);
    }
    let pixels: Vec<u8> = (0..304 * 160).map(|_| rng.below(256) as u8).collect();
    let tset: Vec<u8> = (0..64).map(|_| rng.below(256) as u8).collect();
    let tile_chunk_tiles = place(&mut rng, &mut occ, 400, 0, 500);
    let plain_tiles = place(&mut rng, &mut occ, 1500, 512, 500);
    // Region: x 100..150, rows 100..110.
    let rle = [0xA0, 99, 0x20, 99, 0x60, 49, 0x23, 0x69, 0xC8, 0xA3, 0x91];
    let mut regn = chunk(b"rNAM", b"spawnzone");
    regn.extend(chunk(b"rTIL", &rle));
    let mut chunks = chunk(b"ATTR", b"NAME=Synthetic C");
    chunks.extend(chunk(b"ATTR", b"VERSION=1"));
    chunks.extend(chunk(b"REGN", &regn));
    chunks.extend(chunk(b"TSET", &tset));
    chunks.extend(chunk(b"TILE", &tile_chunk_tiles));
    chunks.extend(chunk(b"XTRA", b"12345"));
    let mut meta = b"elvl".to_vec();
    meta.extend_from_slice(&(12 + chunks.len() as u32).to_le_bytes());
    meta.extend_from_slice(&0u32.to_le_bytes());
    meta.extend(chunks);

    let mut info = Vec::new();
    for v in [40u32, 304, 160] {
        info.extend_from_slice(&v.to_le_bytes());
    }
    info.extend_from_slice(&1u16.to_le_bytes());
    info.extend_from_slice(&8u16.to_le_bytes());
    for v in [0u32, 304 * 160, 0, 0, 256, 0] {
        info.extend_from_slice(&v.to_le_bytes());
    }
    let meta_off = 14 + 40 + 1024 + 304 * 160;
    let fsize = meta_off + meta.len() as u32;
    let mut out = b"BM".to_vec();
    for v in [fsize, meta_off, 14 + 40 + 1024] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend(info);
    out.extend(palette);
    out.extend(pixels);
    out.extend(meta);
    out.extend(plain_tiles);
    out
}

fn map_d() -> Vec<u8> {
    let mut out = Vec::new();
    rec(&mut out, 1020, 1020, 219);
    rec(&mut out, 1022, 0, 220);
    rec(&mut out, 1023, 512, 217);
    rec(&mut out, 5, 5, 1);
    out
}

fn generate(name: &str) -> Vec<u8> {
    match name {
        "synth-a-plain.lvl" => map_a(),
        "synth-b-edges.lvl" => map_b(),
        "synth-c-elvl.lvl" => map_c(),
        "synth-d-overflow.lvl" => map_d(),
        "smallmap.lvl" => include_bytes!("fixtures/smallmap.lvl").to_vec(),
        other => panic!("no generator for {other}"),
    }
}

/// Checks every map in a vector file whose map can be produced here; returns
/// the number of checksums verified.
fn check(text: &str, only: Option<&str>) -> usize {
    let mut current = None;
    let mut checked = 0;
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f[0] {
            "map" => {
                // Real-map records carry an extra path field; read from the end.
                let n = f.len();
                let name = f[n - 3];
                if only.is_some_and(|o| o != name) {
                    current = None;
                    continue;
                }
                let data = generate(name);
                assert_eq!(
                    data.len(),
                    f[n - 2].parse::<usize>().unwrap(),
                    "{name} size"
                );
                assert_eq!(
                    crc32(&data),
                    u32::from_str_radix(f[n - 1], 16).unwrap(),
                    "{name} crc32"
                );
                let lvl = Level::parse(&data).unwrap();
                assert_eq!(lvl.to_bytes(), data, "{name} rewrites byte for byte");
                current = Some((lvl, name.to_string()));
            }
            "tiles" => {
                if let Some((lvl, name)) = &current {
                    let (_, stats) = lvl.server_tile_grid();
                    let want: Vec<usize> = f[1..4].iter().map(|v| v.parse().unwrap()).collect();
                    assert_eq!(
                        [stats.non_empty, stats.turf_flags, stats.out_of_range],
                        want[..],
                        "{name} tile stats"
                    );
                }
            }
            "checksum" => {
                if let Some((lvl, name)) = &current {
                    let (grid, _) = lvl.server_tile_grid();
                    let key = u32::from_str_radix(f[1], 16).unwrap();
                    let want = u32::from_str_radix(f[2], 16).unwrap();
                    let got = map_checksum(key, |x, y| grid.get(x as u32, y as u32));
                    assert_eq!(got, want, "{name} key {key:#x}");
                    checked += 1;
                }
            }
            other => panic!("unknown record {other}"),
        }
    }
    checked
}

#[test]
fn synthetic_map_vectors() {
    let n = check(include_str!("vectors/map-checksum-synthetic.txt"), None);
    assert_eq!(n, 132);
}

#[test]
fn smallmap_vectors() {
    let n = check(
        include_str!("vectors/map-checksum.txt"),
        Some("smallmap.lvl"),
    );
    assert_eq!(n, 33);
}

#[test]
fn synthetic_elvl_contents() {
    let lvl = Level::parse(&map_c()).unwrap();
    let meta = lvl.metadata.as_ref().unwrap();
    assert_eq!(meta.attribute("NAME"), Some("Synthetic C"));
    let region = meta.regions().next().unwrap();
    assert_eq!(region.name(), Some("spawnzone"));
    let tiles = region.tiles().unwrap();
    assert_eq!(tiles.count(), 50 * 10);
    assert!(tiles.contains(100, 100) && tiles.contains(149, 109) && !tiles.contains(150, 100));
}

/// The generated maps are also published as conformance inputs
/// (`crates/oss-conformance/vectors/synth-*.lvl`), so implementations in other
/// languages can check their map checksum without porting the generator.
/// Regenerate with `OSS_REGEN_VECTORS=1`; skipped when the conformance crate is
/// not alongside.
#[test]
fn conformance_map_files_are_current() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../oss-conformance/vectors");
    let regen = std::env::var_os("OSS_REGEN_VECTORS").is_some();
    if !regen && !std::path::Path::new(dir).exists() {
        eprintln!("skipped: {dir} not present");
        return;
    }
    for name in [
        "synth-a-plain.lvl",
        "synth-b-edges.lvl",
        "synth-c-elvl.lvl",
        "synth-d-overflow.lvl",
    ] {
        let path = format!("{dir}/{name}");
        let bytes = generate(name);
        if regen {
            std::fs::write(&path, &bytes).unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{name} is stale");
    }
}
