//! Mutation smoke test: parsers must return errors, never panic, on corrupt input.

use oss_formats::{Chunk, Level, Metadata, Region, RegionBitmap, TileEntry, Tileset};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn seed_level() -> Vec<u8> {
    let mut bmp = vec![0u8; 1078 + 16];
    bmp[..2].copy_from_slice(b"BM");
    let mut tiles = RegionBitmap::new();
    for x in 0..50 {
        tiles.set(x, x, true);
    }
    Level {
        tileset: Some(Tileset { bytes: bmp }),
        metadata: Some(Metadata {
            reserved: 0,
            chunks: vec![
                Chunk::Attribute {
                    key: "NAME".into(),
                    value: "fuzz".into(),
                },
                Chunk::Region(Region::new("r", &tiles)),
            ],
        }),
        tiles: (0..20)
            .map(|i| TileEntry {
                x: i,
                y: i * 3,
                tile: i as u8,
            })
            .collect(),
        trailing: vec![],
    }
    .to_bytes()
}

#[test]
fn mutated_levels_do_not_panic() {
    let seed = seed_level();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..3000 {
        let mut d = seed.clone();
        for _ in 0..(rng.next() % 8 + 1) {
            let i = (rng.next() as usize) % d.len();
            d[i] = rng.next() as u8;
        }
        if rng.next().is_multiple_of(4) {
            d.truncate((rng.next() as usize) % d.len());
        }
        if let Ok(l) = Level::parse(&d) {
            let _ = l.tile_grid();
            if let Some(m) = &l.metadata {
                for r in m.regions() {
                    let _ = r.tiles();
                }
            }
            let _ = l.to_bytes();
        }
        // Also feed the metadata section and region codec directly.
        let _ = Metadata::parse(&d[d.len().min(1080)..]);
        let _ = RegionBitmap::decode(&d[d.len().min(1100)..]);
    }
}
