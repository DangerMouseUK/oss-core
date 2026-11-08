#![no_main]
//! `.lvl` maps with eLVL metadata, eLVL sections on their own, and region
//! bitmaps. Whatever parses must rewrite and parse back to the same value.

use libfuzzer_sys::fuzz_target;
use oss_core_fuzz::assert_stable;
use oss_formats::{Chunk, Level, Metadata, RegionBitmap};

fn check_metadata(meta: &Metadata) {
    assert_stable(meta, Metadata::to_bytes, |b| {
        Metadata::parse(b).map(|(m, _)| m)
    });
    for region in meta.regions() {
        let _ = region.name();
        let _ = region.auto_warp();
        if let Ok(bitmap) = region.tiles() {
            assert_stable(&bitmap, RegionBitmap::encode, RegionBitmap::decode);
        }
    }
    for chunk in &meta.chunks {
        let _ = chunk.kind();
        if let Chunk::Attribute { .. } = chunk {
            let _ = meta.attributes().count();
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, data)) = data.split_first() else {
        return;
    };
    match which % 4 {
        // Building the 1 MiB grids is slow, so only one mode in four does it.
        0 | 3 => {
            if let Ok(level) = Level::parse(data) {
                assert_stable(&level, Level::to_bytes, Level::parse);
                if which % 4 == 3 {
                    let grid = level.tile_grid();
                    let (server, stats) = level.server_tile_grid();
                    // Expansion only adds cells: every tile in the plain grid is set
                    // in the server grid too.
                    let set =
                        |g: &oss_formats::TileGrid| g.cells().iter().filter(|&&t| t != 0).count();
                    assert!(set(&grid) <= stats.non_empty);
                    assert_eq!(set(&server), stats.non_empty);
                }
                if let Some(meta) = &level.metadata {
                    check_metadata(meta);
                }
            }
        }
        1 => {
            if let Ok((meta, len)) = Metadata::parse(data) {
                assert!(len <= data.len());
                check_metadata(&meta);
            }
        }
        _ => {
            if let Ok(bitmap) = RegionBitmap::decode(data) {
                assert_stable(&bitmap, RegionBitmap::encode, RegionBitmap::decode);
                assert_eq!(bitmap.iter().count(), bitmap.count());
            }
        }
    }
});
