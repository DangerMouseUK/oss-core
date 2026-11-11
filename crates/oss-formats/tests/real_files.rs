//! Round-trips real map files from local directories that are never committed.
//!
//! Set `OSS_MAP_DIRS` to one or more directories (separated by `;` on Windows or
//! `:` elsewhere); every `.lvl` (and `.lvz`) found under them is parsed and
//! rewritten. Without the variable the test does nothing.

use std::path::{Path, PathBuf};

use oss_formats::{Level, Lvz};

fn collect(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, ext, out);
        } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case(ext)) {
            out.push(p);
        }
    }
}

fn files(ext: &str) -> Vec<PathBuf> {
    let Some(dirs) = std::env::var_os("OSS_MAP_DIRS") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for d in std::env::split_paths(&dirs) {
        collect(&d, ext, &mut out);
    }
    out
}

#[test]
fn lvl_files_round_trip() {
    for path in files("lvl") {
        let data = std::fs::read(&path).unwrap();
        let lvl = Level::parse(&data).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let grid = lvl.tile_grid();
        let used = grid.cells().iter().filter(|&&t| t != 0).count();
        let mut regions = 0;
        if let Some(m) = &lvl.metadata {
            for r in m.regions() {
                let t = r
                    .tiles()
                    .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                assert_eq!(oss_formats::RegionBitmap::decode(&t.encode()).unwrap(), t);
                regions += 1;
            }
            for c in &m.chunks {
                if let oss_formats::Chunk::Other { kind, .. } = c {
                    println!("  other chunk {:?}", String::from_utf8_lossy(kind));
                }
            }
        }
        println!(
            "{}: tileset={} meta={} regions={regions} tiles={} grid={used}",
            path.display(),
            lvl.tileset.is_some(),
            lvl.metadata.is_some(),
            lvl.tiles.len()
        );
        assert!(
            lvl.to_bytes() == data,
            "{}: rewrite differs",
            path.display()
        );
    }
}

#[test]
fn lvz_files_round_trip() {
    for path in files("lvz") {
        let data = std::fs::read(&path).unwrap();
        let lvz = Lvz::parse(&data).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut objects = 0;
        let mut refused = 0;
        for s in &lvz.sections {
            let d = s
                .data()
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            if s.is_object_section() {
                let o = oss_formats::ObjectSection::parse_with_clv1(&d)
                    .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                // A CLV1 screen object reaches a caller only through
                // parse_with_clv1; the plain parser must still refuse it, so that
                // CLV2-shaped code can never be handed one.
                if o.layout() == oss_formats::ObjectLayout::Clv1
                    && o.objects.iter().any(|d| !d.is_map_object())
                {
                    let e = oss_formats::ObjectSection::parse(&d).unwrap_err();
                    assert!(
                        matches!(e, oss_formats::FormatError::Unsupported { .. }),
                        "{}: plain parse should refuse CLV1 screen objects, got {e}",
                        path.display()
                    );
                    println!("{}: CLV1 screen objects: {e}", path.display());
                    refused += 1;
                }
                assert_eq!(
                    o.to_bytes(),
                    d,
                    "{}: object section rewrite",
                    path.display()
                );
                objects += o.objects.len();
            }
        }
        println!(
            "{}: sections={} objects={objects} clv1_screen_sections={refused}",
            path.display(),
            lvz.sections.len()
        );
        assert!(
            lvz.to_bytes() == data,
            "{}: rewrite differs",
            path.display()
        );
    }
}
