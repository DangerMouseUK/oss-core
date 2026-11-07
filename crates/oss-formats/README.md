# oss-formats

SubSpace content formats, part of [Open SubSpace](https://github.com/DangerMouseUK/oss-core):

- `.lvl` maps, with the tileset bitmap and eLVL metadata (attributes, regions);
- `.lvz` archives, with object definitions;
- `.ossr` replays.

Parsers take `&[u8]` and never panic on malformed input. Writers reproduce well-formed files byte for byte. The crate is `no_std` + `alloc`.

```rust
use oss_formats::Level;

let lvl = Level::default(); // or Level::parse(&std::fs::read("map.lvl")?)?
let (grid, _) = lvl.server_tile_grid();
assert_eq!(grid.get(512, 512), 0);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Format notes (CC BY 4.0) are in [`docs/formats`](https://github.com/DangerMouseUK/oss-core/tree/main/docs/formats).

Licence: MIT.
