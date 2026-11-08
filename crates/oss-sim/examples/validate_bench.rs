//! Times `check_motion`: `cargo run --release -p oss-sim --example validate_bench`.
//!
//! Records a ship flying around a walled box with pillars, then checks every
//! pair of consecutive 10-tick samples many times over, plus the slow path: a
//! straight path through a wall that needs the tile search to find a way round.

use std::hint::black_box;
use std::time::Instant;

use oss_sim::*;

fn main() {
    let mut entries = Vec::new();
    for i in 480u16..=544 {
        for (x, y) in [(i, 480), (i, 544), (480, i), (544, i)] {
            entries.push((x, y, 1u8));
        }
    }
    for y in (486u16..540).step_by(9) {
        for x in (486u16..540).step_by(11) {
            entries.push((x, y, 1));
            entries.push((x + 1, y, 1));
        }
    }
    let tiles = TileMap::from_entries(entries).0;
    let settings = ArenaSettings::default();
    let mut w = World::new(tiles.clone(), settings.clone(), 3);
    w.prize_seed = 0;
    w.spawn_center = (512, 512);
    w.spawn_radius = 4;
    let i = w.add_ship(1, 0, 0);

    let mut samples = Vec::new();
    for t in 0..20_000u32 {
        let input = ShipInput {
            forward: true,
            afterburner: t % 700 < 200,
            left: t % 300 < 40,
            gun: t % 50 == 0,
            ..ShipInput::default()
        };
        w.step(&[input]);
        if t % 10 == 0 {
            let s = &w.ships[i];
            let (p, v) = (s.pos.pixels(), s.vel.to_wire());
            samples.push(Sample {
                time: w.tick,
                x: p.x,
                y: p.y,
                x_speed: v.x,
                y_speed: v.y,
                rotation: s.direction(),
                status: s.toggles & 0x3f,
                energy: s.energy_points(),
            });
        }
    }

    let start = Instant::now();
    let map = MotionMap::new(&tiles);
    println!("MotionMap::new: {:?} (once per map)", start.elapsed());

    let limits = Limits::new(&settings.ships[0], &settings);
    let tolerance = Tolerance::default();
    let context = Context::new(u32::MAX);
    let mut implausible = 0;
    let mut detours = 0;
    let rounds = 200;
    let start = Instant::now();
    for _ in 0..rounds {
        for pair in samples.windows(2) {
            let v = check_motion(
                black_box(&limits),
                &map,
                &pair[0],
                &pair[1],
                &context,
                &tolerance,
            );
            implausible += !v.is_plausible() as usize;
            detours += (v.wall == WallCheck::Detour) as usize;
        }
    }
    let calls = rounds * (samples.len() - 1);
    let per = start.elapsed().as_nanos() as f64 / calls as f64;
    println!(
        "check_motion, recorded flight: {per:.0} ns/call over {calls} calls \
         ({implausible} implausible, {} detours per round)",
        detours / rounds
    );

    // The slow path: through a pillar, with a way round.
    let prev = Sample {
        time: 0,
        x: 486 * 16 - 20,
        y: 486 * 16 + 8,
        energy: 1000,
        ..Sample::default()
    };
    let next = Sample {
        time: 10,
        x: 488 * 16 + 20,
        ..prev
    };
    let n = 200_000;
    let start = Instant::now();
    let mut wall = WallCheck::Clear;
    for _ in 0..n {
        wall = check_motion(&limits, &map, black_box(&prev), &next, &context, &tolerance).wall;
    }
    let per = start.elapsed().as_nanos() as f64 / n as f64;
    println!("check_motion, path through a wall: {per:.0} ns/call ({wall:?})");

    // 500 players at 10 packets/s, as if every check took the slow path.
    let budget = 5_000.0 * per / 1e9 * 100.0;
    println!("if all 5000 checks/s took that path: {budget:.2}% of a core");
}
