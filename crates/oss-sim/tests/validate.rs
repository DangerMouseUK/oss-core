//! The plausibility checks against the simulation itself: whatever the real
//! physics does must pass, and the obvious cheats must not.

use oss_sim::*;

/// A walled box around the spawn area with pillars to bounce off and, if asked,
/// a wormhole in one corner.
fn arena_map(wormhole: bool) -> TileMap {
    let mut entries = Vec::new();
    let (lo, hi) = (480u16, 544u16);
    for i in lo..=hi {
        for (x, y) in [(i, lo), (i, hi), (lo, i), (hi, i)] {
            entries.push((x, y, 1));
        }
    }
    for y in (lo + 6..hi - 4).step_by(9) {
        for x in (lo + 6..hi - 4).step_by(11) {
            for (dx, dy) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
                entries.push((x + dx, y + dy, 1));
            }
        }
    }
    if wormhole {
        entries.push((lo + 2, lo + 2, tile::WORMHOLE));
    }
    TileMap::from_entries(entries).0
}

fn sample(w: &World, i: usize) -> Sample {
    let s = &w.ships[i];
    let (p, v) = (s.pos.pixels(), s.vel.to_wire());
    Sample {
        time: w.tick,
        x: p.x,
        y: p.y,
        x_speed: v.x,
        y_speed: v.y,
        rotation: s.direction(),
        status: s.toggles & 0x3f,
        energy: s.energy_points(),
    }
}

/// Deterministic pseudo-random numbers for inputs and packet gaps.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self, n: u32) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) % n as u64) as u32
    }
}

fn spent(events: &[Event], s: &ShipSettings) -> i32 {
    events
        .iter()
        .map(|e| match *e {
            Event::FiredGun {
                level, multifire, ..
            } => fire_cost(s, Fired::Bullet { level, multifire }),
            Event::FiredBomb { level, .. } => fire_cost(s, Fired::Bomb { level }),
            Event::LaidMine { level, .. } => fire_cost(s, Fired::Mine { level }),
            _ => 0,
        })
        .sum::<i32>()
        / 1000
}

/// Flies every ship type around the box with random inputs (thrust,
/// afterburner, turning, guns, bombs, mines, rockets, cloak and stealth),
/// samples it at random intervals as a lossy connection would, and checks every
/// pair of samples. Returns how many straight paths needed a detour.
fn fly(wormhole: bool, seed: u64) -> usize {
    let mut detours = 0;
    // Closest approach to each bound (own limits), printed for tuning.
    let mut closest = [0u32; 3];
    for kind in 0..8u8 {
        let settings = ArenaSettings::default();
        let mut w = World::new(arena_map(wormhole), settings.clone(), 7);
        w.prize_seed = 1234 + kind as u32;
        w.spawn_center = (512, 512);
        w.spawn_radius = 4;
        let i = w.add_ship(1, kind, 0);
        let ship = settings.ships[kind as usize];
        let any = Limits::new(&ship, &settings);
        // What a server tracks: the spawn loadout from the prize seed, then every
        // prize it hears of. It never sees items used, so counts only go up.
        let mut tracked = Loadout::spawn(&ship, &settings, 1234 + kind as u32);
        assert_eq!(tracked, Loadout::of(&w.ships[i]));
        let mut own = Limits::for_loadout(&ship, &settings, &tracked);
        let tiles = arena_map(wormhole);
        let map = MotionMap::new(&tiles);
        let tolerance = Tolerance::default();
        let mut rng = Lcg(seed ^ kind as u64);

        let mut input = ShipInput::default();
        let mut prev = sample(&w, i);
        let mut gap = 1;
        let mut since = 0;
        let mut fired = 0;
        let mut prized = false;
        let mut super_until = 0;
        let mut warped = false;
        for t in 0..6000 {
            if t % 25 == 0 {
                let r = rng.next(1 << 16);
                input = ShipInput {
                    forward: r & 3 != 0,
                    backward: r & 3 == 0,
                    left: r & 12 == 4,
                    right: r & 12 == 8,
                    afterburner: r & 16 != 0,
                    gun: r & 32 != 0,
                    bomb: r & 64 != 0,
                    mine: r & 0x380 == 0x80,
                    rocket: r & 0x7c00 == 0x400,
                    toggle_cloak: r & 0x1c00 == 0x800,
                    toggle_stealth: r & 0x1c00 == 0xc00,
                    ..ShipInput::default()
                };
            }
            let events = w.step(&[input]);
            // Shots are free under Super, which lasts up to `SuperTime`.
            if t >= super_until {
                fired += spent(&events, &ship);
            }
            // Greens: the server hears of each pickup, so it knows about full
            // charges, warps and upgrades.
            for e in &events {
                if let Event::PrizeTaken { prize, .. } = *e {
                    prized = true;
                    warped |= prize == Prize::Warp as i32;
                    if prize == Prize::Super as i32 {
                        super_until = t + ship.super_time;
                    }
                    // Multiprize's extra prizes arrive as prizes of their own.
                    if let Some(p) = Prize::from_id(prize.unsigned_abs().min(255) as u8) {
                        tracked.apply(&ship, p, prize < 0);
                    }
                }
            }
            since += 1;
            if since < gap {
                continue;
            }
            let next = sample(&w, i);
            let context = Context {
                spent: fired,
                refilled: prized,
                jumped: warped,
                ..Context::default()
            };
            if prized {
                // Upgrades take effect at once and downgrades a little later
                // (energy above a lowered maximum drains away), so a server
                // should keep the looser limits across a prize.
                let after = Limits::for_loadout(&ship, &settings, &tracked);
                own = Limits {
                    rotation: own.rotation.max(after.rotation),
                    max_energy: own.max_energy.max(after.max_energy),
                    recharge: own.recharge.max(after.recharge),
                    caps: own.caps | after.caps,
                    ..after
                };
            } else {
                own = Limits::for_loadout(&ship, &settings, &tracked);
            }
            for l in [&any, &own] {
                let v = check_motion(l, &map, &prev, &next, &context, &tolerance);
                assert!(
                    v.is_plausible(),
                    "ship {kind} tick {t}: {:?}\n{v:?}\n{prev:?}\n{next:?}",
                    v.worst()
                );
                detours += (v.wall == WallCheck::Detour) as usize;
                if core::ptr::eq(l, &own) && !v.wormhole && !warped {
                    let p = [v.distance_percent, v.speed_percent, v.rotation_percent];
                    for (c, p) in closest.iter_mut().zip(p) {
                        *c = (*c).max(p);
                    }
                }
            }
            prev = next;
            fired = 0;
            since = 0;
            prized = false;
            warped = false;
            // Mostly every 10 ticks (Continuum's rate when moving), sometimes a
            // burst of losses.
            gap = match rng.next(10) {
                0 => 1 + rng.next(150),
                1..=2 => 1 + rng.next(30),
                _ => 10,
            };
        }
    }
    eprintln!("seed {seed}: closest distance/speed/rotation % {closest:?}, {detours} detours");
    detours
}

#[test]
fn real_flight_is_plausible() {
    let detours = fly(false, 1) + fly(false, 2);
    assert!(detours > 0, "the tile search should have been exercised");
}

#[test]
fn real_flight_near_a_wormhole_is_plausible() {
    fly(true, 3);
}

/// Stock settings without rockets, so the engines' top speed is
/// `MaximumSpeed` (3250 px/10 s).
fn arena() -> ArenaSettings {
    let mut a = ArenaSettings::default();
    a.ships[0].rocket_max = 0;
    a
}

fn limits() -> Limits {
    let a = arena();
    Limits::new(&a.ships[0], &a)
}

fn at(time: u32, x: i32, y: i32) -> Sample {
    Sample {
        time,
        x,
        y,
        energy: 1000,
        ..Sample::default()
    }
}

fn check(map: &TileMap, prev: &Sample, next: &Sample, context: &Context) -> MotionVerdict {
    check_motion(
        &limits(),
        &MotionMap::new(map),
        prev,
        next,
        context,
        &Tolerance::default(),
    )
}

#[test]
fn speedhack_and_teleport_are_found() {
    let map = TileMap::empty();
    // Top speed 3250 + recoil 400 px/10 s: 36.5 px per tick at most. Ten ticks
    // (plus ten of tolerance) and 32 px of slack allow 105 px.
    let ok = check(
        &map,
        &at(0, 8000, 8000),
        &at(10, 8100, 8000),
        &Context::default(),
    );
    assert!(ok.is_plausible(), "{ok:?}");
    assert!(
        ok.distance_percent > 90 && ok.distance_percent <= 100,
        "{ok:?}"
    );

    let fast = check(
        &map,
        &at(0, 8000, 8000),
        &at(10, 8200, 8000),
        &Context::default(),
    );
    assert_eq!(
        fast.worst(),
        Some(Finding::Teleport {
            percent: 190,
            flash: false
        })
    );

    // The same jump is fine if the server moved the ship, or it was repelled at
    // 5000 px/10 s... only partly: 5400 px/10 s gives 140 px.
    let moved = Context {
        jumped: true,
        ..Context::default()
    };
    assert!(check(&map, &at(0, 8000, 8000), &at(10, 8200, 8000), &moved).is_plausible());
    let repelled = Context {
        repelled: true,
        ..Context::default()
    };
    let v = check(&map, &at(0, 8000, 8000), &at(10, 8130, 8000), &repelled);
    assert!(v.is_plausible(), "{v:?}");

    // Reported velocity: 3650 px/10 s times the bounce gain (BounceFactor 22
    // damps, so none) plus 10 %.
    let mut next = at(10, 8050, 8000);
    next.x_speed = 4000;
    assert!(check(&map, &at(0, 8000, 8000), &next, &Context::default()).is_plausible());
    next.x_speed = 6000;
    let v = check(&map, &at(0, 8000, 8000), &next, &Context::default());
    assert!(
        matches!(v.worst(), Some(Finding::Speed { percent: 149 })),
        "{v:?}"
    );

    // A warp is reported with its flash bit, for the server to judge.
    let mut warped = at(10, 3000, 3000);
    warped.status = STATUS_FLASH;
    let v = check(&map, &at(0, 8000, 8000), &warped, &Context::default());
    assert!(matches!(
        v.worst(),
        Some(Finding::Teleport { flash: true, .. })
    ));

    // A clock-skewing client gets no extra reach when the server caps elapsed
    // time.
    let capped = Context {
        max_ticks: Some(10),
        ..Context::default()
    };
    assert!(
        check(
            &map,
            &at(0, 8000, 8000),
            &at(1000, 9000, 8000),
            &Context::default()
        )
        .is_plausible()
    );
    assert!(!check(&map, &at(0, 8000, 8000), &at(1000, 9000, 8000), &capped).is_plausible());
}

#[test]
fn wormholes_explain_jumps() {
    let map = TileMap::from_entries([(500u16, 500u16, tile::WORMHOLE)]).0;
    // Next to the wormhole (centre tile 502, 502), then across the map.
    let v = check(
        &map,
        &at(0, 8040, 8040),
        &at(10, 1000, 15000),
        &Context::default(),
    );
    assert!(v.wormhole && v.is_plausible(), "{v:?}");
    // Far from it, the same jump is a teleport.
    let v = check(
        &map,
        &at(0, 4000, 4000),
        &at(10, 1000, 15000),
        &Context::default(),
    );
    assert!(!v.wormhole && !v.is_plausible(), "{v:?}");
}

fn wall_at_column(x: u16, gap: Option<(u16, u16)>) -> TileMap {
    let entries = (0..1024u16)
        .filter(|&y| gap.is_none_or(|(a, b)| y < a || y > b))
        .map(|y| (x, y, 1u8));
    TileMap::from_entries(entries).0
}

#[test]
fn passing_through_walls_is_found() {
    // A solid column at tile 500 (pixels 8000..8016).
    let map = wall_at_column(500, None);
    let v = check(
        &map,
        &at(0, 7980, 8000),
        &at(10, 8040, 8000),
        &Context::default(),
    );
    assert_eq!(v.wall, WallCheck::Blocked);
    assert_eq!(v.worst(), Some(Finding::ThroughWall));

    // With a gap three tiles away there is a way round within reach.
    let map = wall_at_column(500, Some((502, 503)));
    let v = check(
        &map,
        &at(0, 7980, 8000),
        &at(10, 8040, 8000),
        &Context::default(),
    );
    assert_eq!(v.wall, WallCheck::Detour);
    assert!(v.is_plausible());

    // Doors count as open.
    let map = TileMap::from_entries((0..1024u16).map(|y| (500, y, tile::FIRST_DOOR))).0;
    let v = check(
        &map,
        &at(0, 7980, 8000),
        &at(10, 8040, 8000),
        &Context::default(),
    );
    assert_eq!(v.wall, WallCheck::Clear);

    // Ending inside a wall.
    let map = wall_at_column(500, None);
    let v = check(
        &map,
        &at(0, 7980, 8000),
        &at(10, 8008, 8000),
        &Context::default(),
    );
    assert_eq!(v.worst(), Some(Finding::InsideWall));

    // A gap far outside the reachable distance doesn't help.
    let map = wall_at_column(500, Some((600, 601)));
    let v = check(
        &map,
        &at(0, 7980, 8000),
        &at(10, 8040, 8000),
        &Context::default(),
    );
    assert_eq!(v.wall, WallCheck::Blocked);
}

#[test]
fn energy_is_bounded() {
    let map = TileMap::empty();
    let a = arena();
    let l = limits();
    // Stock: 1700 max energy, 1150 points per 10 s at most (11.5 per tick).
    assert_eq!((l.max_energy, l.recharge), (1700, 1150));

    let mut prev = at(0, 8000, 8000);
    prev.energy = 500;
    let mut next = at(10, 8000, 8000);
    // 20 ticks with tolerance: up to 500 + 23 (+10).
    next.energy = 533;
    assert!(check(&map, &prev, &next, &Context::default()).is_plausible());
    next.energy = 600;
    let v = check(&map, &prev, &next, &Context::default());
    assert_eq!(
        v.worst(),
        Some(Finding::Energy {
            excess: 67,
            percent: 3
        })
    );
    // Above maximum, whatever the time.
    next.time = 100_000;
    next.energy = 1800;
    assert!(matches!(
        check(&map, &prev, &next, &Context::default()).worst(),
        Some(Finding::Energy { excess: 90, .. })
    ));

    // Firing is paid for: a ship that spent 600 points can't still have 500.
    next.time = 10;
    next.energy = 300;
    let fired = Context {
        spent: 600,
        ..Context::default()
    };
    assert!(!check(&map, &prev, &next, &fired).is_plausible());
    // ... nor fire 800 points' worth from 500 in 20 ticks.
    let v = energy_bounds(&l, 500, 20, 800, false);
    assert!(v.is_empty());
    // Unless it was refilled.
    let refilled = Context {
        spent: 800,
        refilled: true,
        ..Context::default()
    };
    next.energy = 900;
    assert!(check(&map, &prev, &next, &refilled).is_plausible());

    // Costs: stock bullets 20 points per level, bombs 150 + 150 per level.
    let s = &a.ships[0];
    assert_eq!(
        fire_cost(
            s,
            Fired::Bullet {
                level: 1,
                multifire: false
            }
        ),
        (s.bullet_fire_energy * 2 * 1000) as i32
    );
    assert_eq!(
        fire_cost(s, Fired::Bomb { level: 2 }),
        ((s.bomb_fire_energy + 2 * s.bomb_fire_energy_upgrade) * 1000) as i32
    );
}

#[test]
fn rotation_and_status_are_checked() {
    let map = TileMap::empty();
    let mut a = arena();
    a.ships[0].cloak_status = 0;
    a.ships[0].maximum_rotation = 200;
    let l = Limits::new(&a.ships[0], &a);
    let m = MotionMap::new(&map);
    let tol = Tolerance::default();
    let prev = at(0, 8000, 8000);

    // 200 = a fifth of a direction per tick: 20 ticks turn 4 (+1, +10 %).
    let mut next = at(10, 8000, 8000);
    next.rotation = 5;
    assert!(check_motion(&l, &m, &prev, &next, &Context::default(), &tol).is_plausible());
    next.rotation = 35; // also 5 the short way round
    assert!(check_motion(&l, &m, &prev, &next, &Context::default(), &tol).is_plausible());
    next.rotation = 15;
    let v = check_motion(&l, &m, &prev, &next, &Context::default(), &tol);
    assert!(
        matches!(v.worst(), Some(Finding::Rotation { percent: 300 })),
        "{v:?}"
    );

    next.rotation = 0;
    next.status = 0x02 | 0x20; // cloak, in a safe zone
    let v = check_motion(&l, &m, &prev, &next, &Context::default(), &tol);
    assert_eq!(v.worst(), Some(Finding::Status { bits: 0x02 }));
}

#[test]
fn loadout_matches_the_world() {
    let settings = ArenaSettings::default();
    for seed in [1u32, 777, 4242, 0xdead_beef] {
        for kind in 0..8u8 {
            let mut w = World::new(TileMap::empty(), settings.clone(), 1);
            w.prize_seed = seed;
            let i = w.add_ship(0, kind, 0);
            let s = &settings.ships[kind as usize];
            assert_eq!(
                Loadout::of(&w.ships[i]),
                Loadout::spawn(s, &settings, seed),
                "seed {seed} ship {kind}"
            );
        }
    }
    // Prizes move stats within their ranges.
    let s = &settings.ships[0];
    let mut l = Loadout::initial(s);
    for _ in 0..100 {
        l.apply(s, Prize::TopSpeed, false);
    }
    assert_eq!(l.stats.speed, s.maximum_speed);
    assert_eq!(
        l.apply(s, Prize::FullCharge, false),
        PrizeEffect::FullCharge
    );
    assert_eq!(l.apply(s, Prize::Repel, true), PrizeEffect::None);
}

/// Many more random flights; run with `cargo test --release -- --ignored`.
#[test]
#[ignore]
fn many_flights_are_plausible() {
    for seed in 10..110 {
        fly(seed % 2 == 0, seed);
    }
}
