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
                ..Context::new(u32::MAX)
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
        &Context::new(u32::MAX),
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
        &Context::new(u32::MAX),
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
        ..Context::new(u32::MAX)
    };
    assert!(check(&map, &at(0, 8000, 8000), &at(10, 8200, 8000), &moved).is_plausible());
    let repelled = Context {
        repelled: true,
        ..Context::new(u32::MAX)
    };
    let v = check(&map, &at(0, 8000, 8000), &at(10, 8130, 8000), &repelled);
    assert!(v.is_plausible(), "{v:?}");

    // Reported velocity: 3650 px/10 s times the bounce gain (BounceFactor 22
    // damps, so none) plus 10 %.
    let mut next = at(10, 8050, 8000);
    next.x_speed = 4000;
    assert!(check(&map, &at(0, 8000, 8000), &next, &Context::new(u32::MAX)).is_plausible());
    next.x_speed = 6000;
    let v = check(&map, &at(0, 8000, 8000), &next, &Context::new(u32::MAX));
    assert!(
        matches!(v.worst(), Some(Finding::Speed { percent: 149 })),
        "{v:?}"
    );

    // A warp is reported with its flash bit, for the server to judge.
    let mut warped = at(10, 3000, 3000);
    warped.status = STATUS_FLASH;
    let v = check(&map, &at(0, 8000, 8000), &warped, &Context::new(u32::MAX));
    assert!(matches!(
        v.worst(),
        Some(Finding::Teleport { flash: true, .. })
    ));

    // A clock-skewing client gets no extra reach when the server caps elapsed
    // time.
    let capped = Context {
        max_ticks: 10,
        ..Context::new(u32::MAX)
    };
    assert!(
        check(
            &map,
            &at(0, 8000, 8000),
            &at(1000, 9000, 8000),
            &Context::new(u32::MAX)
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
        &Context::new(u32::MAX),
    );
    assert!(v.wormhole && v.is_plausible(), "{v:?}");
    // Far from it, the same jump is a teleport.
    let v = check(
        &map,
        &at(0, 4000, 4000),
        &at(10, 1000, 15000),
        &Context::new(u32::MAX),
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
        &Context::new(u32::MAX),
    );
    assert_eq!(v.wall, WallCheck::Blocked);
    assert_eq!(v.worst(), Some(Finding::ThroughWall));

    // With a gap three tiles away there is a way round within reach.
    let map = wall_at_column(500, Some((502, 503)));
    let v = check(
        &map,
        &at(0, 7980, 8000),
        &at(10, 8040, 8000),
        &Context::new(u32::MAX),
    );
    assert_eq!(v.wall, WallCheck::Detour);
    assert!(v.is_plausible());

    // Doors count as open.
    let map = TileMap::from_entries((0..1024u16).map(|y| (500, y, tile::FIRST_DOOR))).0;
    let v = check(
        &map,
        &at(0, 7980, 8000),
        &at(10, 8040, 8000),
        &Context::new(u32::MAX),
    );
    assert_eq!(v.wall, WallCheck::Clear);

    // Ending inside a wall.
    let map = wall_at_column(500, None);
    let v = check(
        &map,
        &at(0, 7980, 8000),
        &at(10, 8008, 8000),
        &Context::new(u32::MAX),
    );
    assert_eq!(v.worst(), Some(Finding::InsideWall));

    // A gap far outside the reachable distance doesn't help.
    let map = wall_at_column(500, Some((600, 601)));
    let v = check(
        &map,
        &at(0, 7980, 8000),
        &at(10, 8040, 8000),
        &Context::new(u32::MAX),
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
    assert!(check(&map, &prev, &next, &Context::new(u32::MAX)).is_plausible());
    next.energy = 600;
    let v = check(&map, &prev, &next, &Context::new(u32::MAX));
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
        check(&map, &prev, &next, &Context::new(u32::MAX)).worst(),
        Some(Finding::Energy { excess: 90, .. })
    ));

    // Firing is paid for: a ship that spent 600 points can't still have 500.
    next.time = 10;
    next.energy = 300;
    let fired = Context {
        spent: 600,
        ..Context::new(u32::MAX)
    };
    assert!(!check(&map, &prev, &next, &fired).is_plausible());
    // ... nor fire 800 points' worth from 500 in 20 ticks.
    let v = energy_bounds(&l, 500, 20, 800, false);
    assert!(v.is_empty());
    // Unless it was refilled.
    let refilled = Context {
        spent: 800,
        refilled: true,
        ..Context::new(u32::MAX)
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
    assert!(check_motion(&l, &m, &prev, &next, &Context::new(u32::MAX), &tol).is_plausible());
    next.rotation = 35; // also 5 the short way round
    assert!(check_motion(&l, &m, &prev, &next, &Context::new(u32::MAX), &tol).is_plausible());
    next.rotation = 15;
    let v = check_motion(&l, &m, &prev, &next, &Context::new(u32::MAX), &tol);
    assert!(
        matches!(v.worst(), Some(Finding::Rotation { percent: 300 })),
        "{v:?}"
    );

    next.rotation = 0;
    next.status = 0x02 | 0x20; // cloak, in a safe zone
    let v = check_motion(&l, &m, &prev, &next, &Context::new(u32::MAX), &tol);
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

/// A packet as the server sees it: the sample and the server tick it arrived.
struct Arrival {
    sample: Sample,
    at: u32,
}

/// Flies a ship and delivers a position packet every 10 ticks over a bad
/// connection: 2–30 ticks of latency, 8 % loss, 2 % duplicates, and lag spikes
/// that hold packets for up to 1.5 s and then deliver them in a burst.
fn deliver(seed: u64, ticks: u32) -> (Vec<Arrival>, ArenaSettings) {
    let settings = ArenaSettings::default();
    let mut w = World::new(arena_map(false), settings.clone(), 5);
    w.prize_seed = 0;
    w.spawn_center = (512, 512);
    w.spawn_radius = 4;
    let i = w.add_ship(1, 0, 0);
    let mut rng = Lcg(seed);
    let mut out = Vec::new();
    let mut input = ShipInput::default();
    let mut spike_until = 0u32;
    for t in 0..ticks {
        if t % 30 == 0 {
            let r = rng.next(1 << 8);
            input = ShipInput {
                forward: r & 3 != 0,
                afterburner: r & 4 != 0,
                left: r & 24 == 8,
                right: r & 24 == 16,
                ..ShipInput::default()
            };
        }
        w.step(&[input]);
        if t % 10 != 0 {
            continue;
        }
        let sample = sample(&w, i);
        let now = w.tick;
        if spike_until <= now && rng.next(100) < 2 {
            spike_until = now + 50 + rng.next(100);
        }
        if rng.next(100) < 8 {
            continue; // lost
        }
        let mut at = now + 2 + rng.next(29);
        if at < spike_until {
            at = spike_until + rng.next(3);
        }
        out.push(Arrival { sample, at });
        if rng.next(100) < 2 {
            out.push(Arrival {
                sample,
                at: at + rng.next(5),
            });
        }
    }
    out.sort_by_key(|a| a.at); // stable: equal arrivals keep send order
    (out, settings)
}

/// Checks packets in arrival order the way a server would: against the last
/// in-order packet, with elapsed time capped by a [`ClientClock`], and, when
/// `anchor_ticks` is set, also against the newest packet at least that old.
/// Returns every finding.
fn serve(
    arrivals: &[Arrival],
    settings: &ArenaSettings,
    tiles: &TileMap,
    anchor_ticks: Option<u32>,
) -> Vec<Finding> {
    let map = MotionMap::new(tiles);
    let limits = Limits::new(&settings.ships[0], settings);
    let tolerance = Tolerance::default();
    let mut clock = ClientClock::default();
    let mut prev: Option<Sample> = None;
    let mut anchors: Vec<Sample> = Vec::new();
    let mut findings = Vec::new();
    for a in arrivals {
        let next = a.sample;
        let Some(p) = prev else {
            clock.observe(next.time, a.at);
            prev = Some(next);
            anchors.push(next);
            continue;
        };
        let mut check = |from: &Sample| {
            let context = Context {
                max_ticks: clock.max_ticks(from.time, a.at, 30),
                ..Context::new(u32::MAX)
            };
            let v = check_motion(&limits, &map, from, &next, &context, &tolerance);
            findings.extend(v.findings());
        };
        check(&p);
        if let Some(span) = anchor_ticks
            && let Some(old) = anchors
                .iter()
                .rev()
                .find(|s| next.time.wrapping_sub(s.time) as i32 >= span as i32)
        {
            check(old);
        }
        clock.observe(next.time, a.at);
        if next.time.wrapping_sub(p.time) as i32 > 0 {
            prev = Some(next);
            anchors.push(next);
        }
    }
    findings
}

#[test]
fn a_bad_connection_is_plausible() {
    for seed in 0..20 {
        let (arrivals, settings) = deliver(seed, 6000);
        assert!(
            arrivals
                .windows(2)
                .any(|w| w[1].sample.time < w[0].sample.time),
            "the test should include reordering"
        );
        let found = serve(&arrivals, &settings, &arena_map(false), Some(100));
        assert!(found.is_empty(), "seed {seed}: {found:?}");
    }
}
#[test]
fn the_clock_guard_stops_a_timestamp_jump_from_excusing_a_teleport() {
    let a = arena();
    let limits = Limits::new(&a.ships[0], &a);
    let empty = TileMap::empty();
    let map = MotionMap::new(&empty);
    let tol = Tolerance::default();
    let mut clock = ClientClock::default();
    // Honest packets every 10 ticks, arriving 5 ticks after they're sent.
    let mut prev = at(0, 8000, 8000);
    clock.observe(prev.time, 5);
    for k in 1..=5u32 {
        let next = at(10 * k, 8000 + 30 * k as i32, 8000);
        let cap = clock.max_ticks(prev.time, 10 * k + 5, 30);
        let context = Context {
            max_ticks: cap,
            ..Context::new(u32::MAX)
        };
        assert!(check_motion(&limits, &map, &prev, &next, &context, &tol).is_plausible());
        clock.observe(next.time, 10 * k + 5);
        prev = next;
    }
    // The cheat moves 1000 px and claims 300 extra ticks to explain it.
    let cheat = at(prev.time + 310, prev.x + 1000, 8000);
    let trusting = check_motion(&limits, &map, &prev, &cheat, &Context::new(u32::MAX), &tol);
    assert!(trusting.is_plausible(), "the timestamp alone excuses it");
    let guarded = Context {
        max_ticks: clock.max_ticks(prev.time, 65, 30),
        ..Context::new(u32::MAX)
    };
    let v = check_motion(&limits, &map, &prev, &cheat, &guarded, &tol);
    assert!(
        matches!(v.worst(), Some(Finding::Teleport { percent, .. }) if percent > 300),
        "{v:?}"
    );
}

#[test]
fn a_late_burst_after_a_lag_spike_is_not_limited() {
    let a = arena();
    let limits = Limits::new(&a.ships[0], &a);
    let empty = TileMap::empty();
    let map = MotionMap::new(&empty);
    let mut clock = ClientClock::default();
    clock.observe(0, 5);
    let prev = at(0, 8000, 8000);
    // Sent 150 ticks later at top speed, but delivered after a 2 s stall, in
    // the same tick as several others: the server's own clock says almost no
    // time has passed since the last delivery, but the client's is right.
    let next = at(150, 8000 + 480, 8000);
    let cap = clock.max_ticks(prev.time, 205, 30);
    assert!(cap >= 150);
    let v = check_motion(
        &limits,
        &map,
        &prev,
        &next,
        &Context {
            max_ticks: cap,
            ..Context::new(u32::MAX)
        },
        &Tolerance::default(),
    );
    assert!(v.is_plausible(), "{v:?}");
}

#[test]
fn a_moderate_speedhack_shows_over_a_second_not_per_packet() {
    let a = arena();
    let limits = Limits::new(&a.ships[0], &a);
    let empty = TileMap::empty();
    let map = MotionMap::new(&empty);
    let tol = Tolerance::default();
    // 1.5x the afterburner top speed (3250 px/10 s), honestly timestamped.
    let fly = |t: u32| at(t, 4000 + (t * 4875 / 1000) as i32, 8000);
    let check = |from: u32, to: u32| {
        check_motion(
            &limits,
            &map,
            &fly(from),
            &fly(to),
            &Context::new(u32::MAX),
            &tol,
        )
    };
    assert!(
        (0..100)
            .step_by(10)
            .all(|t| check(t, t + 10).is_plausible())
    );
    assert!(matches!(
        check(0, 100).worst(),
        Some(Finding::Teleport { .. })
    ));
}

/// A ship flown in the real world: `before` ticks idle at (x, y), then the
/// inputs of `act` for one tick, then `after` idle ticks. Returns the samples
/// either side, with the flash bit only on the second (Continuum sends it on
/// the first packet after a warp), and the world.
fn around(act: ShipInput, setup: impl FnOnce(&mut World)) -> (Sample, Sample, World) {
    let settings = arena();
    let mut w = World::new(TileMap::empty(), settings, 9);
    w.prize_seed = 0;
    w.add_ship(1, 0, 0);
    setup(&mut w);
    for _ in 0..10 {
        w.step(&[ShipInput::default()]);
    }
    let mut prev = sample(&w, 0);
    prev.status &= !STATUS_FLASH;
    w.step(&[act]);
    for _ in 0..9 {
        w.step(&[ShipInput::default()]);
    }
    let mut next = sample(&w, 0);
    next.status |= STATUS_FLASH;
    (prev, next, w)
}

fn judge(w: &World, prev: &Sample, next: &Sample, context: &Context) -> MotionVerdict {
    let a = &w.settings;
    let limits = Limits::new(&a.ships[0], a);
    check_motion(
        &limits,
        &MotionMap::new(&w.map),
        prev,
        next,
        context,
        &Tolerance::default(),
    )
}

#[test]
fn an_honest_warp_to_spawn_is_explained_by_its_energy() {
    let warp = ShipInput {
        warp: true,
        ..ShipInput::default()
    };
    let (prev, next, w) = around(warp, |w| {
        w.ships[0].pos = Pos::from_pixels(14000, 3000);
    });
    assert!(
        next.energy < 50 && prev.x == 14000,
        "the warp happened: {next:?}"
    );
    let v = judge(&w, &prev, &next, &Context::new(u32::MAX));
    assert!(v.flash_explained && v.is_plausible(), "{v:?}");
}

#[test]
fn an_honest_portal_jump_needs_the_server_to_know_of_the_portal() {
    let portal = ShipInput {
        portal: true,
        ..ShipInput::default()
    };
    let warp = ShipInput {
        warp: true,
        ..ShipInput::default()
    };
    // Place a portal at one spot, then warp to it from another.
    let settings = arena();
    let mut w = World::new(TileMap::empty(), settings, 9);
    w.prize_seed = 0;
    w.add_ship(1, 0, 0);
    w.ships[0].items.portals = 1;
    w.ships[0].pos = Pos::from_pixels(4000, 4000);
    w.step(&[portal]);
    for _ in 0..5 {
        w.step(&[ShipInput::default()]);
    }
    w.ships[0].pos = Pos::from_pixels(12000, 12000);
    for _ in 0..10 {
        w.step(&[ShipInput::default()]);
    }
    let prev = sample(&w, 0);
    w.step(&[warp]);
    let mut next = sample(&w, 0);
    next.status |= STATUS_FLASH;
    assert!(
        (next.x - 4000).abs() < 20,
        "the portal jump happened: {next:?}"
    );
    // Full energy remains, so it doesn't look like a warp to spawn.
    let v = judge(&w, &prev, &next, &Context::new(u32::MAX));
    assert!(matches!(
        v.worst(),
        Some(Finding::Teleport { flash: true, .. })
    ));
    assert!(v.worst().unwrap().severity() >= 100);
    let held = Context {
        portal_held: true,
        ..Context::new(u32::MAX)
    };
    assert!(judge(&w, &prev, &next, &held).is_plausible());
}

#[test]
fn a_pinned_flash_bit_lightens_nothing() {
    let wall = TileMap::from_entries((0..1024u16).map(|y| (500u16, y, 1u8))).0;
    let map = MotionMap::new(&wall);
    let l = limits();
    let tol = Tolerance::default();
    let ctx = Context::new(u32::MAX);
    // A short hop through a wall, with and without the flash bit: the same
    // finding and weight (review round 7, V2).
    let prev = at(0, 7980, 8000);
    let mut next = at(10, 8040, 8000);
    let honest = check_motion(&l, &map, &prev, &next, &ctx, &tol);
    next.status = STATUS_FLASH;
    let flashed = check_motion(&l, &map, &prev, &next, &ctx, &tol);
    assert_eq!(honest.worst(), Some(Finding::ThroughWall));
    assert_eq!(flashed.worst(), Some(Finding::ThroughWall));
    assert!(!flashed.flash_explained);
    // A long jump with the flash bit but energy to spare is no warp to spawn.
    let far = Sample {
        status: STATUS_FLASH,
        ..at(10, 2000, 2000)
    };
    let v = check_motion(
        &l,
        &MotionMap::new(&TileMap::empty()),
        &prev,
        &far,
        &ctx,
        &tol,
    );
    let worst = v.worst().unwrap();
    assert!(matches!(worst, Finding::Teleport { flash: true, .. }));
    assert!(worst.severity() >= 100);
}
