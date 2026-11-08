//! Plausibility checks for a server: could a ship legitimately have gone from one
//! reported state to the next?
//!
//! A server sees only a sample of each player's position packets, some late,
//! some lost. Rather than stepping the simulation, these checks bound what any
//! input sequence could have done in the elapsed time: the furthest a ship could
//! travel, the fastest it could be moving, how far it could turn, how much energy
//! it could have, and whether it had to pass through a wall to get there. Every
//! bound errs on the side of the player, because a false positive is worse than a
//! miss. The verdict says how far past each bound a sample was, so a trust score
//! can weigh it.
//!
//! The checks are integer-only and deterministic, so a finding can be reproduced
//! from a log, and allocate nothing. A call takes about 0.15 µs on the common
//! path; a sample whose straight path crosses a wall pays about 1.5 µs more for a
//! bounded tile search (see `examples/validate_bench.rs`). The tests fly every
//! ship type through walls, pillars and a wormhole with random inputs and lossy
//! sampling, and require every real sample to pass.
//!
//! Typical use, per player:
//!
//! 1. When the player enters a ship, build [`Limits`] for it (from settings, or
//!    tighter from a tracked [`Loadout`](crate::Loadout)), and once per map a
//!    [`MotionMap`].
//! 2. For each accepted position packet, call [`check_motion`] with the previous
//!    accepted [`Sample`], the new one and a [`Context`] saying what the server
//!    knows happened in between (a respawn, weapons fired).
//! 3. Feed [`MotionVerdict::findings`] into the trust score.

#![warn(missing_docs)]

use core::ops::RangeInclusive;

use crate::fixed::isqrt;
use crate::loadout::Loadout;
use crate::map::{MAP_TILES, TileMap, is_solid_id, tile};
use crate::settings::{ArenaSettings, ShipSettings};
use crate::ship::cap;

/// Position packet status bits a ship needs the matching capability for:
/// stealth, cloak, X-radar and antiwarp (the same bit values as [`cap`]).
pub const CAPABILITY_STATUS: u8 = cap::STEALTH | cap::CLOAK | cap::XRADAR | cap::ANTIWARP;

/// The `FLASH` status bit: set when a ship warps, portals or uncloaks.
pub const STATUS_FLASH: u8 = 0x10;

/// The most a ship of one type can do, in settings units. Build once per player
/// per ship change (or loadout change) and reuse.
///
/// Fields are public so a server can tighten or loosen them, e.g. drop
/// `gravity_speed` on a map without wormholes (which [`check_motion`] already
/// does) or raise `speed` for an arena module that pushes ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Top speed in pixels per 10 seconds from the ship's own engines: the
    /// higher of `MaximumSpeed` (afterburners) and `Misc:RocketSpeed` when the
    /// ship can have rockets, plus a positive `Flag:FlaggerSpeedAdjustment`.
    pub speed: u32,
    /// `Repel:Speed`: the top speed while repelled, counted when
    /// [`Context::repelled`] says so.
    pub repel_speed: u32,
    /// `GravityTopSpeed` when the ship type has `Gravity`; only counted on maps
    /// with wormholes.
    pub gravity_speed: u32,
    /// `BombThrust` when the ship can have bombs: firing one pushes it back past
    /// its top speed for a tick.
    pub recoil: u32,
    /// How much a wall bounce can multiply velocity, in 1/256 (256 = no gain).
    /// Above 256 only when `Misc:BounceFactor` is below 16; two bounces in one
    /// tick (a corner) are included.
    pub bounce_gain: u32,
    /// Rotation in settings units (1000 = one of 40 directions per tick).
    pub rotation: u32,
    /// Maximum energy in points.
    pub max_energy: i32,
    /// Recharge in points per 10 seconds.
    pub recharge: u32,
    /// [`cap`] bits the ship may have; only the [`CAPABILITY_STATUS`] ones are
    /// checked against reported status.
    pub caps: u8,
}

impl Limits {
    /// Limits for any loadout of this ship type: upgraded maxima, every
    /// capability its `*Status` settings allow.
    pub fn new(ship: &ShipSettings, arena: &ArenaSettings) -> Self {
        let mut caps = 0;
        for (status, bit) in [
            (ship.stealth_status, cap::STEALTH),
            (ship.cloak_status, cap::CLOAK),
            (ship.xradar_status, cap::XRADAR),
            (ship.anti_warp_status, cap::ANTIWARP),
        ] {
            if status > 0 {
                caps |= bit;
            }
        }
        let rockets = ship.rocket_max > 0 || ship.initial_rocket > 0;
        let mut speed = ship.maximum_speed.max(ship.initial_speed);
        if rockets {
            speed = speed.max(arena.rocket_speed);
        }
        speed = speed.saturating_add(arena.flagger.speed_adjustment.max(0) as u32);
        let bombs = ship.max_bombs > 0 || ship.initial_bombs > 0;
        let bounce = arena.bounce_factor.clamp(1, 16);
        Self {
            speed,
            repel_speed: arena.repel_speed,
            gravity_speed: if ship.gravity != 0 {
                ship.gravity_top_speed
            } else {
                0
            },
            recoil: if bombs { ship.bomb_thrust } else { 0 },
            bounce_gain: 256 * 16 * 16 / (bounce * bounce),
            rotation: ship.maximum_rotation.max(ship.initial_rotation),
            max_energy: ship.maximum_energy.max(ship.initial_energy) as i32,
            recharge: ship.maximum_recharge.max(ship.initial_recharge),
            caps: caps | cap::MULTIFIRE | cap::BOUNCING_BULLETS | cap::PROXIMITY,
        }
    }

    /// Tighter limits for a ship whose [`Loadout`] the server tracks: its own
    /// rotation, maximum energy, recharge and capabilities, and rocket speed
    /// only if it holds rockets. Engine speed stays at `MaximumSpeed`, which
    /// afterburners reach whatever the loadout.
    ///
    /// The server can't see a rocket being used, so it should not decrement
    /// rockets; if it does, it must keep these limits for `RocketTime` after the
    /// last one goes.
    pub fn for_loadout(ship: &ShipSettings, arena: &ArenaSettings, loadout: &Loadout) -> Self {
        let mut speed = ship.maximum_speed.max(ship.initial_speed);
        if loadout.items.rockets > 0 {
            speed = speed.max(arena.rocket_speed);
        }
        Self {
            speed: speed.saturating_add(arena.flagger.speed_adjustment.max(0) as u32),
            rotation: loadout.stats.rotation,
            max_energy: loadout.stats.max_energy as i32,
            recharge: loadout.stats.recharge,
            caps: loadout.caps,
            ..Self::new(ship, arena)
        }
    }
}

/// Most wormholes a [`MotionMap`] records.
const MAX_WORMHOLES: usize = 64;

/// The map facts the checks need, built once per map.
#[derive(Debug, Clone)]
pub struct MotionMap<'a> {
    map: &'a TileMap,
    /// Centre tiles of wormholes (at most [`MotionMap::MAX_WORMHOLES`]).
    wormholes: [(i16, i16); MAX_WORMHOLES],
    wormhole_count: usize,
}

impl<'a> MotionMap<'a> {
    /// Wormholes beyond this many are ignored (every jump is then assumed to be
    /// explainable, see [`MotionMap::new`]).
    pub const MAX_WORMHOLES: usize = MAX_WORMHOLES;

    /// Scans the map for wormholes (one pass over its tiles). A map with more
    /// than [`MotionMap::MAX_WORMHOLES`] wormholes makes every jump count as a
    /// possible wormhole trip.
    pub fn new(map: &'a TileMap) -> Self {
        let mut wormholes = [(0, 0); MAX_WORMHOLES];
        let mut count = 0;
        let cells = map.cells();
        for (i, &id) in cells.iter().enumerate() {
            if id != tile::WORMHOLE {
                continue;
            }
            let (x, y) = ((i % MAP_TILES) as i32, (i / MAP_TILES) as i32);
            // Objects are stored expanded; the top-left tile marks the object.
            if map.get(x - 1, y) == tile::WORMHOLE || map.get(x, y - 1) == tile::WORMHOLE {
                continue;
            }
            if count == Self::MAX_WORMHOLES {
                count = usize::MAX;
                break;
            }
            wormholes[count] = ((x + 2) as i16, (y + 2) as i16);
            count += 1;
        }
        Self {
            map,
            wormholes,
            wormhole_count: count,
        }
    }

    /// The tile map.
    pub fn map(&self) -> &TileMap {
        self.map
    }

    /// Whether the map has wormholes (so gravity and wormhole jumps apply).
    pub fn has_wormholes(&self) -> bool {
        self.wormhole_count > 0
    }

    /// Whether a wormhole's centre is within `pixels` of pixel (x, y).
    fn wormhole_near(&self, x: i32, y: i32, pixels: i64) -> bool {
        if self.wormhole_count == usize::MAX {
            return true;
        }
        let reach = pixels + 3 * 16;
        self.wormholes[..self.wormhole_count]
            .iter()
            .any(|&(wx, wy)| {
                let (dx, dy) = (
                    (wx as i64 * 16 + 8 - x as i64),
                    (wy as i64 * 16 + 8 - y as i64),
                );
                dx * dx + dy * dy <= reach * reach
            })
    }
}

/// One reported ship state, in wire units (as in a C2S position packet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sample {
    /// The client's timestamp, in ticks (1/100 s); wraps.
    pub time: u32,
    /// Position of the ship's centre in pixels.
    pub x: i32,
    /// Position of the ship's centre in pixels.
    pub y: i32,
    /// Velocity in pixels per 10 seconds.
    pub x_speed: i32,
    /// Velocity in pixels per 10 seconds.
    pub y_speed: i32,
    /// Direction, 0..40 (values of 40 and above are taken modulo 40).
    pub rotation: u8,
    /// Status bits (stealth, cloak, X-radar, antiwarp, flash, safe zone, UFO).
    pub status: u8,
    /// Energy in points.
    pub energy: i32,
}

/// How much slack to allow for timing and rounding. The defaults suit a client
/// on an ordinary connection; widen them for high-latency players rather than
/// ignoring findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tolerance {
    /// Ticks added to the elapsed time (timestamp jitter, the tick a packet was
    /// sampled in).
    pub ticks: u32,
    /// Pixels added to the reachable distance.
    pub pixels: u32,
    /// Percent added to speed and rotation limits.
    pub percent: u32,
    /// Energy points added to the energy bound.
    pub energy: i32,
}

impl Default for Tolerance {
    fn default() -> Self {
        Self {
            ticks: 10,
            pixels: 32,
            percent: 10,
            energy: 10,
        }
    }
}

/// What the server knows happened between two samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Context {
    /// The ship legitimately jumped: respawn, ship or frequency change, a
    /// `?warpto`, attaching to or detaching from a turret, or anything else the
    /// server moved it for. Skips the distance and wall checks.
    pub jumped: bool,
    /// The ship may have been repelled (an enemy repel went off within
    /// `Repel:Distance` of it within the last `Repel:Time` ticks), so it may
    /// have moved at `Repel:Speed`.
    pub repelled: bool,
    /// Energy was refilled: respawn, ship change, a full-charge prize or a
    /// positive capability prize the arena doesn't allow (which gives a full
    /// charge instead).
    pub refilled: bool,
    /// Energy points spent on weapons the server saw fired after `prev` up to and
    /// including `next` (see [`fire_cost`](crate::fire_cost); divide its
    /// milli-points by 1000). Leave out shots fired within `SuperTime` ticks of
    /// a Super prize: weapons are free while it lasts, for a random time below
    /// that.
    pub spent: i32,
    /// Caps the elapsed time taken from the client's timestamps. A server that
    /// passes its own elapsed ticks plus some slack stops a client from widening
    /// every bound by skewing its clock; `None` trusts the timestamps (and leaves
    /// clock checks to the caller).
    pub max_ticks: Option<u32>,
}

/// The result of [`check_motion`]: how each quantity compares with its bound
/// (tolerance included). Percentages are of the bound, so 100 is at the limit
/// and anything above is implausible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MotionVerdict {
    /// Elapsed ticks the bounds were computed for (tolerance included).
    pub ticks: u32,
    /// Distance travelled, as a percentage of the furthest reachable.
    pub distance_percent: u32,
    /// Reported speed, as a percentage of the fastest possible.
    pub speed_percent: u32,
    /// Change of direction, as a percentage of the most the ship could turn.
    pub rotation_percent: u32,
    /// What the path between the two positions crosses.
    pub wall: WallCheck,
    /// A wormhole was within reach, which explains a jump.
    pub wormhole: bool,
    /// The new sample has the flash bit (warp, portal or uncloak).
    pub flash: bool,
    /// Capability status bits set without the capability.
    pub illegal_status: u8,
    /// Energy points above the most the ship could have; 0 if within.
    pub energy_excess: i32,
    /// `energy_excess` as a percentage of maximum energy.
    pub energy_excess_percent: u32,
}

/// What the straight path between two samples crosses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WallCheck {
    /// Nothing solid on the straight path.
    #[default]
    Clear,
    /// The straight path crosses a wall, but there is a way around within reach.
    Detour,
    /// No path within reach avoids walls.
    Blocked,
    /// The new position is inside a solid tile.
    Inside,
    /// Not checked: the ship jumped, or the search area was too small to decide
    /// (counts as plausible).
    Unchecked,
}

/// One implausible aspect of a sample, from [`MotionVerdict::findings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finding {
    /// The ship got further than it could have; `flash` if the sample had the
    /// flash bit, as after a warp or portal, which the server may choose to
    /// accept after its own checks.
    Teleport {
        /// Distance as a percentage of the reachable distance.
        percent: u32,
        /// The sample had the flash bit.
        flash: bool,
    },
    /// Reported velocity faster than the ship can go.
    Speed {
        /// Speed as a percentage of the fastest possible.
        percent: u32,
    },
    /// Turned faster than the ship can.
    Rotation {
        /// Turn as a percentage of the most possible.
        percent: u32,
    },
    /// Got from one side of a wall to the other with no way around in reach.
    ThroughWall,
    /// The ship's centre is inside a solid tile.
    InsideWall,
    /// More energy than the ship could have.
    Energy {
        /// Points above the bound.
        excess: i32,
        /// Excess as a percentage of maximum energy.
        percent: u32,
    },
    /// Stealth, cloak, X-radar or antiwarp on without the capability.
    Status {
        /// The offending status bits.
        bits: u8,
    },
}

impl Finding {
    /// A rough weight for a trust score: percentage points over the limit for
    /// the measured findings, 100 for a wall pass or illegal status, 200 for a
    /// ship inside a wall.
    pub fn severity(&self) -> u32 {
        match *self {
            Finding::Teleport { percent, .. }
            | Finding::Speed { percent }
            | Finding::Rotation { percent } => percent.saturating_sub(100),
            Finding::Energy { percent, .. } => percent.max(1),
            Finding::ThroughWall | Finding::Status { .. } => 100,
            Finding::InsideWall => 200,
        }
    }
}

impl MotionVerdict {
    /// Every implausible aspect, in no particular order. Empty when plausible.
    pub fn findings(&self) -> impl Iterator<Item = Finding> + use<> {
        let teleport = (self.distance_percent > 100 && !self.wormhole)
            || (self.flash && self.wall == WallCheck::Blocked);
        let found = [
            teleport.then_some(Finding::Teleport {
                percent: self.distance_percent,
                flash: self.flash,
            }),
            (self.speed_percent > 100).then_some(Finding::Speed {
                percent: self.speed_percent,
            }),
            (self.rotation_percent > 100).then_some(Finding::Rotation {
                percent: self.rotation_percent,
            }),
            (self.wall == WallCheck::Blocked && !self.flash).then_some(Finding::ThroughWall),
            (self.wall == WallCheck::Inside).then_some(Finding::InsideWall),
            (self.energy_excess > 0).then_some(Finding::Energy {
                excess: self.energy_excess,
                percent: self.energy_excess_percent,
            }),
            (self.illegal_status != 0).then_some(Finding::Status {
                bits: self.illegal_status,
            }),
        ];
        found.into_iter().flatten()
    }

    /// Whether nothing was implausible.
    pub fn is_plausible(&self) -> bool {
        self.findings().next().is_none()
    }

    /// The most severe finding, if any.
    pub fn worst(&self) -> Option<Finding> {
        self.findings().max_by_key(Finding::severity)
    }
}

/// The range of energy (points) a ship can report after `ticks`, having had
/// `prev_energy` and spent `spent` points on weapons since. The upper bound is
/// the most it could have if it fired first and recharged after, capped at
/// maximum energy; the lower bound is 0, since damage, afterburners and toggles
/// (cloak, stealth, X-radar, antiwarp) can drain any amount the server doesn't
/// see. The range is empty when the ship could not have afforded `spent`.
/// With `refilled` (respawn, full charge) the bound is maximum energy, since
/// shots may have come before the refill.
pub fn energy_bounds(
    limits: &Limits,
    prev_energy: i32,
    ticks: u32,
    spent: i32,
    refilled: bool,
) -> RangeInclusive<i32> {
    let max = limits.max_energy as i64;
    if refilled {
        return 0..=max.clamp(0, i32::MAX as i64) as i32;
    }
    let start = (prev_energy as i64).clamp(0, max);
    let gained = limits.recharge as i64 * ticks as i64 / 1000;
    let hi = (start + gained - spent.max(0) as i64).min(max);
    0..=hi.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// Checks whether a ship could have gone from `prev` to `next`.
///
/// Elapsed time comes from the samples' client timestamps (wrapping; a sample
/// older than `prev` counts as no time at all), capped by
/// [`Context::max_ticks`], plus [`Tolerance::ticks`].
///
/// - **Distance**: the ship moves at most `speed` (or `gravity_speed` on maps
///   with wormholes, or `repel_speed` when [`Context::repelled`]) plus `recoil`
///   per tick. A longer jump is a teleport unless a
///   wormhole was in reach or the context says the ship jumped.
/// - **Speed**: reported velocity at most that, times the bounce gain.
/// - **Rotation**: `rotation / 1000` directions per tick, except across a jump.
/// - **Walls**: closed doors and bricks count as open, because the server may not
///   know their state. If the straight path crosses a wall, a bounded tile search
///   looks for a way around within the reachable distance.
/// - **Energy**: see [`energy_bounds`].
/// - **Status**: capability bits ([`CAPABILITY_STATUS`]) need the capability.
///   UFO and the other bits are not checked.
pub fn check_motion(
    limits: &Limits,
    map: &MotionMap<'_>,
    prev: &Sample,
    next: &Sample,
    context: &Context,
    tolerance: &Tolerance,
) -> MotionVerdict {
    let client_ticks = next.time.wrapping_sub(prev.time) as i32;
    let mut ticks = client_ticks.max(0) as u32;
    if let Some(cap) = context.max_ticks {
        ticks = ticks.min(cap);
    }
    // Beyond ten minutes the bounds mean nothing anyway; the cap keeps the
    // arithmetic in range.
    let ticks = ticks.saturating_add(tolerance.ticks).min(MAX_TICKS);
    let pct = 100 + tolerance.percent as i64;

    // Fastest movement, pixels per 10 s.
    let mut top = limits.speed as i64;
    if map.has_wormholes() {
        top = top.max(limits.gravity_speed as i64);
    }
    if context.repelled {
        top = top.max(limits.repel_speed as i64);
    }
    let travel = top + limits.recoil as i64;

    // Distance (squared, so no square root on the common path).
    let (dx, dy) = (next.x as i64 - prev.x as i64, next.y as i64 - prev.y as i64);
    let dist_sq = dx * dx + dy * dy;
    let reach = travel * ticks as i64 / 1000 + tolerance.pixels as i64;
    let distance_percent = percent_of(dist_sq, reach);

    // Reported speed.
    let max_report = travel * limits.bounce_gain as i64 / 256 * pct / 100;
    let (vx, vy) = (next.x_speed as i64, next.y_speed as i64);
    let (vx, vy) = (
        vx.clamp(-MAX_SPEED, MAX_SPEED),
        vy.clamp(-MAX_SPEED, MAX_SPEED),
    );
    let speed_percent = percent_of(vx * vx + vy * vy, max_report);

    // Rotation, the short way round.
    let turned = (next.rotation % 40).abs_diff(prev.rotation % 40);
    let turned = turned.min(40 - turned) as i64;
    let can_turn = (limits.rotation as i64 * ticks as i64 / 1000 + 1) * pct / 100;
    let rotation_percent = if can_turn >= 20 {
        0
    } else {
        (turned * 100 / can_turn.max(1)) as u32
    };

    let flash = next.status & STATUS_FLASH != 0;
    let mut wormhole = false;
    let wall = if context.jumped {
        WallCheck::Unchecked
    } else if distance_percent > 100 {
        // Already a teleport (unless a wormhole explains it); only report a ship
        // that ended up inside a wall on top of that.
        wormhole = map.wormhole_near(prev.x, prev.y, reach);
        if !wormhole && inside_wall(map.map, next) {
            WallCheck::Inside
        } else {
            WallCheck::Unchecked
        }
    } else {
        check_walls(map.map, prev, next, reach)
    };
    let distance_percent = if context.jumped { 0 } else { distance_percent };
    // A jump (respawn, warp, wormhole) faces the ship any way.
    let rotation_percent = if context.jumped || wormhole {
        0
    } else {
        rotation_percent
    };

    // Energy.
    let bounds = energy_bounds(limits, prev.energy, ticks, context.spent, context.refilled);
    let energy_excess = if bounds.is_empty() {
        // Couldn't afford what it fired: the shortfall is the excess.
        (-*bounds.end()).max(1)
    } else {
        (next.energy as i64 - *bounds.end() as i64 - tolerance.energy as i64)
            .clamp(0, i32::MAX as i64) as i32
    };
    let energy_excess_percent = if energy_excess > 0 {
        (energy_excess as i64 * 100 / (limits.max_energy as i64).max(1)).max(1) as u32
    } else {
        0
    };

    MotionVerdict {
        ticks,
        distance_percent,
        speed_percent,
        rotation_percent,
        wall,
        wormhole,
        flash,
        illegal_status: next.status & CAPABILITY_STATUS & !limits.caps,
        energy_excess,
        energy_excess_percent,
    }
}

/// Elapsed ticks are capped at ten minutes.
const MAX_TICKS: u32 = 60_000;
/// Reported speeds are clamped to this (the wire carries 16 bits).
const MAX_SPEED: i64 = 1 << 20;

/// `sqrt(value_sq)` as a percentage of `limit`.
fn percent_of(value_sq: i64, limit: i64) -> u32 {
    if value_sq == 0 {
        return 0;
    }
    if limit <= 0 {
        return u32::MAX;
    }
    let limit_sq = limit as i128 * limit as i128;
    if (value_sq as i128) <= limit_sq {
        // Within the limit: still report how close, for tuning.
        return isqrt((value_sq as i128 * 10_000 / limit_sq) as i64) as u32;
    }
    (isqrt(value_sq) as i128 * 100 / limit as i128).min(u32::MAX as i128) as u32
}

fn inside_wall(map: &TileMap, s: &Sample) -> bool {
    blocks(map.get(s.x.div_euclid(16), s.y.div_euclid(16)))
}

/// Whether a tile stops a ship, as far as the server can tell: walls and
/// objects, but not doors (their state depends on timing the server may not
/// track exactly).
fn blocks(id: u8) -> bool {
    is_solid_id(id) && !(tile::FIRST_DOOR..=tile::LAST_DOOR).contains(&id)
}

fn check_walls(map: &TileMap, prev: &Sample, next: &Sample, reach: i64) -> WallCheck {
    let tile_of = |v: i32| v.div_euclid(16);
    if inside_wall(map, next) {
        return WallCheck::Inside;
    }
    // Walk the straight path in steps of at most 8 pixels along its longer axis,
    // so no tile it crosses squarely is skipped.
    let (dx, dy) = (next.x - prev.x, next.y - prev.y);
    let steps = (dx.unsigned_abs().max(dy.unsigned_abs()) / 8 + 1) as i64;
    let crosses = (1..steps).any(|i| {
        let x = prev.x as i64 + dx as i64 * i / steps;
        let y = prev.y as i64 + dy as i64 * i / steps;
        blocks(map.get(tile_of(x as i32), tile_of(y as i32)))
    });
    if !crosses {
        return WallCheck::Clear;
    }
    // A four-way tile search overcounts a diagonal path by up to sqrt(2), so
    // allow that many steps (and a couple for partial tiles at each end).
    let budget = (reach * 1415 / 1000 / 16 + 3) as u32;
    detour(
        map,
        (tile_of(prev.x), tile_of(prev.y)),
        (tile_of(next.x), tile_of(next.y)),
        budget,
    )
}

/// Side of the square tile window [`detour`] searches.
const WINDOW: i32 = 64;

/// Searches for a path of free tiles from `start` to `goal` in at most `budget`
/// four-way steps, within a 64x64-tile window around them (bit sets on the
/// stack). Reaching the window's edge means the search can't decide, which
/// counts as plausible.
fn detour(map: &TileMap, start: (i32, i32), goal: (i32, i32), budget: u32) -> WallCheck {
    if (goal.0 - start.0).abs() >= WINDOW - 2 || (goal.1 - start.1).abs() >= WINDOW - 2 {
        return WallCheck::Unchecked;
    }
    let ox = (start.0 + goal.0) / 2 - WINDOW / 2;
    let oy = (start.1 + goal.1) / 2 - WINDOW / 2;
    let (sc, sr) = ((start.0 - ox) as usize, (start.1 - oy) as usize);
    let (gc, gr) = ((goal.0 - ox) as usize, (goal.1 - oy) as usize);

    // Only rows the search can reach need reading.
    let span = budget.min(WINDOW as u32) as usize;
    let rows = sr.saturating_sub(span)..(sr + span + 1).min(WINDOW as usize);
    // Columns likewise; unread cells stay blocked, which the budget never reaches.
    let cols = sc.saturating_sub(span)..(sc + span + 1).min(WINDOW as usize);
    let cells = map.cells();
    let mut free = [0u64; WINDOW as usize];
    for r in rows {
        let y = oy + r as i32;
        let (x0, x1) = (ox + cols.start as i32, ox + cols.end as i32);
        let mut bits = 0u64;
        if (0..MAP_TILES as i32).contains(&y) && x0 >= 0 && x1 <= MAP_TILES as i32 {
            let row = &cells[y as usize * MAP_TILES..][x0 as usize..x1 as usize];
            for (c, &id) in cols.clone().zip(row) {
                bits |= (!blocks(id) as u64) << c;
            }
        } else {
            for c in cols.clone() {
                bits |= (!blocks(map.get(ox + c as i32, y)) as u64) << c;
            }
        }
        free[r] = bits;
    }
    free[sr] |= 1 << sc;

    const EDGE_COLS: u64 = 1 | (1 << (WINDOW - 1));
    let mut reached = [0u64; WINDOW as usize];
    reached[sr] = 1 << sc;
    let (mut lo, mut hi) = (sr, sr);
    for _ in 0..budget {
        let mut next = reached;
        let (new_lo, new_hi) = (lo.saturating_sub(1), (hi + 1).min(WINDOW as usize - 1));
        let mut changed = false;
        for r in new_lo..=new_hi {
            let mut grow = reached[r] | reached[r] << 1 | reached[r] >> 1;
            if r > 0 {
                grow |= reached[r - 1];
            }
            if r + 1 < WINDOW as usize {
                grow |= reached[r + 1];
            }
            grow &= free[r];
            changed |= grow != reached[r];
            next[r] = grow;
        }
        reached = next;
        if reached[gr] & (1 << gc) != 0 {
            return WallCheck::Detour;
        }
        if !changed {
            return WallCheck::Blocked;
        }
        while lo > 0 && reached[lo - 1] != 0 {
            lo -= 1;
        }
        while hi + 1 < WINDOW as usize && reached[hi + 1] != 0 {
            hi += 1;
        }
        if lo == 0 || hi == WINDOW as usize - 1 || (lo..=hi).any(|r| reached[r] & EDGE_COLS != 0) {
            return WallCheck::Unchecked;
        }
    }
    WallCheck::Blocked
}
