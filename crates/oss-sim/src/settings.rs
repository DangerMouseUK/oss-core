//! The arena settings the simulation uses, in Continuum's own units (speeds in
//! pixels/10 s, times in ticks, energy in points, percentages in 0.1%). The client fills
//! these from the server's settings packet; [`ArenaSettings::default`] holds the stock
//! values a freshly installed zone ships with, used by the offline sandbox.

#![warn(missing_docs)]

/// Per-ship settings (one block per ship type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShipSettings {
    /// Ship radius in pixels (0 means the default, 14).
    pub radius: u16,
    /// Rotation rate a ship spawns with, in 1/400 turn per second (so `r / 1000` of the
    /// 40 directions per tick).
    pub initial_rotation: u32,
    /// Thrust a ship spawns with: pixels/10 s of speed gained per tick.
    pub initial_thrust: u32,
    /// Top speed a ship spawns with, in pixels/10 s.
    pub initial_speed: u32,
    /// Recharge a ship spawns with, in energy points per 10 s.
    pub initial_recharge: u32,
    /// Maximum energy a ship spawns with, in points.
    pub initial_energy: u32,
    /// Highest rotation rate prizes can raise it to.
    pub maximum_rotation: u32,
    /// Highest thrust prizes can raise it to; also the thrust while afterburning.
    pub maximum_thrust: u32,
    /// Highest top speed prizes can raise it to; also the top speed while afterburning.
    pub maximum_speed: u32,
    /// Highest recharge prizes can raise it to.
    pub maximum_recharge: u32,
    /// Highest maximum energy prizes can raise it to.
    pub maximum_energy: u32,
    /// Rotation added (or removed) by one rotation prize.
    pub upgrade_rotation: u32,
    /// Thrust added (or removed) by one thruster prize.
    pub upgrade_thrust: u32,
    /// Top speed added (or removed) by one top-speed prize.
    pub upgrade_speed: u32,
    /// Recharge added (or removed) by one quick-charge prize.
    pub upgrade_recharge: u32,
    /// Maximum energy added (or removed) by one energy prize.
    pub upgrade_energy: u32,
    /// Energy per 10 s while afterburners are on (and thrusting).
    pub afterburner_energy: u32,
    /// Recoil (pixels/10 s, applied backwards after the speed clamp) when firing a
    /// bomb.
    pub bomb_thrust: u32,
    /// Bullet speed in pixels/10 s, added to the ship's velocity.
    pub bullet_speed: u32,
    /// Bomb speed in pixels/10 s, added to the ship's velocity.
    pub bomb_speed: u32,
    /// Burst shrapnel speed in pixels/10 s.
    pub burst_speed: u32,
    /// Energy points per bullet shot, times (gun level + 1), where the level is 0..=3
    /// as on the wire.
    pub bullet_fire_energy: u32,
    /// Energy points per multifire shot, times (gun level + 1).
    pub multi_fire_energy: u32,
    /// Energy points per bomb at level 0.
    pub bomb_fire_energy: u32,
    /// Extra energy points per bomb for each bomb level.
    pub bomb_fire_energy_upgrade: u32,
    /// Energy points per mine at level 0.
    pub landmine_fire_energy: u32,
    /// Extra energy points per mine for each bomb level.
    pub landmine_fire_energy_upgrade: u32,
    /// Ticks (1/100 s) after a bullet before the next gun shot. A bullet also holds
    /// bombs and mines back until that tick (it never shortens a longer pending bomb
    /// delay).
    pub bullet_fire_delay: u32,
    /// Ticks after a multifire shot before the next gun shot; bombs and mines are held
    /// back until that tick too.
    pub multi_fire_delay: u32,
    /// Ticks after a bomb before the next bomb, mine or gun shot (plus
    /// `Flag:FlaggerBombFireDelay` for flaggers). Bursts, thors, decoys, repels and
    /// bricks also hold guns and bombs back this long. With `EmpBomb` set, a bomb
    /// doesn't hold guns back.
    pub bomb_fire_delay: u32,
    /// Ticks after a mine before the next bomb or mine; guns are held back until that
    /// tick too.
    pub landmine_fire_delay: u32,
    /// Multifire spread in 1/111 degree.
    pub multi_fire_angle: u32,
    /// Cloak upkeep, energy per 10 s.
    pub cloak_energy: u32,
    /// Stealth upkeep, energy per 10 s.
    pub stealth_energy: u32,
    /// Antiwarp upkeep, energy per 10 s.
    pub anti_warp_energy: u32,
    /// X-radar upkeep, energy per 10 s.
    pub xradar_energy: u32,
    /// Wormhole pull (0 = none; negative pushes).
    pub gravity: i32,
    /// Top speed (pixels/10 s) allowed while a wormhole is pulling the ship.
    pub gravity_top_speed: u32,
    /// Super prize duration: a random number of ticks below this.
    pub super_time: u32,
    /// Shields prize duration in ticks.
    pub shields_time: u32,
    /// Rocket duration in ticks.
    pub rocket_time: u32,
    /// Random prizes a ship gets on spawn (drawn from the arena's prize seed).
    pub initial_bounty: u32,
    /// Wall bounces a bomb makes before exploding on a wall.
    pub bomb_bounce_count: u8,
    /// Shrapnel pieces in a burst.
    pub burst_shrapnel: u8,
    /// Mines one ship may have out at once.
    pub max_mines: u8,
    /// Most repels a ship can hold.
    pub repel_max: u8,
    /// Most bursts a ship can hold.
    pub burst_max: u8,
    /// Most decoys a ship can hold.
    pub decoy_max: u8,
    /// Most thors a ship can hold.
    pub thor_max: u8,
    /// Most bricks a ship can hold.
    pub brick_max: u8,
    /// Most rockets a ship can hold.
    pub rocket_max: u8,
    /// Most portals a ship can hold.
    pub portal_max: u8,
    /// Repels a ship spawns with.
    pub initial_repel: u8,
    /// Bursts a ship spawns with.
    pub initial_burst: u8,
    /// Bricks a ship spawns with.
    pub initial_brick: u8,
    /// Rockets a ship spawns with.
    pub initial_rocket: u8,
    /// Thors a ship spawns with.
    pub initial_thor: u8,
    /// Decoys a ship spawns with.
    pub initial_decoy: u8,
    /// Portals a ship spawns with.
    pub initial_portal: u8,
    /// Most shrapnel pieces per bomb.
    pub shrapnel_max: u8,
    /// Shrapnel pieces added (or removed) by one shrapnel prize.
    pub shrapnel_rate: u8,
    /// Cloak: 0 = never, 1 = can be prized, 2 = starts with it.
    pub cloak_status: u8,
    /// Stealth: 0 = never, 1 = can be prized, 2 = starts with it.
    pub stealth_status: u8,
    /// X-radar: 0 = never, 1 = can be prized, 2 = starts with it.
    pub xradar_status: u8,
    /// Antiwarp: 0 = never, 1 = can be prized, 2 = starts with it.
    pub anti_warp_status: u8,
    /// Gun level a ship spawns with (0 = none, 1..=3; the wire level is one less).
    pub initial_guns: u8,
    /// Highest gun level prizes can raise it to (0..=3).
    pub max_guns: u8,
    /// Bomb level a ship spawns with (0 = none, 1..=3; the wire level is one less).
    pub initial_bombs: u8,
    /// Highest bomb level prizes can raise it to (0..=3).
    pub max_bombs: u8,
    /// Guns fire two parallel bullets.
    pub double_barrel: bool,
    /// Bombs are EMP bombs (they stop recharge on a hit, and don't hold guns back).
    pub emp_bomb: bool,
    /// Weapons can't be fired while afterburners are on.
    pub disable_fast_shooting: bool,
    /// Soccer: ticks a ball can be carried before it is thrown automatically (0 =
    /// forever).
    pub soccer_throw_time: u32,
    /// Soccer: ball friction (higher slows it less).
    pub soccer_ball_friction: u32,
    /// Soccer: distance (pixels) at which the ship picks a ball up.
    pub soccer_ball_proximity: u32,
    /// Soccer: speed (pixels/10 s) a ball is fired at.
    pub soccer_ball_speed: u32,
    /// Thrust lost while one or more turrets ride on the ship (once, not per
    /// turret, as nullspace applies it; a rocket overrides it).
    pub turret_thrust_penalty: u32,
    /// Top speed (pixels/10 s) lost while one or more turrets ride on the ship
    /// (once, not per turret).
    pub turret_speed_penalty: u32,
    /// Radar vision: the ship sees mines.
    pub see_mines: bool,
    /// Radar vision: the ship sees bombs from this level up (0 = none, 1 = all,
    /// 2 = L2 and up, 3 = L3 and up). ASSS documents 4 = L4 only, but the packet
    /// field is 2 bits wide.
    pub see_bomb_level: u8,
    /// `Ship:DamageFactor`: how readily a hit costs the ship a prize. 0 never does;
    /// otherwise a hit has a `1 / (factor * 200 / damage + 1)` chance, so 1 is
    /// near-certain and 5000 is almost never. Not a damage multiplier.
    pub damage_factor: u32,
    /// `Ship:PrizeShareLimit`: a ship below this bounty still receives prizes a
    /// teammate picks up (see [`crate::World::share_prize`]).
    pub prize_share_limit: u32,
}

/// `Flag:Flagger*`: adjustments for players carrying flags (and ball carriers when
/// `Soccer:UseFlagger` is set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlaggerSettings {
    /// Added to a flagger's thrust (may be negative).
    pub thrust_adjustment: i32,
    /// Added to a flagger's top speed in pixels/10 s (may be negative).
    pub speed_adjustment: i32,
    /// Extra bomb delay for flaggers (ticks).
    pub bomb_fire_delay: u32,
    /// Flaggers' guns fire one level higher.
    pub gun_upgrade: bool,
    /// Flaggers' bombs fire one level higher.
    pub bomb_upgrade: bool,
    /// Flaggers' weapon cost in 1/1000 (1000 = unchanged).
    pub fire_cost_percent: u32,
    /// Damage flaggers take, in 1/1000 (1000 = unchanged).
    pub damage_percent: u32,
    /// Carriers are marked on everyone's radar.
    pub on_radar: bool,
    /// Kill points multiplier (scored by the server).
    pub kill_multiplier: u32,
}

/// `Soccer:*`, the arena-wide ball rules the client enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoccerSettings {
    /// Balls bounce off walls (otherwise they stop).
    pub ball_bounce: bool,
    /// Ball carriers may fire bombs (otherwise that key shoots the ball).
    pub allow_bombs: bool,
    /// Ball carriers may fire guns (otherwise that key shoots the ball).
    pub allow_guns: bool,
    /// Ticks after a shot before anyone can catch it.
    pub pass_delay: u32,
    /// Ticks without news of a ball before it can't be picked up (0 = never).
    pub ball_blank_delay: u32,
    /// Balls always show on the radar.
    pub ball_location: bool,
    /// Goal layout (0-6).
    pub mode: u8,
    /// Ball carriers get the flagger adjustments.
    pub use_flagger: bool,
    /// `Misc:DisableBallThroughWalls`: no picking a ball up through a wall.
    pub no_wall_pass: bool,
}

impl ShipSettings {
    /// Collision radius in pixels.
    pub const fn radius_pixels(&self) -> i32 {
        if self.radius == 0 {
            14
        } else {
            self.radius as i32
        }
    }
}

/// Number of prize types (and prize weights).
pub const PRIZE_COUNT: usize = 28;

/// Arena-wide settings plus the eight ship blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArenaSettings {
    /// Settings for each ship type, Warbird (0) to Shark (7).
    pub ships: [ShipSettings; 8],
    /// Wall bounce: velocity is multiplied by `16 / bounce_factor` on impact (below 16
    /// speeds the ship up).
    pub bounce_factor: u32,
    /// Bullet lifetime in ticks.
    pub bullet_alive_time: u32,
    /// Bomb lifetime in ticks.
    pub bomb_alive_time: u32,
    /// Mine lifetime in ticks.
    pub mine_alive_time: u32,
    /// Decoy lifetime in ticks.
    pub decoy_alive_time: u32,
    /// Damage (energy points) of a level-0 bullet.
    pub bullet_damage_level: u32,
    /// Extra bullet damage per gun level.
    pub bullet_damage_upgrade: u32,
    /// Damage of a bomb at the centre of its blast.
    pub bomb_damage_level: u32,
    /// Damage of a burst piece.
    pub burst_damage_level: u32,
    /// Damage of shrapnel before it becomes active.
    pub inactive_shrap_damage: u32,
    /// Shrapnel damage relative to bullets, in 0.1%.
    pub shrapnel_damage_percent: u32,
    /// EMP bomb damage relative to normal bombs, in 0.1%.
    pub ebomb_damage_percent: u32,
    /// Bouncing bomb damage relative to normal bombs, in 0.1%.
    pub bbomb_damage_percent: u32,
    /// Bullet damage is exact rather than randomised.
    pub exact_damage: bool,
    /// Longest recharge stop from an EMP hit (ticks).
    pub ebomb_shutdown_time: u32,
    /// Bomb blast radius in pixels (per level).
    pub bomb_explode_pixels: u32,
    /// Ticks a proximity bomb waits after triggering before it explodes.
    pub bomb_explode_delay: u32,
    /// Proximity trigger radius in tiles (plus the bomb level).
    pub proximity_distance: u32,
    /// Proximity bombs can't be fired with an enemy already in range.
    pub bomb_safety: bool,
    /// Shrapnel speed in pixels/10 s.
    pub shrapnel_speed: u32,
    /// Shrapnel flies in random directions rather than evenly spread.
    pub shrapnel_random: bool,
    /// Mines a whole frequency may have out at once.
    pub team_max_mines: u32,
    /// Speed (pixels/10 s) a repel pushes ships and weapons away at; also the top speed
    /// while repelled.
    pub repel_speed: u32,
    /// Ticks a repelled ship may exceed its top speed.
    pub repel_time: u32,
    /// Repel reach in pixels.
    pub repel_distance: u32,
    /// Thrust while a rocket burns.
    pub rocket_thrust: u32,
    /// Top speed (pixels/10 s) while a rocket burns.
    pub rocket_speed: u32,
    /// Brick lifetime in ticks.
    pub brick_time: u32,
    /// Ticks a portal stays usable.
    pub warp_point_delay: u32,
    /// Antiwarp reach in pixels.
    pub anti_warp_pixels: u32,
    /// Ticks of fake antiwarp after warping or using a portal.
    pub anti_warp_settle_delay: u32,
    /// Engine shutdown prize duration in ticks (three times as long for the bad
    /// version).
    pub engine_shutdown_time: u32,
    /// Ticks a dead ship waits before respawning.
    pub enter_delay: u32,
    /// Bounty gained per kill.
    pub bounty_increase_for_kill: u32,
    /// Door behaviour: -2 random, -1 weighted random, 0..=255 fixed door bits.
    pub door_mode: i32,
    /// Ticks between door changes.
    pub door_delay: u32,
    /// Prize weights in prize-id order (1 = QuickCharge .. 28 = Portal).
    pub prize_weights: [u8; PRIZE_COUNT],
    /// Greens allowed per player, in 0.1% (1000 = one per player).
    pub prize_factor: u32,
    /// Ticks between green spawn rounds.
    pub prize_delay: u32,
    /// Greens tried per spawn round.
    pub prize_hide_count: u32,
    /// Green spawn square: `minimum_virtual + upgrade_virtual * players` tiles wide.
    pub minimum_virtual: u32,
    /// Tiles the green spawn square grows by per player.
    pub upgrade_virtual: u32,
    /// Longest a green lasts (ticks).
    pub prize_max_exist: u32,
    /// Shortest a green lasts (ticks).
    pub prize_min_exist: u32,
    /// One prize in this many is negative (0 = never).
    pub prize_negative_factor: u32,
    /// Lifetime (ticks) of the green a kill leaves behind.
    pub death_prize_time: u32,
    /// Prizes a multiprize gives.
    pub multi_prize_count: u32,
    /// Random warp/spawn distance limit from the centre (tiles).
    pub warp_radius_limit: u32,
    /// `Flag:Flagger*` adjustments.
    pub flagger: FlaggerSettings,
    /// `Soccer:*` ball rules.
    pub soccer: SoccerSettings,
    /// Wormholes pull bombs as well as ships.
    pub gravity_bombs: bool,
    /// How often a wormhole's destination changes (ticks; 0 = every trip).
    pub wormhole_switch_time: u32,
    /// `Misc:NearDeathLevel`: energy (points) that counts as a near death. A hit that
    /// takes a ship from above this level down to it or below costs it one bounty
    /// (duelling zones). 0 disables it.
    pub near_death_level: u32,
}

/// Stock ship block: every ship in a freshly installed zone uses these values.
pub const STOCK_SHIP: ShipSettings = ShipSettings {
    radius: 0,
    initial_rotation: 200,
    initial_thrust: 15,
    initial_speed: 2010,
    initial_recharge: 400,
    initial_energy: 1000,
    maximum_rotation: 230,
    maximum_thrust: 17,
    maximum_speed: 3250,
    maximum_recharge: 1150,
    maximum_energy: 1700,
    upgrade_rotation: 40,
    upgrade_thrust: 2,
    upgrade_speed: 250,
    upgrade_recharge: 166,
    upgrade_energy: 100,
    afterburner_energy: 1200,
    bomb_thrust: 400,
    bullet_speed: 2000,
    bomb_speed: 2000,
    burst_speed: 3000,
    bullet_fire_energy: 20,
    multi_fire_energy: 30,
    bomb_fire_energy: 300,
    bomb_fire_energy_upgrade: 50,
    landmine_fire_energy: 270,
    landmine_fire_energy_upgrade: 150,
    bullet_fire_delay: 25,
    multi_fire_delay: 50,
    bomb_fire_delay: 150,
    landmine_fire_delay: 125,
    multi_fire_angle: 500,
    cloak_energy: 100,
    stealth_energy: 333,
    anti_warp_energy: 100,
    xradar_energy: 250,
    gravity: 1500,
    gravity_top_speed: 100,
    super_time: 6000,
    shields_time: 4000,
    rocket_time: 1000,
    initial_bounty: 500,
    bomb_bounce_count: 0,
    burst_shrapnel: 24,
    max_mines: 5,
    repel_max: 3,
    burst_max: 3,
    decoy_max: 3,
    thor_max: 3,
    brick_max: 3,
    rocket_max: 3,
    portal_max: 3,
    initial_repel: 0,
    initial_burst: 0,
    initial_brick: 0,
    initial_rocket: 0,
    initial_thor: 0,
    initial_decoy: 0,
    initial_portal: 0,
    shrapnel_max: 8,
    shrapnel_rate: 2,
    cloak_status: 0,
    stealth_status: 1,
    xradar_status: 1,
    anti_warp_status: 1,
    initial_guns: 0,
    max_guns: 3,
    initial_bombs: 0,
    max_bombs: 2,
    double_barrel: false,
    emp_bomb: false,
    disable_fast_shooting: false,
    soccer_throw_time: 1200,
    soccer_ball_friction: 12,
    soccer_ball_proximity: 64,
    soccer_ball_speed: 2500,
    turret_thrust_penalty: 0,
    turret_speed_penalty: 0,
    see_mines: false,
    see_bomb_level: 0,
    damage_factor: 30,
    prize_share_limit: 100,
};

/// Stock flagger settings (ASSS public arena).
pub const STOCK_FLAGGER: FlaggerSettings = FlaggerSettings {
    thrust_adjustment: 0,
    speed_adjustment: 0,
    bomb_fire_delay: 0,
    gun_upgrade: true,
    bomb_upgrade: true,
    fire_cost_percent: 1000,
    damage_percent: 1000,
    on_radar: true,
    kill_multiplier: 2,
};

/// Stock soccer settings (ASSS public arena).
pub const STOCK_SOCCER: SoccerSettings = SoccerSettings {
    ball_bounce: true,
    allow_bombs: true,
    allow_guns: true,
    pass_delay: 20,
    ball_blank_delay: 200,
    ball_location: true,
    mode: 0,
    use_flagger: true,
    no_wall_pass: false,
};

/// Stock prize weights (QuickCharge, Energy, Rotation, Stealth, Cloak, XRadar, Warp,
/// Gun, Bomb, BouncingBullets, Thruster, TopSpeed, Recharge, Glue, MultiFire,
/// Proximity, AllWeapons, Shields, Shrapnel, AntiWarp, Repel, Burst, Decoy, Thor,
/// MultiPrize, Brick, Rocket, Portal).
pub const STOCK_PRIZE_WEIGHTS: [u8; PRIZE_COUNT] = [
    40, 40, 40, 40, 25, 40, 7, 25, 25, 25, 40, 40, 10, 0, 30, 25, 10, 10, 30, 25, 70, 70, 40, 30,
    130, 200, 50, 60,
];

impl Default for ArenaSettings {
    fn default() -> Self {
        Self {
            ships: [STOCK_SHIP; 8],
            bounce_factor: 22,
            bullet_alive_time: 550,
            bomb_alive_time: 8000,
            mine_alive_time: 12000,
            decoy_alive_time: 1500,
            bullet_damage_level: 200,
            bullet_damage_upgrade: 100,
            bomb_damage_level: 750,
            burst_damage_level: 700,
            inactive_shrap_damage: 3,
            shrapnel_damage_percent: 1000,
            ebomb_damage_percent: 1000,
            bbomb_damage_percent: 1000,
            exact_damage: false,
            ebomb_shutdown_time: 400,
            bomb_explode_pixels: 80,
            bomb_explode_delay: 150,
            proximity_distance: 3,
            bomb_safety: true,
            shrapnel_speed: 3000,
            shrapnel_random: true,
            team_max_mines: 12,
            repel_speed: 5000,
            repel_time: 225,
            repel_distance: 512,
            rocket_thrust: 25,
            rocket_speed: 5500,
            brick_time: 12000,
            warp_point_delay: 6000,
            anti_warp_pixels: 1000,
            anti_warp_settle_delay: 0,
            engine_shutdown_time: 700,
            enter_delay: 200,
            bounty_increase_for_kill: 6,
            door_mode: -2,
            door_delay: 600,
            prize_weights: STOCK_PRIZE_WEIGHTS,
            prize_factor: 10000,
            prize_delay: 700,
            prize_hide_count: 10,
            minimum_virtual: 10,
            upgrade_virtual: 6,
            prize_max_exist: 8000,
            prize_min_exist: 4000,
            prize_negative_factor: 300,
            death_prize_time: 1000,
            multi_prize_count: 10,
            warp_radius_limit: 20,
            flagger: STOCK_FLAGGER,
            soccer: STOCK_SOCCER,
            gravity_bombs: true,
            wormhole_switch_time: 100_000,
            near_death_level: 0,
        }
    }
}

impl ArenaSettings {
    /// Settings for flying around offline: the stock zone. Ships start armed through
    /// their initial bounty, exactly as in a real zone.
    pub fn sandbox() -> Self {
        Self::default()
    }

    /// Sum of all prize weights.
    pub fn prize_weight_total(&self) -> u32 {
        self.prize_weights.iter().map(|&w| w as u32).sum()
    }
}

fn clamp_u32(v: i32) -> u32 {
    v.max(0) as u32
}

impl ShipSettings {
    /// Reads one ship block of the server's settings packet.
    pub fn from_proto(s: &oss_proto::settings::ShipSettings) -> Self {
        Self {
            radius: s.radius() as u16,
            initial_rotation: s.initial_rotation() as u32,
            initial_thrust: s.initial_thrust() as u32,
            initial_speed: s.initial_speed() as u32,
            initial_recharge: s.initial_recharge() as u32,
            initial_energy: s.initial_energy() as u32,
            maximum_rotation: s.maximum_rotation() as u32,
            maximum_thrust: s.maximum_thrust() as u32,
            maximum_speed: s.maximum_speed() as u32,
            maximum_recharge: s.maximum_recharge() as u32,
            maximum_energy: s.maximum_energy() as u32,
            upgrade_rotation: s.upgrade_rotation() as u32,
            upgrade_thrust: s.upgrade_thrust() as u32,
            upgrade_speed: s.upgrade_speed() as u32,
            upgrade_recharge: s.upgrade_recharge() as u32,
            upgrade_energy: s.upgrade_energy() as u32,
            afterburner_energy: s.afterburner_energy() as u32,
            bomb_thrust: s.bomb_thrust() as u32,
            bullet_speed: s.bullet_speed() as u32,
            bomb_speed: s.bomb_speed() as u32,
            burst_speed: s.burst_speed() as u32,
            bullet_fire_energy: s.bullet_fire_energy() as u32,
            multi_fire_energy: s.multi_fire_energy() as u32,
            bomb_fire_energy: s.bomb_fire_energy() as u32,
            bomb_fire_energy_upgrade: s.bomb_fire_energy_upgrade() as u32,
            landmine_fire_energy: s.landmine_fire_energy() as u32,
            landmine_fire_energy_upgrade: s.landmine_fire_energy_upgrade() as u32,
            bullet_fire_delay: s.bullet_fire_delay() as u32,
            multi_fire_delay: s.multi_fire_delay() as u32,
            bomb_fire_delay: s.bomb_fire_delay() as u32,
            landmine_fire_delay: s.landmine_fire_delay() as u32,
            multi_fire_angle: s.multi_fire_angle() as u32,
            cloak_energy: s.cloak_energy() as u32,
            stealth_energy: s.stealth_energy() as u32,
            anti_warp_energy: s.anti_warp_energy() as u32,
            xradar_energy: s.xradar_energy() as u32,
            gravity: s.gravity() as i32,
            gravity_top_speed: (s.gravity_top_speed() as i32).max(0) as u32,
            super_time: clamp_u32(s.super_time()),
            shields_time: clamp_u32(s.shields_time()),
            rocket_time: s.rocket_time() as u32,
            initial_bounty: s.initial_bounty() as u32,
            bomb_bounce_count: s.bomb_bounce_count(),
            burst_shrapnel: s.burst_shrapnel(),
            max_mines: s.max_mines(),
            repel_max: s.repel_max(),
            burst_max: s.burst_max(),
            decoy_max: s.decoy_max(),
            thor_max: s.thor_max(),
            brick_max: s.brick_max(),
            rocket_max: s.rocket_max(),
            portal_max: s.portal_max(),
            initial_repel: s.initial_repel(),
            initial_burst: s.initial_burst(),
            initial_brick: s.initial_brick(),
            initial_rocket: s.initial_rocket(),
            initial_thor: s.initial_thor(),
            initial_decoy: s.initial_decoy(),
            initial_portal: s.initial_portal(),
            shrapnel_max: s.shrapnel_max(),
            shrapnel_rate: s.shrapnel_rate(),
            cloak_status: s.cloak_status(),
            stealth_status: s.stealth_status(),
            xradar_status: s.xradar_status(),
            anti_warp_status: s.anti_warp_status(),
            initial_guns: s.initial_guns().min(3),
            max_guns: s.max_guns().min(3),
            initial_bombs: s.initial_bombs().min(3),
            max_bombs: s.max_bombs().min(3),
            double_barrel: s.double_barrel() != 0,
            emp_bomb: s.emp_bomb() != 0,
            disable_fast_shooting: s.disable_fast_shooting() != 0,
            soccer_throw_time: s.soccer_throw_time() as u32,
            soccer_ball_friction: s.soccer_ball_friction() as u32,
            soccer_ball_proximity: s.soccer_ball_proximity() as u32,
            soccer_ball_speed: s.soccer_ball_speed() as u32,
            turret_thrust_penalty: (s.turret_thrust_penalty() as i32).max(0) as u32,
            turret_speed_penalty: (s.turret_speed_penalty() as i32).max(0) as u32,
            see_mines: s.see_mines() != 0,
            see_bomb_level: s.see_bomb_level().min(3),
            damage_factor: s.damage_factor() as u32,
            prize_share_limit: s.prize_share_limit() as u32,
        }
    }
}

impl ArenaSettings {
    /// Builds simulation settings from the server's settings packet (S2C 0x0F).
    /// Damage values arrive multiplied by 1000 and are converted back to points;
    /// negative values are clamped so a hostile packet can't break the simulation.
    pub fn from_client_settings(cs: &oss_proto::ClientSettings) -> Self {
        let short = |v: i16| (v as i32).max(0) as u32;
        Self {
            ships: core::array::from_fn(|i| ShipSettings::from_proto(&cs.ships[i])),
            bounce_factor: (cs.bounce_factor() as i32).max(1) as u32,
            bullet_alive_time: clamp_u32(cs.bullet_alive_time()),
            bomb_alive_time: clamp_u32(cs.bomb_alive_time()),
            mine_alive_time: clamp_u32(cs.mine_alive_time()),
            decoy_alive_time: clamp_u32(cs.decoy_alive_time()),
            bullet_damage_level: clamp_u32(cs.bullet_damage_level()) / 1000,
            bullet_damage_upgrade: clamp_u32(cs.bullet_damage_upgrade()) / 1000,
            bomb_damage_level: clamp_u32(cs.bomb_damage_level()) / 1000,
            burst_damage_level: clamp_u32(cs.burst_damage_level()) / 1000,
            inactive_shrap_damage: clamp_u32(cs.inactive_shrap_damage()) / 1000,
            shrapnel_damage_percent: short(cs.shrapnel_damage_percent()),
            ebomb_damage_percent: short(cs.ebomb_damage_percent()),
            bbomb_damage_percent: short(cs.bbomb_damage_percent()),
            exact_damage: cs.exact_damage() != 0,
            ebomb_shutdown_time: short(cs.ebomb_shutdown_time()),
            bomb_explode_pixels: short(cs.bomb_explode_pixels()),
            bomb_explode_delay: short(cs.bomb_explode_delay()),
            proximity_distance: short(cs.proximity_distance()),
            bomb_safety: cs.bomb_safety() != 0,
            shrapnel_speed: clamp_u32(cs.shrapnel_speed()),
            shrapnel_random: cs.shrapnel_random() != 0,
            team_max_mines: cs.team_max_mines() as u32,
            repel_speed: clamp_u32(cs.repel_speed()),
            repel_time: short(cs.repel_time()),
            repel_distance: short(cs.repel_distance()),
            rocket_thrust: clamp_u32(cs.rocket_thrust()),
            rocket_speed: clamp_u32(cs.rocket_speed()),
            brick_time: short(cs.brick_time()),
            warp_point_delay: short(cs.warp_point_delay()),
            anti_warp_pixels: short(cs.anti_warp_pixels()),
            anti_warp_settle_delay: cs.anti_warp_settle_delay() as u32,
            engine_shutdown_time: short(cs.engine_shutdown_time()),
            enter_delay: short(cs.enter_delay()),
            bounty_increase_for_kill: short(cs.bounty_increase_for_kill()),
            door_mode: cs.door_mode() as i32,
            door_delay: (cs.door_delay() as i32).max(1) as u32,
            prize_weights: cs.prize_weights,
            prize_factor: short(cs.prize_factor()),
            prize_delay: short(cs.prize_delay()),
            prize_hide_count: short(cs.prize_hide_count() as i16),
            minimum_virtual: short(cs.minimum_virtual()),
            upgrade_virtual: short(cs.upgrade_virtual()),
            prize_max_exist: short(cs.prize_max_exist()),
            prize_min_exist: short(cs.prize_min_exist()),
            prize_negative_factor: short(cs.prize_negative_factor()),
            death_prize_time: short(cs.death_prize_time()),
            multi_prize_count: short(cs.multi_prize_count()),
            warp_radius_limit: short(cs.warp_radius_limit()),
            flagger: FlaggerSettings {
                thrust_adjustment: cs.flagger_thrust_adjustment() as i32,
                speed_adjustment: cs.flagger_speed_adjustment() as i32,
                bomb_fire_delay: short(cs.flagger_bomb_fire_delay()),
                gun_upgrade: cs.flagger_gun_upgrade() != 0,
                bomb_upgrade: cs.flagger_bomb_upgrade() != 0,
                fire_cost_percent: short(cs.flagger_fire_cost_percent()),
                damage_percent: short(cs.flagger_damage_percent()),
                on_radar: cs.flagger_on_radar() != 0,
                kill_multiplier: short(cs.flagger_kill_multiplier()),
            },
            soccer: SoccerSettings {
                ball_bounce: cs.ball_bounce() != 0,
                allow_bombs: cs.allow_bombs() != 0,
                allow_guns: cs.allow_guns() != 0,
                pass_delay: short(cs.pass_delay()),
                ball_blank_delay: short(cs.ball_blank_delay()),
                ball_location: cs.ball_location() != 0,
                mode: cs.soccer_mode(),
                use_flagger: cs.use_flagger() != 0,
                no_wall_pass: cs.disable_ball_through_walls() != 0,
            },
            gravity_bombs: cs.gravity_bombs() != 0,
            wormhole_switch_time: clamp_u32(cs.wormhole_switch_time()),
            near_death_level: short(cs.near_death_level()),
        }
    }
}

impl ShipSettings {
    /// Writes this block into a settings-packet ship block (fields the simulation
    /// doesn't use are left as they are).
    pub fn write_proto(&self, s: &mut oss_proto::settings::ShipSettings) {
        let u16_ = |v: u32| v.min(u16::MAX as u32) as u16;
        s.set_radius(self.radius.min(255) as u8);
        s.set_initial_rotation(u16_(self.initial_rotation));
        s.set_initial_thrust(u16_(self.initial_thrust));
        s.set_initial_speed(u16_(self.initial_speed));
        s.set_initial_recharge(u16_(self.initial_recharge));
        s.set_initial_energy(u16_(self.initial_energy));
        s.set_maximum_rotation(u16_(self.maximum_rotation));
        s.set_maximum_thrust(u16_(self.maximum_thrust));
        s.set_maximum_speed(u16_(self.maximum_speed));
        s.set_maximum_recharge(u16_(self.maximum_recharge));
        s.set_maximum_energy(u16_(self.maximum_energy));
        s.set_upgrade_rotation(u16_(self.upgrade_rotation));
        s.set_upgrade_thrust(u16_(self.upgrade_thrust));
        s.set_upgrade_speed(u16_(self.upgrade_speed));
        s.set_upgrade_recharge(u16_(self.upgrade_recharge));
        s.set_upgrade_energy(u16_(self.upgrade_energy));
        s.set_afterburner_energy(u16_(self.afterburner_energy));
        s.set_bomb_thrust(u16_(self.bomb_thrust));
        s.set_bullet_speed(u16_(self.bullet_speed));
        s.set_bomb_speed(u16_(self.bomb_speed));
        s.set_burst_speed(u16_(self.burst_speed));
        s.set_bullet_fire_energy(u16_(self.bullet_fire_energy));
        s.set_multi_fire_energy(u16_(self.multi_fire_energy));
        s.set_bomb_fire_energy(u16_(self.bomb_fire_energy));
        s.set_bomb_fire_energy_upgrade(u16_(self.bomb_fire_energy_upgrade));
        s.set_landmine_fire_energy(u16_(self.landmine_fire_energy));
        s.set_landmine_fire_energy_upgrade(u16_(self.landmine_fire_energy_upgrade));
        s.set_bullet_fire_delay(u16_(self.bullet_fire_delay));
        s.set_multi_fire_delay(u16_(self.multi_fire_delay));
        s.set_bomb_fire_delay(u16_(self.bomb_fire_delay));
        s.set_landmine_fire_delay(u16_(self.landmine_fire_delay));
        s.set_multi_fire_angle(u16_(self.multi_fire_angle));
        s.set_cloak_energy(u16_(self.cloak_energy));
        s.set_stealth_energy(u16_(self.stealth_energy));
        s.set_anti_warp_energy(u16_(self.anti_warp_energy));
        s.set_xradar_energy(u16_(self.xradar_energy));
        s.set_gravity(self.gravity.clamp(i16::MIN as i32, i16::MAX as i32) as i16);
        s.set_gravity_top_speed(self.gravity_top_speed.min(i16::MAX as u32) as i16);
        s.set_super_time(self.super_time.min(i32::MAX as u32) as i32);
        s.set_shields_time(self.shields_time.min(i32::MAX as u32) as i32);
        s.set_rocket_time(u16_(self.rocket_time));
        s.set_initial_bounty(u16_(self.initial_bounty));
        s.set_bomb_bounce_count(self.bomb_bounce_count);
        s.set_burst_shrapnel(self.burst_shrapnel);
        s.set_max_mines(self.max_mines);
        s.set_repel_max(self.repel_max);
        s.set_burst_max(self.burst_max);
        s.set_decoy_max(self.decoy_max);
        s.set_thor_max(self.thor_max);
        s.set_brick_max(self.brick_max);
        s.set_rocket_max(self.rocket_max);
        s.set_portal_max(self.portal_max);
        s.set_initial_repel(self.initial_repel);
        s.set_initial_burst(self.initial_burst);
        s.set_initial_brick(self.initial_brick);
        s.set_initial_rocket(self.initial_rocket);
        s.set_initial_thor(self.initial_thor);
        s.set_initial_decoy(self.initial_decoy);
        s.set_initial_portal(self.initial_portal);
        s.set_shrapnel_max(self.shrapnel_max);
        s.set_shrapnel_rate(self.shrapnel_rate);
        s.set_cloak_status(self.cloak_status);
        s.set_stealth_status(self.stealth_status);
        s.set_xradar_status(self.xradar_status);
        s.set_anti_warp_status(self.anti_warp_status);
        s.set_initial_guns(self.initial_guns);
        s.set_max_guns(self.max_guns);
        s.set_initial_bombs(self.initial_bombs);
        s.set_max_bombs(self.max_bombs);
        s.set_double_barrel(self.double_barrel as u8);
        s.set_emp_bomb(self.emp_bomb as u8);
        s.set_disable_fast_shooting(self.disable_fast_shooting as u8);
        s.set_soccer_throw_time(u16_(self.soccer_throw_time));
        s.set_soccer_ball_friction(u16_(self.soccer_ball_friction));
        s.set_soccer_ball_proximity(u16_(self.soccer_ball_proximity));
        s.set_soccer_ball_speed(u16_(self.soccer_ball_speed));
        s.set_turret_thrust_penalty(self.turret_thrust_penalty.min(i16::MAX as u32) as i16);
        s.set_turret_speed_penalty(self.turret_speed_penalty.min(i16::MAX as u32) as i16);
        s.set_see_mines(self.see_mines as u8);
        // A 2-bit field: ASSS's documented 4 (L4 only) can't be sent.
        s.set_see_bomb_level(self.see_bomb_level.min(3));
        s.set_damage_factor(u16_(self.damage_factor));
        s.set_prize_share_limit(u16_(self.prize_share_limit));
    }
}

impl ArenaSettings {
    /// A settings packet carrying these settings (the inverse of
    /// [`ArenaSettings::from_client_settings`]; other fields stay zero). Used by test
    /// servers and tools.
    pub fn to_client_settings(&self) -> oss_proto::ClientSettings {
        let mut cs = oss_proto::ClientSettings::default();
        for (i, ship) in self.ships.iter().enumerate() {
            ship.write_proto(&mut cs.ships[i]);
        }
        let i32_ = |v: u32| v.min(i32::MAX as u32) as i32;
        let i16_ = |v: u32| v.min(i16::MAX as u32) as i16;
        cs.set_bounce_factor(i16_(self.bounce_factor));
        cs.set_bullet_alive_time(i32_(self.bullet_alive_time));
        cs.set_bomb_alive_time(i32_(self.bomb_alive_time));
        cs.set_mine_alive_time(i32_(self.mine_alive_time));
        cs.set_decoy_alive_time(i32_(self.decoy_alive_time));
        cs.set_bullet_damage_level(i32_(self.bullet_damage_level.saturating_mul(1000)));
        cs.set_bullet_damage_upgrade(i32_(self.bullet_damage_upgrade.saturating_mul(1000)));
        cs.set_bomb_damage_level(i32_(self.bomb_damage_level.saturating_mul(1000)));
        cs.set_burst_damage_level(i32_(self.burst_damage_level.saturating_mul(1000)));
        cs.set_inactive_shrap_damage(i32_(self.inactive_shrap_damage.saturating_mul(1000)));
        cs.set_shrapnel_damage_percent(i16_(self.shrapnel_damage_percent));
        cs.set_ebomb_damage_percent(i16_(self.ebomb_damage_percent));
        cs.set_bbomb_damage_percent(i16_(self.bbomb_damage_percent));
        cs.set_exact_damage(self.exact_damage as u8);
        cs.set_ebomb_shutdown_time(i16_(self.ebomb_shutdown_time));
        cs.set_bomb_explode_pixels(i16_(self.bomb_explode_pixels));
        cs.set_bomb_explode_delay(i16_(self.bomb_explode_delay));
        cs.set_proximity_distance(i16_(self.proximity_distance));
        cs.set_bomb_safety(self.bomb_safety as u8);
        cs.set_shrapnel_speed(i32_(self.shrapnel_speed));
        cs.set_shrapnel_random(self.shrapnel_random as u8);
        cs.set_team_max_mines(self.team_max_mines.min(255) as u8);
        cs.set_repel_speed(i32_(self.repel_speed));
        cs.set_repel_time(i16_(self.repel_time));
        cs.set_repel_distance(i16_(self.repel_distance));
        cs.set_rocket_thrust(i32_(self.rocket_thrust));
        cs.set_rocket_speed(i32_(self.rocket_speed));
        cs.set_brick_time(i16_(self.brick_time));
        cs.set_warp_point_delay(i16_(self.warp_point_delay));
        cs.set_anti_warp_pixels(i16_(self.anti_warp_pixels));
        cs.set_anti_warp_settle_delay(self.anti_warp_settle_delay.min(255) as u8);
        cs.set_engine_shutdown_time(i16_(self.engine_shutdown_time));
        cs.set_enter_delay(i16_(self.enter_delay));
        cs.set_bounty_increase_for_kill(i16_(self.bounty_increase_for_kill));
        cs.set_door_mode(self.door_mode.clamp(i16::MIN as i32, i16::MAX as i32) as i16);
        cs.set_door_delay(i16_(self.door_delay));
        cs.prize_weights = self.prize_weights;
        cs.set_prize_factor(i16_(self.prize_factor));
        cs.set_prize_delay(i16_(self.prize_delay));
        cs.set_prize_hide_count(self.prize_hide_count.min(255) as u8);
        cs.set_minimum_virtual(i16_(self.minimum_virtual));
        cs.set_upgrade_virtual(i16_(self.upgrade_virtual));
        cs.set_prize_max_exist(i16_(self.prize_max_exist));
        cs.set_prize_min_exist(i16_(self.prize_min_exist));
        cs.set_prize_negative_factor(i16_(self.prize_negative_factor));
        cs.set_death_prize_time(i16_(self.death_prize_time));
        cs.set_multi_prize_count(i16_(self.multi_prize_count));
        cs.set_warp_radius_limit(i16_(self.warp_radius_limit));
        let f = &self.flagger;
        let signed = |v: i32| v.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        cs.set_flagger_thrust_adjustment(signed(f.thrust_adjustment));
        cs.set_flagger_speed_adjustment(signed(f.speed_adjustment));
        cs.set_flagger_bomb_fire_delay(i16_(f.bomb_fire_delay));
        cs.set_flagger_gun_upgrade(f.gun_upgrade as u8);
        cs.set_flagger_bomb_upgrade(f.bomb_upgrade as u8);
        cs.set_flagger_fire_cost_percent(i16_(f.fire_cost_percent));
        cs.set_flagger_damage_percent(i16_(f.damage_percent));
        cs.set_flagger_on_radar(f.on_radar as i16);
        cs.set_flagger_kill_multiplier(i16_(f.kill_multiplier));
        let b = &self.soccer;
        cs.set_ball_bounce(b.ball_bounce as u8);
        cs.set_allow_bombs(b.allow_bombs as u8);
        cs.set_allow_guns(b.allow_guns as u8);
        cs.set_pass_delay(i16_(b.pass_delay));
        cs.set_ball_blank_delay(i16_(b.ball_blank_delay));
        cs.set_ball_location(b.ball_location as u8);
        cs.set_soccer_mode(b.mode);
        cs.set_use_flagger(b.use_flagger as u8);
        cs.set_disable_ball_through_walls(b.no_wall_pass as u8);
        cs.set_gravity_bombs(self.gravity_bombs as u8);
        cs.set_wormhole_switch_time(self.wormhole_switch_time.min(i32::MAX as u32) as i32);
        cs.set_near_death_level(i16_(self.near_death_level));
        cs.set_send_position_delay(20);
        cs.set_map_zoom_factor(10);
        cs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_settings_packet() {
        let mut cs = oss_proto::ClientSettings::default();
        cs.set_bounce_factor(22);
        cs.set_bullet_damage_level(200_000);
        cs.set_bullet_alive_time(550);
        cs.set_enter_delay(-5);
        cs.prize_weights[7] = 25;
        cs.ships[2].set_initial_speed(2010);
        cs.ships[2].set_radius(16);
        cs.ships[2].set_initial_guns(2);
        cs.ships[2].set_shrapnel_max(8);
        let a = ArenaSettings::from_client_settings(&cs);
        assert_eq!(a.bounce_factor, 22);
        assert_eq!(a.bullet_damage_level, 200);
        assert_eq!(a.bullet_alive_time, 550);
        assert_eq!(a.enter_delay, 0);
        assert_eq!(a.prize_weights[7], 25);
        assert_eq!(a.ships[2].initial_speed, 2010);
        assert_eq!(a.ships[2].radius_pixels(), 16);
        assert_eq!(a.ships[2].initial_guns, 2);
        assert_eq!(a.ships[2].shrapnel_max, 8);
        // Stock settings survive a round trip through the packet.
        let stock = ArenaSettings::default();
        assert_eq!(
            ArenaSettings::from_client_settings(&stock.to_client_settings()),
            stock
        );
        // A zero bounce factor must not divide by zero.
        cs.set_bounce_factor(0);
        assert_eq!(ArenaSettings::from_client_settings(&cs).bounce_factor, 1);
    }
}
