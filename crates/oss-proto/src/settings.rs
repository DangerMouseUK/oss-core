//! The arena settings packet (S2C `0x0F`), 1428 bytes.
//!
//! The layout is kept as the arrays the wire uses, so a server can fill it from
//! configuration generically (see the `*_KEYS` tables, which give the usual
//! `Section:Key` configuration name for each slot) and a client can read it
//! through the named accessors. Encoding is byte-exact: every bit of the packet,
//! padding included, is a field here.
//!
//! Layout (offsets in bytes):
//!
//! | Offset | Size | Contents |
//! |--------|------|----------|
//! | 0      | 4    | type byte `0x0F` + arena flag bits ([`ClientSettings::bits`]) |
//! | 4      | 1152 | 8 x [`ShipSettings`] (144 bytes each) |
//! | 1156   | 80   | 20 x `i32` ([`LONG_KEYS`]) |
//! | 1236   | 16   | 4 x spawn position bitfields ([`SpawnPosition`]) |
//! | 1252   | 116  | 58 x `i16` ([`SHORT_KEYS`]) |
//! | 1368   | 32   | 32 x `u8` ([`BYTE_KEYS`]) |
//! | 1400   | 28   | 28 x `u8` prize weights ([`PRIZE_WEIGHT_KEYS`]) |

use alloc::vec::Vec;

use crate::DecodeError;
use crate::wire::{Reader, Writer};

/// Type byte of the settings packet.
pub const SETTINGS_TYPE: u8 = 0x0F;
/// Encoded length of [`ClientSettings`].
pub const SETTINGS_LEN: usize = 1428;
/// Encoded length of one [`ShipSettings`].
pub const SHIP_SETTINGS_LEN: usize = 144;

/// Configuration section names of the eight ships, in ship-number order.
pub const SHIP_NAMES: [&str; 8] = [
    "Warbird",
    "Javelin",
    "Spider",
    "Leviathan",
    "Terrier",
    "Weasel",
    "Lancaster",
    "Shark",
];

/// Configuration names of [`ClientSettings::longs`]. Damage values marked
/// "x1000" are sent multiplied by 1000 relative to the configured value.
pub const LONG_KEYS: [&str; 20] = [
    "Bullet:BulletDamageLevel", // x1000
    "Bomb:BombDamageLevel",     // x1000
    "Bullet:BulletAliveTime",
    "Bomb:BombAliveTime",
    "Misc:DecoyAliveTime",
    "Misc:SafetyLimit",
    "Misc:FrequencyShift",
    "Team:MaxFrequency",
    "Repel:RepelSpeed",
    "Mine:MineAliveTime",
    "Burst:BurstDamageLevel",     // x1000
    "Bullet:BulletDamageUpgrade", // x1000
    "Flag:FlagDropDelay",
    "Flag:EnterGameFlaggingDelay",
    "Rocket:RocketThrust",
    "Rocket:RocketSpeed",
    "Shrapnel:InactiveShrapDamage", // x1000
    "Wormhole:SwitchTime",
    "Misc:ActivateAppShutdownTime",
    "Shrapnel:ShrapnelSpeed",
];

/// Indices of [`LONG_KEYS`] whose values are sent multiplied by 1000.
pub const LONG_KEYS_X1000: [usize; 5] = [0, 1, 10, 11, 16];

/// Configuration names of [`ClientSettings::shorts`].
pub const SHORT_KEYS: [&str; 58] = [
    "Latency:SendRoutePercent",
    "Bomb:BombExplodeDelay",
    "Misc:SendPositionDelay",
    "Bomb:BombExplodePixels",
    "Prize:DeathPrizeTime",
    "Bomb:JitterTime",
    "Kill:EnterDelay",
    "Prize:EngineShutdownTime",
    "Bomb:ProximityDistance",
    "Kill:BountyIncreaseForKill",
    "Misc:BounceFactor",
    "Radar:MapZoomFactor",
    "Kill:MaxBonus",
    "Kill:MaxPenalty",
    "Kill:RewardBase",
    "Repel:RepelTime",
    "Repel:RepelDistance",
    "Misc:TickerDelay",
    "Flag:FlaggerOnRadar",
    "Flag:FlaggerKillMultiplier",
    "Prize:PrizeFactor",
    "Prize:PrizeDelay",
    "Prize:MinimumVirtual",
    "Prize:UpgradeVirtual",
    "Prize:PrizeMaxExist",
    "Prize:PrizeMinExist",
    "Prize:PrizeNegativeFactor",
    "Door:DoorDelay",
    "Toggle:AntiWarpPixels",
    "Door:DoorMode",
    "Flag:FlagBlankDelay",
    "Flag:NoDataFlagDropDelay",
    "Prize:MultiPrizeCount",
    "Brick:BrickTime",
    "Misc:WarpRadiusLimit",
    "Bomb:EBombShutdownTime",
    "Bomb:EBombDamagePercent",
    "Radar:RadarNeutralSize",
    "Misc:WarpPointDelay",
    "Misc:NearDeathLevel",
    "Bomb:BBombDamagePercent",
    "Shrapnel:ShrapnelDamagePercent",
    "Latency:ClientSlowPacketTime",
    "Flag:FlagDropResetReward",
    "Flag:FlaggerFireCostPercent",
    "Flag:FlaggerDamagePercent",
    "Flag:FlaggerBombFireDelay",
    "Soccer:PassDelay",
    "Soccer:BallBlankDelay",
    "Latency:S2CNoDataKickoutDelay",
    "Flag:FlaggerThrustAdjustment",
    "Flag:FlaggerSpeedAdjustment",
    "Latency:ClientSlowPacketSampleSize",
    "Unused:Unused5",
    "Unused:Unused4",
    "Unused:Unused3",
    "Unused:Unused2",
    "Unused:Unused1",
];

/// Configuration names of [`ClientSettings::bytes`].
pub const BYTE_KEYS: [&str; 32] = [
    "Shrapnel:Random",
    "Soccer:BallBounce",
    "Soccer:AllowBombs",
    "Soccer:AllowGuns",
    "Soccer:Mode",
    "Team:MaxPerTeam",
    "Team:MaxPerPrivateTeam",
    "Mine:TeamMaxMines",
    "Wormhole:GravityBombs",
    "Bomb:BombSafety",
    "Chat:MessageReliable",
    "Prize:TakePrizeReliable",
    "Message:AllowAudioMessages",
    "Prize:PrizeHideCount",
    "Misc:ExtraPositionData",
    "Misc:SlowFrameCheck",
    "Flag:CarryFlags",
    "Misc:AllowSavedShips",
    "Radar:RadarMode",
    "Misc:VictoryMusic",
    "Flag:FlaggerGunUpgrade",
    "Flag:FlaggerBombUpgrade",
    "Soccer:UseFlagger",
    "Soccer:BallLocation",
    "Misc:AntiWarpSettleDelay",
    "Unused:Unused7",
    "Unused:Unused6",
    "Unused:Unused5",
    "Unused:Unused4",
    "Unused:Unused3",
    "Unused:Unused2",
    "Unused:Unused1",
];

/// Configuration names of [`ClientSettings::prize_weights`] (section `PrizeWeight`).
pub const PRIZE_WEIGHT_KEYS: [&str; 28] = [
    "PrizeWeight:QuickCharge",
    "PrizeWeight:Energy",
    "PrizeWeight:Rotation",
    "PrizeWeight:Stealth",
    "PrizeWeight:Cloak",
    "PrizeWeight:XRadar",
    "PrizeWeight:Warp",
    "PrizeWeight:Gun",
    "PrizeWeight:Bomb",
    "PrizeWeight:BouncingBullets",
    "PrizeWeight:Thruster",
    "PrizeWeight:TopSpeed",
    "PrizeWeight:Recharge",
    "PrizeWeight:Glue",
    "PrizeWeight:MultiFire",
    "PrizeWeight:Proximity",
    "PrizeWeight:AllWeapons",
    "PrizeWeight:Shields",
    "PrizeWeight:Shrapnel",
    "PrizeWeight:AntiWarp",
    "PrizeWeight:Repel",
    "PrizeWeight:Burst",
    "PrizeWeight:Decoy",
    "PrizeWeight:Thor",
    "PrizeWeight:MultiPrize",
    "PrizeWeight:Brick",
    "PrizeWeight:Rocket",
    "PrizeWeight:Portal",
];

/// Key names (within the ship's section) of [`ShipSettings::longs`].
pub const SHIP_LONG_KEYS: [&str; 2] = ["SuperTime", "ShieldsTime"];

/// Index of the packed bitfield inside [`ShipSettings::shorts`].
pub const SHIP_MISC_BITS_INDEX: usize = 10;

/// Key names of [`ShipSettings::shorts`]. Slot [`SHIP_MISC_BITS_INDEX`] is not a
/// single setting: it packs `SeeBombLevel`, `DisableFastShooting` and `Radius`.
pub const SHIP_SHORT_KEYS: [&str; 49] = [
    "Gravity",
    "GravityTopSpeed",
    "BulletFireEnergy",
    "MultiFireEnergy",
    "BombFireEnergy",
    "BombFireEnergyUpgrade",
    "LandmineFireEnergy",
    "LandmineFireEnergyUpgrade",
    "BulletSpeed",
    "BombSpeed",
    "",
    "MultiFireAngle",
    "CloakEnergy",
    "StealthEnergy",
    "AntiWarpEnergy",
    "XRadarEnergy",
    "MaximumRotation",
    "MaximumThrust",
    "MaximumSpeed",
    "MaximumRecharge",
    "MaximumEnergy",
    "InitialRotation",
    "InitialThrust",
    "InitialSpeed",
    "InitialRecharge",
    "InitialEnergy",
    "UpgradeRotation",
    "UpgradeThrust",
    "UpgradeSpeed",
    "UpgradeRecharge",
    "UpgradeEnergy",
    "AfterburnerEnergy",
    "BombThrust",
    "BurstSpeed",
    "TurretThrustPenalty",
    "TurretSpeedPenalty",
    "BulletFireDelay",
    "MultiFireDelay",
    "BombFireDelay",
    "LandmineFireDelay",
    "RocketTime",
    "InitialBounty",
    "DamageFactor",
    "PrizeShareLimit",
    "AttachBounty",
    "SoccerThrowTime",
    "SoccerBallFriction",
    "SoccerBallProximity",
    "SoccerBallSpeed",
];

/// Key names of [`ShipSettings::bytes`].
pub const SHIP_BYTE_KEYS: [&str; 18] = [
    "TurretLimit",
    "BurstShrapnel",
    "MaxMines",
    "RepelMax",
    "BurstMax",
    "DecoyMax",
    "ThorMax",
    "BrickMax",
    "RocketMax",
    "PortalMax",
    "InitialRepel",
    "InitialBurst",
    "InitialBrick",
    "InitialRocket",
    "InitialThor",
    "InitialDecoy",
    "InitialPortal",
    "BombBounceCount",
];

/// Key names, bit offsets and widths of the fields packed in
/// [`ShipSettings::weapons`]: `(key, lowest bit, width)`.
pub const SHIP_WEAPON_BITS: [(&str, u32, u32); 13] = [
    ("ShrapnelMax", 0, 5),
    ("ShrapnelRate", 5, 5),
    ("CloakStatus", 10, 2),
    ("StealthStatus", 12, 2),
    ("XRadarStatus", 14, 2),
    ("AntiWarpStatus", 16, 2),
    ("InitialGuns", 18, 2),
    ("MaxGuns", 20, 2),
    ("InitialBombs", 22, 2),
    ("MaxBombs", 24, 2),
    ("DoubleBarrel", 26, 1),
    ("EmpBomb", 27, 1),
    ("SeeMines", 28, 1),
];

/// Key names, bit offsets and widths of the fields packed in the ship's misc
/// short ([`SHIP_MISC_BITS_INDEX`]).
pub const SHIP_MISC_BITS: [(&str, u32, u32); 3] = [
    ("SeeBombLevel", 0, 2),
    ("DisableFastShooting", 2, 1),
    ("Radius", 3, 8),
];

/// Configuration names, bit offsets and widths of [`ClientSettings::bits`].
/// Bits 0-7 hold the packet type and are not settings.
pub const ARENA_BITS: [(&str, u32, u32); 8] = [
    ("Bullet:ExactDamage", 8, 1),
    ("Spectator:HideFlags", 9, 1),
    ("Spectator:NoXRadar", 10, 1),
    ("Misc:SlowFrameCheck", 11, 3),
    ("Misc:DisableScreenshot", 14, 1),
    ("Misc:MaxTimerDrift", 16, 3),
    ("Soccer:DisableWallPass", 19, 1),
    ("Soccer:DisableBallKilling", 20, 1),
];

/// Reads `width` bits at `lo`.
pub const fn get_bits(word: u32, lo: u32, width: u32) -> u32 {
    (word >> lo) & ((1u32 << width) - 1)
}

/// Returns `word` with `width` bits at `lo` replaced by the low bits of `value`.
pub const fn set_bits(word: u32, lo: u32, width: u32, value: u32) -> u32 {
    let mask = ((1u32 << width) - 1) << lo;
    (word & !mask) | ((value << lo) & mask)
}

macro_rules! array_accessors {
    ($arr:ident: $( $idx:literal => $get:ident, $set:ident : $ty:ty, $doc:literal; )*) => {
        $(
            #[doc = $doc]
            #[allow(clippy::unnecessary_cast)]
            pub fn $get(&self) -> $ty {
                self.$arr[$idx] as $ty
            }
            #[doc = concat!("Sets: ", $doc)]
            #[allow(clippy::unnecessary_cast)]
            pub fn $set(&mut self, v: $ty) {
                self.$arr[$idx] = v as _;
            }
        )*
    };
}

macro_rules! bit_accessors {
    ($word:ident [$idx:literal]: $( $lo:literal, $w:literal => $get:ident, $set:ident : $ty:ty, $doc:literal; )*) => {
        $(
            #[doc = $doc]
            pub fn $get(&self) -> $ty {
                get_bits(u32::from(self.$word[$idx] as u16), $lo, $w) as $ty
            }
            #[doc = concat!("Sets: ", $doc)]
            pub fn $set(&mut self, v: $ty) {
                let w = set_bits(u32::from(self.$word[$idx] as u16), $lo, $w, u32::from(v));
                self.$word[$idx] = w as u16 as i16;
            }
        )*
    };
}

macro_rules! word_bits {
    ($word:ident: $( $lo:literal, $w:literal => $get:ident, $set:ident : $ty:ty, $doc:literal; )*) => {
        $(
            #[doc = $doc]
            pub fn $get(&self) -> $ty {
                get_bits(self.$word, $lo, $w) as $ty
            }
            #[doc = concat!("Sets: ", $doc)]
            pub fn $set(&mut self, v: $ty) {
                self.$word = set_bits(self.$word, $lo, $w, v as u32);
            }
        )*
    };
}

/// Per-ship settings, 144 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShipSettings {
    /// [`SHIP_LONG_KEYS`] values.
    pub longs: [i32; 2],
    /// [`SHIP_SHORT_KEYS`] values; slot 10 is the misc bitfield.
    pub shorts: [i16; 49],
    /// [`SHIP_BYTE_KEYS`] values.
    pub bytes: [u8; 18],
    /// Packed weapon fields ([`SHIP_WEAPON_BITS`]); bits 29-31 unused.
    pub weapons: u32,
    /// Trailing bytes with no known meaning (sent as configured, normally 0).
    pub padding: [u8; 16],
}

impl Default for ShipSettings {
    fn default() -> Self {
        Self {
            longs: [0; 2],
            shorts: [0; 49],
            bytes: [0; 18],
            weapons: 0,
            padding: [0; 16],
        }
    }
}

impl ShipSettings {
    array_accessors! { longs:
        0 => super_time, set_super_time: i32, "How long Super lasts (ticks).";
        1 => shields_time, set_shields_time: i32, "How long Shields last (ticks).";
    }

    array_accessors! { shorts:
        0 => gravity, set_gravity: i16, "Wormhole pull on this ship (0 = none).";
        1 => gravity_top_speed, set_gravity_top_speed: i16, "Extra speed allowed while pulled by a wormhole.";
        2 => bullet_fire_energy, set_bullet_fire_energy: u16, "Energy to fire one L1 bullet.";
        3 => multi_fire_energy, set_multi_fire_energy: u16, "Energy to fire multifire L1 bullets.";
        4 => bomb_fire_energy, set_bomb_fire_energy: u16, "Energy to fire one L1 bomb.";
        5 => bomb_fire_energy_upgrade, set_bomb_fire_energy_upgrade: u16, "Extra energy per bomb level.";
        6 => landmine_fire_energy, set_landmine_fire_energy: u16, "Energy to place one L1 mine.";
        7 => landmine_fire_energy_upgrade, set_landmine_fire_energy_upgrade: u16, "Extra energy per mine level.";
        8 => bullet_speed, set_bullet_speed: u16, "Bullet speed.";
        9 => bomb_speed, set_bomb_speed: u16, "Bomb speed.";
        11 => multi_fire_angle, set_multi_fire_angle: u16, "Angle between multifire and forward bullets (111 = 1 degree).";
        12 => cloak_energy, set_cloak_energy: u16, "Cloak upkeep (thousandths of energy per tick).";
        13 => stealth_energy, set_stealth_energy: u16, "Stealth upkeep.";
        14 => anti_warp_energy, set_anti_warp_energy: u16, "Antiwarp upkeep.";
        15 => xradar_energy, set_xradar_energy: u16, "X-radar upkeep.";
        16 => maximum_rotation, set_maximum_rotation: u16, "Maximum rotation rate (400 = one turn per second).";
        17 => maximum_thrust, set_maximum_thrust: u16, "Maximum thrust.";
        18 => maximum_speed, set_maximum_speed: u16, "Maximum speed.";
        19 => maximum_recharge, set_maximum_recharge: u16, "Maximum recharge rate.";
        20 => maximum_energy, set_maximum_energy: u16, "Maximum energy.";
        21 => initial_rotation, set_initial_rotation: u16, "Initial rotation rate.";
        22 => initial_thrust, set_initial_thrust: u16, "Initial thrust.";
        23 => initial_speed, set_initial_speed: u16, "Initial speed.";
        24 => initial_recharge, set_initial_recharge: u16, "Initial recharge rate.";
        25 => initial_energy, set_initial_energy: u16, "Initial energy.";
        26 => upgrade_rotation, set_upgrade_rotation: u16, "Rotation added per prize.";
        27 => upgrade_thrust, set_upgrade_thrust: u16, "Thrust added per prize.";
        28 => upgrade_speed, set_upgrade_speed: u16, "Speed added per prize.";
        29 => upgrade_recharge, set_upgrade_recharge: u16, "Recharge added per prize.";
        30 => upgrade_energy, set_upgrade_energy: u16, "Energy added per prize.";
        31 => afterburner_energy, set_afterburner_energy: u16, "Afterburner upkeep.";
        32 => bomb_thrust, set_bomb_thrust: u16, "Recoil from firing a bomb.";
        33 => burst_speed, set_burst_speed: u16, "Burst shrapnel speed.";
        34 => turret_thrust_penalty, set_turret_thrust_penalty: i16, "Thrust lost per attached turret.";
        35 => turret_speed_penalty, set_turret_speed_penalty: i16, "Speed lost per attached turret.";
        36 => bullet_fire_delay, set_bullet_fire_delay: u16, "Delay after a bullet (ticks).";
        37 => multi_fire_delay, set_multi_fire_delay: u16, "Delay after multifire (ticks).";
        38 => bomb_fire_delay, set_bomb_fire_delay: u16, "Delay after a bomb (ticks).";
        39 => landmine_fire_delay, set_landmine_fire_delay: u16, "Delay after a mine (ticks).";
        40 => rocket_time, set_rocket_time: u16, "How long a rocket lasts (ticks).";
        41 => initial_bounty, set_initial_bounty: u16, "Bounty on spawn.";
        42 => damage_factor, set_damage_factor: u16, "How easily the ship loses prizes when hit (0 = never).";
        43 => prize_share_limit, set_prize_share_limit: u16, "Maximum bounty that still receives team prizes.";
        44 => attach_bounty, set_attach_bounty: u16, "Bounty needed to attach as a turret.";
        45 => soccer_throw_time, set_soccer_throw_time: u16, "Time the ball can be carried (ticks).";
        46 => soccer_ball_friction, set_soccer_ball_friction: u16, "Ball friction.";
        47 => soccer_ball_proximity, set_soccer_ball_proximity: u16, "Ball pickup distance (pixels).";
        48 => soccer_ball_speed, set_soccer_ball_speed: u16, "Ball speed when fired.";
    }

    array_accessors! { bytes:
        0 => turret_limit, set_turret_limit: u8, "Turrets allowed on this ship.";
        1 => burst_shrapnel, set_burst_shrapnel: u8, "Bullets in a burst.";
        2 => max_mines, set_max_mines: u8, "Mines this ship may have placed.";
        3 => repel_max, set_repel_max: u8, "Maximum repels.";
        4 => burst_max, set_burst_max: u8, "Maximum bursts.";
        5 => decoy_max, set_decoy_max: u8, "Maximum decoys.";
        6 => thor_max, set_thor_max: u8, "Maximum thors.";
        7 => brick_max, set_brick_max: u8, "Maximum bricks.";
        8 => rocket_max, set_rocket_max: u8, "Maximum rockets.";
        9 => portal_max, set_portal_max: u8, "Maximum portals.";
        10 => initial_repel, set_initial_repel: u8, "Repels on spawn.";
        11 => initial_burst, set_initial_burst: u8, "Bursts on spawn.";
        12 => initial_brick, set_initial_brick: u8, "Bricks on spawn.";
        13 => initial_rocket, set_initial_rocket: u8, "Rockets on spawn.";
        14 => initial_thor, set_initial_thor: u8, "Thors on spawn.";
        15 => initial_decoy, set_initial_decoy: u8, "Decoys on spawn.";
        16 => initial_portal, set_initial_portal: u8, "Portals on spawn.";
        17 => bomb_bounce_count, set_bomb_bounce_count: u8, "Wall bounces before bombs explode on impact.";
    }

    bit_accessors! { shorts[10]:
        0, 2 => see_bomb_level, set_see_bomb_level: u8, "Bombs visible on radar (0 none, 1 all, 2 L2 and up, 3 L3 and up).";
        2, 1 => disable_fast_shooting, set_disable_fast_shooting: u8, "Firing is blocked while afterburners are on (1).";
        3, 8 => radius, set_radius: u8, "Ship radius in pixels (0 means the default 14).";
    }

    word_bits! { weapons:
        0, 5 => shrapnel_max, set_shrapnel_max: u8, "Maximum shrapnel per bomb.";
        5, 5 => shrapnel_rate, set_shrapnel_rate: u8, "Shrapnel added per prize.";
        10, 2 => cloak_status, set_cloak_status: u8, "Cloak availability (0 no, 1 can be prized, 2 initial).";
        12, 2 => stealth_status, set_stealth_status: u8, "Stealth availability.";
        14, 2 => xradar_status, set_xradar_status: u8, "X-radar availability.";
        16, 2 => anti_warp_status, set_anti_warp_status: u8, "Antiwarp availability.";
        18, 2 => initial_guns, set_initial_guns: u8, "Gun level on spawn (0-3).";
        20, 2 => max_guns, set_max_guns: u8, "Maximum gun level.";
        22, 2 => initial_bombs, set_initial_bombs: u8, "Bomb level on spawn (0-3).";
        24, 2 => max_bombs, set_max_bombs: u8, "Maximum bomb level.";
        26, 1 => double_barrel, set_double_barrel: u8, "Guns fire two bullets (1).";
        27, 1 => emp_bomb, set_emp_bomb: u8, "Bombs are EMP (1).";
        28, 1 => see_mines, set_see_mines: u8, "Mines show on radar (1).";
    }

    /// Effective radius in pixels (the default 14 when the setting is 0).
    pub fn effective_radius(&self) -> u8 {
        match self.radius() {
            0 => 14,
            r => r,
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let mut s = Self::default();
        for v in &mut s.longs {
            *v = r.i32()?;
        }
        for v in &mut s.shorts {
            *v = r.i16()?;
        }
        s.bytes = r.array()?;
        s.weapons = r.u32()?;
        s.padding = r.array()?;
        Ok(s)
    }

    fn write(&self, out: &mut Vec<u8>) {
        self.longs.iter().for_each(|&v| out.put_i32(v));
        self.shorts.iter().for_each(|&v| out.put_i16(v));
        out.put_bytes(&self.bytes);
        out.put_u32(self.weapons);
        out.put_bytes(&self.padding);
    }
}

/// A team's spawn area: a packed `u32` (x: 10 bits, y: 10 bits, radius: 9 bits,
/// 3 unused bits), all in tiles. Zero means "use the default".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpawnPosition(pub u32);

impl SpawnPosition {
    /// Builds a spawn position; values are truncated to their bit widths.
    pub fn new(x: u16, y: u16, radius: u16) -> Self {
        let w = set_bits(0, 0, 10, x.into());
        let w = set_bits(w, 10, 10, y.into());
        Self(set_bits(w, 20, 9, radius.into()))
    }
    /// Centre x tile.
    pub fn x(self) -> u16 {
        get_bits(self.0, 0, 10) as u16
    }
    /// Centre y tile.
    pub fn y(self) -> u16 {
        get_bits(self.0, 10, 10) as u16
    }
    /// Radius in tiles.
    pub fn radius(self) -> u16 {
        get_bits(self.0, 20, 9) as u16
    }
}

/// The arena settings packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSettings {
    /// The first 32-bit word: bits 0-7 are the packet type (always written as
    /// `0x0F`), the rest are [`ARENA_BITS`].
    pub bits: u32,
    /// Ship settings in ship-number order (see [`SHIP_NAMES`]).
    pub ships: [ShipSettings; 8],
    /// [`LONG_KEYS`] values.
    pub longs: [i32; 20],
    /// Spawn areas for frequencies 0-3.
    pub spawns: [SpawnPosition; 4],
    /// [`SHORT_KEYS`] values.
    pub shorts: [i16; 58],
    /// [`BYTE_KEYS`] values.
    pub bytes: [u8; 32],
    /// [`PRIZE_WEIGHT_KEYS`] values.
    pub prize_weights: [u8; 28],
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            bits: u32::from(SETTINGS_TYPE),
            ships: [ShipSettings::default(); 8],
            longs: [0; 20],
            spawns: [SpawnPosition::default(); 4],
            shorts: [0; 58],
            bytes: [0; 32],
            prize_weights: [0; 28],
        }
    }
}

impl ClientSettings {
    word_bits! { bits:
        8, 1 => exact_damage, set_exact_damage: u8, "Bullet damage is exact rather than random (1).";
        9, 1 => hide_flags, set_hide_flags: u8, "Spectators cannot see dropped flags (1).";
        10, 1 => no_xradar, set_no_xradar: u8, "Spectators get no X-radar (1).";
        11, 3 => slow_frame_rate, set_slow_frame_rate: u8, "Slow-frame check threshold (configured as Misc:SlowFrameCheck).";
        14, 1 => disable_screenshot, set_disable_screenshot: u8, "Disables the client's screenshot key (1).";
        16, 3 => max_timer_drift, set_max_timer_drift: u8, "Allowed client timer drift.";
        19, 1 => disable_ball_through_walls, set_disable_ball_through_walls: u8, "Balls cannot be passed through walls (1).";
        20, 1 => disable_ball_killing, set_disable_ball_killing: u8, "Disables ball killing (1).";
    }

    array_accessors! { longs:
        0 => bullet_damage_level, set_bullet_damage_level: i32, "Maximum L1 bullet damage (x1000 on the wire).";
        1 => bomb_damage_level, set_bomb_damage_level: i32, "Bomb damage at the centre (x1000).";
        2 => bullet_alive_time, set_bullet_alive_time: i32, "Bullet lifetime (ticks).";
        3 => bomb_alive_time, set_bomb_alive_time: i32, "Bomb lifetime (ticks).";
        4 => decoy_alive_time, set_decoy_alive_time: i32, "Decoy lifetime (ticks).";
        5 => safety_limit, set_safety_limit: i32, "Time allowed in a safe zone (ticks).";
        6 => frequency_shift, set_frequency_shift: i32, "Random pitch shift applied to sounds.";
        7 => max_frequency, set_max_frequency: i32, "One more than the highest allowed frequency.";
        8 => repel_speed, set_repel_speed: i32, "Speed players are repelled at.";
        9 => mine_alive_time, set_mine_alive_time: i32, "Mine lifetime (ticks).";
        10 => burst_damage_level, set_burst_damage_level: i32, "Maximum burst bullet damage (x1000).";
        11 => bullet_damage_upgrade, set_bullet_damage_upgrade: i32, "Extra damage per bullet level (x1000).";
        12 => flag_drop_delay, set_flag_drop_delay: i32, "Time before a carrier drops flags (0 = never).";
        13 => enter_game_flagging_delay, set_enter_game_flagging_delay: i32, "Time a new player waits before seeing flags.";
        14 => rocket_thrust, set_rocket_thrust: i32, "Thrust while a rocket is active.";
        15 => rocket_speed, set_rocket_speed: i32, "Speed while a rocket is active.";
        16 => inactive_shrap_damage, set_inactive_shrap_damage: i32, "Shrapnel damage in its first quarter second (x1000).";
        17 => wormhole_switch_time, set_wormhole_switch_time: i32, "How often wormholes change destination.";
        18 => activate_app_shutdown_time, set_activate_app_shutdown_time: i32, "Shutdown after the client regains focus (ticks).";
        19 => shrapnel_speed, set_shrapnel_speed: i32, "Shrapnel speed.";
    }

    array_accessors! { shorts:
        0 => send_route_percent, set_send_route_percent: i16, "Share of ping spent client-to-server, for clock sync.";
        1 => bomb_explode_delay, set_bomb_explode_delay: i16, "Delay from proximity trigger to explosion.";
        2 => send_position_delay, set_send_position_delay: i16, "Ticks between client position packets.";
        3 => bomb_explode_pixels, set_bomb_explode_pixels: i16, "L1 blast radius in pixels.";
        4 => death_prize_time, set_death_prize_time: i16, "Lifetime of the prize left by a kill.";
        5 => jitter_time, set_jitter_time: i16, "Screen shake after a bomb hit (ticks).";
        6 => enter_delay, set_enter_delay: i16, "Respawn delay after death (ticks).";
        7 => engine_shutdown_time, set_engine_shutdown_time: i16, "Engine shutdown duration (ticks).";
        8 => proximity_distance, set_proximity_distance: i16, "Proximity trigger radius in tiles.";
        9 => bounty_increase_for_kill, set_bounty_increase_for_kill: i16, "Bounty gained per kill.";
        10 => bounce_factor, set_bounce_factor: i16, "Wall bounciness (16 = no speed loss).";
        11 => map_zoom_factor, set_map_zoom_factor: i16, "Radar zoom (48 = whole map).";
        12 => max_bonus, set_max_bonus: i16, "Kill reward bonus cap.";
        13 => max_penalty, set_max_penalty: i16, "Kill reward penalty cap.";
        14 => reward_base, set_reward_base: i16, "Base kill reward.";
        15 => repel_time, set_repel_time: i16, "Repel effect duration (ticks).";
        16 => repel_distance, set_repel_distance: i16, "Repel radius in pixels.";
        17 => ticker_delay, set_ticker_delay: i16, "Time between ticker help messages.";
        18 => flagger_on_radar, set_flagger_on_radar: i16, "Flag carriers show red on radar.";
        19 => flagger_kill_multiplier, set_flagger_kill_multiplier: i16, "Extra kill points for flaggers.";
        20 => prize_factor, set_prize_factor: i16, "Prizes per player factor.";
        21 => prize_delay, set_prize_delay: i16, "Prize regeneration period (ticks).";
        22 => minimum_virtual, set_minimum_virtual: i16, "Prize/flag spawn distance from the centre.";
        23 => upgrade_virtual, set_upgrade_virtual: i16, "Spawn distance added per player.";
        24 => prize_max_exist, set_prize_max_exist: i16, "Longest prize lifetime.";
        25 => prize_min_exist, set_prize_min_exist: i16, "Shortest prize lifetime.";
        26 => prize_negative_factor, set_prize_negative_factor: i16, "Odds of a negative prize.";
        27 => door_delay, set_door_delay: i16, "How often doors change.";
        28 => anti_warp_pixels, set_anti_warp_pixels: i16, "Antiwarp radius in pixels.";
        29 => door_mode, set_door_mode: i16, "Door mode (-2 random, -1 weighted, 0-255 fixed bits).";
        30 => flag_blank_delay, set_flag_blank_delay: i16, "No-data time before flags are hidden.";
        31 => no_data_flag_drop_delay, set_no_data_flag_drop_delay: i16, "No-data time before carried flags drop.";
        32 => multi_prize_count, set_multi_prize_count: i16, "Prizes given by a multiprize.";
        33 => brick_time, set_brick_time: i16, "Brick lifetime (ticks).";
        34 => warp_radius_limit, set_warp_radius_limit: i16, "Random warp distance limit from the centre.";
        35 => ebomb_shutdown_time, set_ebomb_shutdown_time: i16, "Longest recharge stop from an EMP hit.";
        36 => ebomb_damage_percent, set_ebomb_damage_percent: i16, "EMP damage (0.1% units).";
        37 => radar_neutral_size, set_radar_neutral_size: i16, "Neutral area between radar zones (pixels).";
        38 => warp_point_delay, set_warp_point_delay: i16, "Portal lifetime.";
        39 => near_death_level, set_near_death_level: i16, "Energy counted as a near death.";
        40 => bbomb_damage_percent, set_bbomb_damage_percent: i16, "Bouncing bomb damage (0.1% units).";
        41 => shrapnel_damage_percent, set_shrapnel_damage_percent: i16, "Shrapnel damage relative to bullets (0.1%).";
        42 => client_slow_packet_time, set_client_slow_packet_time: i16, "Latency counted as a slow packet.";
        43 => flag_drop_reset_reward, set_flag_drop_reset_reward: i16, "Kill reward that resets the flag drop timer.";
        44 => flagger_fire_cost_percent, set_flagger_fire_cost_percent: i16, "Flagger weapon cost (0.1%).";
        45 => flagger_damage_percent, set_flagger_damage_percent: i16, "Damage taken by flaggers (0.1%).";
        46 => flagger_bomb_fire_delay, set_flagger_bomb_fire_delay: i16, "Flagger bomb delay.";
        47 => pass_delay, set_pass_delay: i16, "Ticks before a fired ball can be caught.";
        48 => ball_blank_delay, set_ball_blank_delay: i16, "No-data time before the ball cannot be picked up.";
        49 => s2c_no_data_kickout_delay, set_s2c_no_data_kickout_delay: i16, "No-data time before the client disconnects.";
        50 => flagger_thrust_adjustment, set_flagger_thrust_adjustment: i16, "Thrust change for flaggers.";
        51 => flagger_speed_adjustment, set_flagger_speed_adjustment: i16, "Speed change for flaggers.";
        52 => client_slow_packet_sample_size, set_client_slow_packet_sample_size: i16, "Packets sampled for slow-packet kicks.";
    }

    array_accessors! { bytes:
        0 => shrapnel_random, set_shrapnel_random: u8, "Shrapnel spreads randomly rather than evenly.";
        1 => ball_bounce, set_ball_bounce: u8, "The ball bounces off walls.";
        2 => allow_bombs, set_allow_bombs: u8, "Ball carriers may fire bombs.";
        3 => allow_guns, set_allow_guns: u8, "Ball carriers may fire guns.";
        4 => soccer_mode, set_soccer_mode: u8, "Goal layout.";
        5 => max_per_team, set_max_per_team: u8, "Players allowed on a public team.";
        6 => max_per_private_team, set_max_per_private_team: u8, "Players allowed on a private team.";
        7 => team_max_mines, set_team_max_mines: u8, "Mines a whole team may have placed.";
        8 => gravity_bombs, set_gravity_bombs: u8, "Wormholes pull bombs.";
        9 => bomb_safety, set_bomb_safety: u8, "Proximity bombs cannot be fired with an enemy in range.";
        10 => message_reliable, set_message_reliable: u8, "Chat is sent reliably.";
        11 => take_prize_reliable, set_take_prize_reliable: u8, "Prize pickups are sent reliably.";
        12 => allow_audio_messages, set_allow_audio_messages: u8, "Voice messages allowed.";
        13 => prize_hide_count, set_prize_hide_count: u8, "Prizes regenerated each prize period.";
        14 => extra_position_data, set_extra_position_data: u8, "Players receive extra (sysop) position data.";
        15 => slow_frame_check, set_slow_frame_check: u8, "Client checks for slow frames.";
        16 => carry_flags, set_carry_flags: u8, "Flag carrying mode (0 no, 1 yes, n = n-1 at a time).";
        17 => allow_saved_ships, set_allow_saved_ships: u8, "Saved ships allowed.";
        18 => radar_mode, set_radar_mode: u8, "Radar mode.";
        19 => victory_music, set_victory_music: u8, "Play victory music.";
        20 => flagger_gun_upgrade, set_flagger_gun_upgrade: u8, "Flaggers get a gun upgrade.";
        21 => flagger_bomb_upgrade, set_flagger_bomb_upgrade: u8, "Flaggers get a bomb upgrade.";
        22 => use_flagger, set_use_flagger: u8, "Ball carriers get flagger adjustments.";
        23 => ball_location, set_ball_location: u8, "The ball's location is always shown.";
        24 => anti_warp_settle_delay, set_anti_warp_settle_delay: u8, "Fake antiwarp ticks after attach/portal/warp.";
    }

    /// Decodes the packet (type byte included).
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let found = *data.first().ok_or(DecodeError::Empty)?;
        if found != SETTINGS_TYPE {
            return Err(DecodeError::WrongType {
                expected: SETTINGS_TYPE,
                found,
            });
        }
        if data.len() < SETTINGS_LEN {
            return Err(DecodeError::Truncated {
                kind: SETTINGS_TYPE,
                need: SETTINGS_LEN,
                have: data.len(),
            });
        }
        let mut r = Reader::new(data, SETTINGS_TYPE);
        let bits = r.u32()?;
        let mut ships = [ShipSettings::default(); 8];
        for s in &mut ships {
            *s = ShipSettings::read(&mut r)?;
        }
        let mut s = Self {
            bits,
            ships,
            ..Self::default()
        };
        for v in &mut s.longs {
            *v = r.i32()?;
        }
        for v in &mut s.spawns {
            *v = SpawnPosition(r.u32()?);
        }
        for v in &mut s.shorts {
            *v = r.i16()?;
        }
        s.bytes = r.array()?;
        s.prize_weights = r.array()?;
        Ok(s)
    }

    /// Appends the encoded packet (always [`SETTINGS_LEN`] bytes).
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(SETTINGS_LEN);
        out.put_u32((self.bits & !0xFF) | u32::from(SETTINGS_TYPE));
        self.ships.iter().for_each(|s| s.write(out));
        self.longs.iter().for_each(|&v| out.put_i32(v));
        self.spawns.iter().for_each(|v| out.put_u32(v.0));
        self.shorts.iter().for_each(|&v| out.put_i16(v));
        out.put_bytes(&self.bytes);
        out.put_bytes(&self.prize_weights);
    }

    /// The encoded packet.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SETTINGS_LEN);
        self.encode(&mut v);
        v
    }

    /// Sum of the prize weights (the denominator when picking a random prize).
    pub fn prize_weight_total(&self) -> u32 {
        self.prize_weights.iter().map(|&w| u32::from(w)).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_offsets() {
        let mut s = ClientSettings::default();
        s.ships[0].longs[0] = 0x0101_0101;
        s.ships[7].padding[15] = 0xEE;
        s.longs[0] = 0x0202_0202;
        s.spawns[0] = SpawnPosition(0x0303_0303);
        s.shorts[0] = 0x0404;
        s.bytes[0] = 0x05;
        s.prize_weights[27] = 0x06;
        let b = s.to_bytes();
        assert_eq!(b.len(), SETTINGS_LEN);
        assert_eq!(b[0], 0x0F);
        assert_eq!(b[4], 0x01);
        assert_eq!(b[4 + 8 * SHIP_SETTINGS_LEN - 1], 0xEE);
        assert_eq!(b[1156], 0x02);
        assert_eq!(b[1236], 0x03);
        assert_eq!(b[1252], 0x04);
        assert_eq!(b[1368], 0x05);
        assert_eq!(b[1427], 0x06);
    }

    #[test]
    fn round_trip_every_byte() {
        // Fill every byte with a distinct pattern and check decode/encode is exact.
        let mut raw: Vec<u8> = (0..SETTINGS_LEN).map(|i| (i * 31 + 7) as u8).collect();
        raw[0] = SETTINGS_TYPE;
        let s = ClientSettings::decode(&raw).unwrap();
        assert_eq!(s.to_bytes(), raw);
    }

    #[test]
    fn accessors() {
        let mut s = ClientSettings::default();
        s.ships[2].set_maximum_speed(3000);
        s.ships[2].set_radius(20);
        s.ships[2].set_see_bomb_level(2);
        s.ships[2].set_disable_fast_shooting(1);
        s.ships[2].set_max_guns(3);
        s.ships[2].set_see_mines(1);
        s.set_max_timer_drift(5);
        s.set_exact_damage(1);
        s.set_door_mode(-2);
        s.spawns[1] = SpawnPosition::new(512, 1000, 300);
        let back = ClientSettings::decode(&s.to_bytes()).unwrap();
        let sh = &back.ships[2];
        assert_eq!(sh.maximum_speed(), 3000);
        assert_eq!(sh.shorts[18], 3000);
        assert_eq!(
            (sh.radius(), sh.see_bomb_level(), sh.disable_fast_shooting()),
            (20, 2, 1)
        );
        assert_eq!(sh.shorts[SHIP_MISC_BITS_INDEX], (20 << 3) | (1 << 2) | 2);
        assert_eq!((sh.max_guns(), sh.see_mines()), (3, 1));
        assert_eq!(back.max_timer_drift(), 5);
        assert_eq!(back.exact_damage(), 1);
        assert_eq!(back.bits & 0xFF, 0x0F);
        assert_eq!(back.door_mode(), -2);
        let sp = back.spawns[1];
        assert_eq!((sp.x(), sp.y(), sp.radius()), (512, 1000, 300));
        assert_eq!(back.ships[0].effective_radius(), 14);
    }

    #[test]
    fn decode_errors() {
        assert!(ClientSettings::decode(&[]).is_err());
        assert!(ClientSettings::decode(&[0x0F; 100]).is_err());
        assert!(ClientSettings::decode(&[0x0E; SETTINGS_LEN]).is_err());
    }

    #[test]
    fn key_tables_are_consistent() {
        assert_eq!(SHIP_SHORT_KEYS[18], "MaximumSpeed");
        assert_eq!(SHIP_SHORT_KEYS[SHIP_MISC_BITS_INDEX], "");
        assert_eq!(SHORT_KEYS[29], "Door:DoorMode");
        assert_eq!(BYTE_KEYS[24], "Misc:AntiWarpSettleDelay");
    }
}
