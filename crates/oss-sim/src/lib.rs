//! Deterministic simulation of SubSpace ships, weapons and map collision,
//! driven by the arena settings the server sends. Shared by the client (prediction)
//! and, later, by the server (plausibility checks), so it has no rendering or I/O.
//!
//! The world advances in fixed 100 Hz ticks using integer arithmetic only (see
//! [`fixed`] for units), so identical inputs give bit-identical results everywhere.

// Moved from oss-client with an established API; its items are documented
// progressively (see docs/CHANGELOG.md).
#![allow(missing_docs)]

pub mod coverage;
pub mod fixed;
pub mod loadout;
pub mod map;
pub mod prize;
pub mod remote;
pub mod settings;
pub mod ship;
pub mod validate;
pub mod weapons;
pub mod world;

pub use fixed::{POS_SCALE, Pos, TICKS_PER_SECOND, VEL_SCALE, Vec2, Vel, VieRng};
pub use loadout::{Loadout, PrizeEffect};
pub use map::{MAP_TILES, MapObject, TileMap, is_animated_object, is_solid_id, object_size, tile};
pub use prize::{Green, Prize, generate_prize};
pub use remote::{RemoteState, RemoteWeapon, RemoteWeaponKind};
pub use settings::{
    ArenaSettings, FlaggerSettings, PRIZE_COUNT, STOCK_SHIP, ShipSettings, SoccerSettings,
};
pub use ship::{Items, Ship, ShipInput, ShipState, ShipStats, cap, toggle};
pub use validate::{
    CAPABILITY_STATUS, Context, Finding, Limits, MotionMap, MotionVerdict, STATUS_FLASH, Sample,
    Tolerance, WallCheck, check_motion, energy_bounds,
};
pub use weapons::{Fired, Projectile, ProjectileKind, ProxTrigger, fire_cost, flagger_cost};
pub use world::{Brick, Event, World};

#[cfg(test)]
mod tests;
