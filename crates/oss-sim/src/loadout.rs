//! A ship's loadout (upgradeable stats, counted items, capabilities, gun and bomb
//! levels) and the prize rules that change it, without the rest of a [`World`].
//!
//! The client's [`World`] applies prizes through this type, and a server can keep
//! one `Loadout` per player to know what each ship may legitimately have: start
//! from [`Loadout::spawn`] (which replays the initial-bounty prizes from the
//! shared prize seed), then [`Loadout::apply`] every prize the player picks up or
//! is given.
//!
//! [`World`]: crate::World

#![warn(missing_docs)]

use crate::prize::{Prize, generate_prize};
use crate::settings::{ArenaSettings, ShipSettings};
use crate::ship::{Items, Ship, ShipStats, cap};

/// Everything prizes can change on a ship, apart from its energy and timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Loadout {
    /// Rotation, thrust, speed, recharge and maximum energy, in settings units.
    pub stats: ShipStats,
    /// Repels, bursts, decoys, thors, bricks, rockets and portals.
    pub items: Items,
    /// [`cap`] bits: stealth, cloak, X-radar, antiwarp, multifire, bouncing
    /// bullets, proximity bombs.
    pub caps: u8,
    /// Gun level, 0 (none) to 3.
    pub guns: u8,
    /// Bomb level, 0 (none) to 3.
    pub bombs: u8,
    /// Shrapnel pieces per bomb.
    pub shrapnel: u8,
}

/// What a prize does besides changing the [`Loadout`]; the caller (the client's
/// world, or a server tracking the player) applies these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrizeEffect {
    /// Nothing else.
    None,
    /// Energy refills to the maximum.
    FullCharge,
    /// Energy drops to 1 point (a bad full charge, or a bad capability prize for
    /// one the ship can't have).
    DrainEnergy,
    /// Engine shutdown for `Prize:EngineShutdownTime` ticks, three times as long
    /// if `negative`.
    EngineShutdown {
        /// The bad version.
        negative: bool,
    },
    /// Shields for `ShieldsTime` ticks.
    Shields,
    /// Super for a random time below `SuperTime`.
    Super,
    /// The ship warps to a spawn point.
    Warp,
    /// `Prize:MultiPrizeCount` further random prizes.
    Multiprize,
}

impl Loadout {
    /// The loadout before initial-bounty prizes: initial stats, items, guns and
    /// bombs, and the capabilities whose status setting is 2 ("always").
    pub fn initial(s: &ShipSettings) -> Self {
        let mut caps = 0;
        for (status, bit) in [
            (s.stealth_status, cap::STEALTH),
            (s.cloak_status, cap::CLOAK),
            (s.xradar_status, cap::XRADAR),
            (s.anti_warp_status, cap::ANTIWARP),
        ] {
            if status == 2 {
                caps |= bit;
            }
        }
        Self {
            stats: ShipStats::initial(s),
            items: Items::initial(s),
            caps,
            guns: s.initial_guns.min(s.max_guns),
            bombs: s.initial_bombs.min(s.max_bombs),
            shrapnel: 0,
        }
    }

    /// The loadout a ship spawns with: [`Loadout::initial`] plus `InitialBounty`
    /// random prizes drawn from `prize_seed` (the arena's shared seed, which this
    /// does not advance), exactly as the client draws them.
    pub fn spawn(s: &ShipSettings, arena: &ArenaSettings, prize_seed: u32) -> Self {
        let mut l = Self::initial(s);
        if arena.prize_weight_total() == 0 {
            return l;
        }
        let mut seed = prize_seed;
        let mut given = 0;
        for _ in 0..9999 {
            if given >= s.initial_bounty {
                break;
            }
            let p = generate_prize(&mut seed, arena, false);
            let Some(prize) = Prize::from_id(p.clamp(0, 255) as u8) else {
                continue;
            };
            if prize.excluded_from_batches() && prize != Prize::Multiprize {
                continue;
            }
            if l.apply(s, prize, false) == PrizeEffect::Multiprize {
                l.multiprize(s, arena, seed);
            }
            // Energy effects don't matter: the ship spawns fully charged.
            given += 1;
        }
        l
    }

    /// Applies a multiprize's `MultiPrizeCount` extra prizes, drawn from `seed`
    /// (the arena's shared prize seed at that moment; not advanced). Returns the
    /// last energy effect among them ([`PrizeEffect::FullCharge`] or
    /// [`PrizeEffect::DrainEnergy`]), or [`PrizeEffect::None`].
    pub fn multiprize(
        &mut self,
        s: &ShipSettings,
        arena: &ArenaSettings,
        mut seed: u32,
    ) -> PrizeEffect {
        let mut energy = PrizeEffect::None;
        let mut given = 0;
        for _ in 0..9999 {
            if given >= arena.multi_prize_count {
                break;
            }
            let p = generate_prize(&mut seed, arena, false);
            let Some(prize) = Prize::from_id(p.clamp(0, 255) as u8) else {
                continue;
            };
            if p <= 0 || prize.excluded_from_batches() {
                continue;
            }
            // Batches never contain the timed effects, warp or multiprize, so
            // only energy effects can come back.
            let effect = self.apply(s, prize, false);
            if matches!(effect, PrizeEffect::FullCharge | PrizeEffect::DrainEnergy) {
                energy = effect;
            }
            given += 1;
        }
        energy
    }

    /// Applies `prize` (the bad version if `negative`) and returns what else it
    /// does. Stats move by their upgrade step within initial..=maximum; counted
    /// items within 0..=their maximum; capabilities only if the arena allows them.
    pub fn apply(&mut self, s: &ShipSettings, prize: Prize, negative: bool) -> PrizeEffect {
        fn adjust(v: &mut u32, step: u32, lo: u32, hi: u32, negative: bool) {
            *v = if negative {
                v.saturating_sub(step).max(lo)
            } else {
                (*v + step).min(hi.max(lo))
            };
        }
        fn count(v: &mut u8, max: u8, negative: bool) {
            *v = if negative {
                v.saturating_sub(1)
            } else {
                v.saturating_add(1).min(max)
            };
        }
        let mut effect = PrizeEffect::None;
        let mut capability = |l: &mut Loadout, bit: u8, status: u8| {
            if negative {
                if l.caps & bit == 0 && status == 0 {
                    effect = PrizeEffect::DrainEnergy;
                }
                l.caps &= !bit;
            } else if status > 0 {
                l.caps |= bit;
            } else {
                effect = PrizeEffect::FullCharge;
            }
        };
        match prize {
            Prize::QuickCharge => adjust(
                &mut self.stats.recharge,
                s.upgrade_recharge,
                s.initial_recharge,
                s.maximum_recharge,
                negative,
            ),
            Prize::Energy => adjust(
                &mut self.stats.max_energy,
                s.upgrade_energy,
                s.initial_energy,
                s.maximum_energy,
                negative,
            ),
            Prize::Rotation => adjust(
                &mut self.stats.rotation,
                s.upgrade_rotation,
                s.initial_rotation,
                s.maximum_rotation,
                negative,
            ),
            Prize::Thruster => adjust(
                &mut self.stats.thrust,
                s.upgrade_thrust,
                s.initial_thrust,
                s.maximum_thrust,
                negative,
            ),
            Prize::TopSpeed => adjust(
                &mut self.stats.speed,
                s.upgrade_speed,
                s.initial_speed,
                s.maximum_speed,
                negative,
            ),
            Prize::Stealth => capability(self, cap::STEALTH, s.stealth_status),
            Prize::Cloak => capability(self, cap::CLOAK, s.cloak_status),
            Prize::XRadar => capability(self, cap::XRADAR, s.xradar_status),
            Prize::Antiwarp => capability(self, cap::ANTIWARP, s.anti_warp_status),
            Prize::BouncingBullets => capability(self, cap::BOUNCING_BULLETS, 1),
            Prize::Multifire => capability(self, cap::MULTIFIRE, 1),
            Prize::Proximity => capability(self, cap::PROXIMITY, 1),
            Prize::Guns => {
                self.guns = if negative {
                    self.guns.saturating_sub(1).max(s.initial_guns)
                } else {
                    (self.guns + 1).min(s.max_guns)
                }
            }
            Prize::Bombs => {
                self.bombs = if negative {
                    self.bombs.saturating_sub(1).max(s.initial_bombs)
                } else {
                    (self.bombs + 1).min(s.max_bombs)
                }
            }
            Prize::Shrapnel => {
                self.shrapnel = if negative {
                    self.shrapnel.saturating_sub(s.shrapnel_rate)
                } else {
                    self.shrapnel
                        .saturating_add(s.shrapnel_rate)
                        .min(s.shrapnel_max)
                }
            }
            Prize::Repel => count(&mut self.items.repels, s.repel_max, negative),
            Prize::Burst => count(&mut self.items.bursts, s.burst_max, negative),
            Prize::Decoy => count(&mut self.items.decoys, s.decoy_max, negative),
            Prize::Thor => count(&mut self.items.thors, s.thor_max, negative),
            Prize::Brick => count(&mut self.items.bricks, s.brick_max, negative),
            Prize::Rocket => count(&mut self.items.rockets, s.rocket_max, negative),
            Prize::Portal => count(&mut self.items.portals, s.portal_max, negative),
            Prize::FullCharge => {
                effect = if negative {
                    PrizeEffect::DrainEnergy
                } else {
                    PrizeEffect::FullCharge
                }
            }
            Prize::EngineShutdown => effect = PrizeEffect::EngineShutdown { negative },
            Prize::Shields => effect = PrizeEffect::Shields,
            Prize::Super => effect = PrizeEffect::Super,
            Prize::Warp => {
                effect = if negative {
                    PrizeEffect::FullCharge
                } else {
                    PrizeEffect::Warp
                }
            }
            Prize::Multiprize => {
                if !negative {
                    effect = PrizeEffect::Multiprize;
                }
            }
        }
        effect
    }

    /// The loadout part of a ship.
    pub fn of(ship: &Ship) -> Self {
        Self {
            stats: ship.stats,
            items: ship.items,
            caps: ship.caps,
            guns: ship.guns,
            bombs: ship.bombs,
            shrapnel: ship.shrapnel,
        }
    }

    /// Writes this loadout into a ship.
    pub fn store(&self, ship: &mut Ship) {
        ship.stats = self.stats;
        ship.items = self.items;
        ship.caps = self.caps;
        ship.guns = self.guns;
        ship.bombs = self.bombs;
        ship.shrapnel = self.shrapnel;
    }
}
