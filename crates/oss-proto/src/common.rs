//! Sub-structures shared by several game packets.

use alloc::vec::Vec;

use crate::DecodeError;
use crate::objects::ObjectData;
use crate::position::WeaponInfo;
use crate::wire::{FixedStr, Reader, Wire, Writer};

/// Chat message types (`kind` in chat packets).
pub mod chat_type {
    /// Arena message (green; server to client only).
    pub const ARENA: u8 = 0;
    /// Public macro.
    pub const PUBLIC_MACRO: u8 = 1;
    /// Public message.
    pub const PUBLIC: u8 = 2;
    /// Team (own frequency) message.
    pub const FREQ: u8 = 3;
    /// Message to the target player's frequency.
    pub const ENEMY_FREQ: u8 = 4;
    /// Private message to a player in the same arena.
    pub const PRIVATE: u8 = 5;
    /// Red warning with a name tag (server to client).
    pub const WARNING: u8 = 6;
    /// Remote (cross-arena) private message.
    pub const REMOTE_PRIVATE: u8 = 7;
    /// Red server error / sysop warning without a name (server to client).
    pub const SERVER_ERROR: u8 = 8;
    /// Chat channel message.
    pub const CHANNEL: u8 = 9;
}

/// Prize numbers (green packets, S2C `0x20`, prize weights order + 1).
pub mod prize {
    /// Recharge.
    pub const RECHARGE: i16 = 1;
    /// Energy.
    pub const ENERGY: i16 = 2;
    /// Rotation.
    pub const ROTATION: i16 = 3;
    /// Stealth.
    pub const STEALTH: i16 = 4;
    /// Cloak.
    pub const CLOAK: i16 = 5;
    /// X-radar.
    pub const XRADAR: i16 = 6;
    /// Warp.
    pub const WARP: i16 = 7;
    /// Gun upgrade.
    pub const GUN: i16 = 8;
    /// Bomb upgrade.
    pub const BOMB: i16 = 9;
    /// Bouncing bullets.
    pub const BOUNCE: i16 = 10;
    /// Thruster.
    pub const THRUST: i16 = 11;
    /// Top speed.
    pub const SPEED: i16 = 12;
    /// Full charge.
    pub const FULL_CHARGE: i16 = 13;
    /// Engine shutdown.
    pub const SHUTDOWN: i16 = 14;
    /// Multifire.
    pub const MULTIFIRE: i16 = 15;
    /// Proximity bombs.
    pub const PROX: i16 = 16;
    /// Super.
    pub const SUPER: i16 = 17;
    /// Shields.
    pub const SHIELDS: i16 = 18;
    /// Shrapnel.
    pub const SHRAPNEL: i16 = 19;
    /// Antiwarp.
    pub const ANTIWARP: i16 = 20;
    /// Repel.
    pub const REPEL: i16 = 21;
    /// Burst.
    pub const BURST: i16 = 22;
    /// Decoy.
    pub const DECOY: i16 = 23;
    /// Thor.
    pub const THOR: i16 = 24;
    /// Multiprize.
    pub const MULTIPRIZE: i16 = 25;
    /// Brick.
    pub const BRICK: i16 = 26;
    /// Rocket.
    pub const ROCKET: i16 = 27;
    /// Portal.
    pub const PORTAL: i16 = 28;
}

/// Player record sent in S2C `0x03` (64 bytes including its own type byte).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlayerData {
    /// Ship (0-7, 8 = spectator).
    pub ship: i8,
    /// Whether the player accepts voice messages.
    pub accept_audio: u8,
    /// Name (20 bytes, may lack a NUL).
    pub name: FixedStr<20>,
    /// Squad (20 bytes, may lack a NUL).
    pub squad: FixedStr<20>,
    /// Kill points.
    pub kill_points: i32,
    /// Flag points.
    pub flag_points: i32,
    /// Player id.
    pub pid: i16,
    /// Frequency.
    pub freq: i16,
    /// Kills.
    pub wins: i16,
    /// Deaths.
    pub losses: i16,
    /// Player this one is attached to as a turret (-1 = none).
    pub attached_to: i16,
    /// Flags carried.
    pub flags_carried: i16,
    /// Bit 0: has a crown (KoTH); bit 1: send damage reports for this player.
    pub misc_bits: u8,
}

impl PlayerData {
    /// Encoded size, type byte included.
    pub const LEN: usize = 64;
    /// Type byte that starts each record.
    pub const TYPE: u8 = 0x03;

    fn read_body(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            ship: r.i8()?,
            accept_audio: r.u8()?,
            name: r.fixed()?,
            squad: r.fixed()?,
            kill_points: r.i32()?,
            flag_points: r.i32()?,
            pid: r.i16()?,
            freq: r.i16()?,
            wins: r.i16()?,
            losses: r.i16()?,
            attached_to: r.i16()?,
            flags_carried: r.i16()?,
            misc_bits: r.u8()?,
        })
    }

    /// Appends the record, type byte included.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_i8(self.ship);
        out.put_u8(self.accept_audio);
        self.name.write(out);
        self.squad.write(out);
        out.put_i32(self.kill_points);
        out.put_i32(self.flag_points);
        out.put_i16(self.pid);
        out.put_i16(self.freq);
        out.put_i16(self.wins);
        out.put_i16(self.losses);
        out.put_i16(self.attached_to);
        out.put_i16(self.flags_carried);
        out.put_u8(self.misc_bits);
    }

    /// Decodes one or more concatenated records (each starting with `0x03`).
    pub fn decode_all(data: &[u8]) -> Result<Vec<Self>, DecodeError> {
        let mut out = Vec::new();
        let mut r = Reader::new(data, Self::TYPE);
        while r.remaining() > 0 {
            let t = r.u8()?;
            if t != Self::TYPE {
                return Err(DecodeError::Invalid {
                    kind: Self::TYPE,
                    field: "concatenated record type",
                });
            }
            out.push(Self::read_body(&mut r)?);
        }
        if out.is_empty() {
            return Err(DecodeError::Truncated {
                kind: Self::TYPE,
                need: Self::LEN,
                have: data.len(),
            });
        }
        Ok(out)
    }
}

/// One brick (S2C `0x21`), 16 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Brick {
    /// First end, x tile.
    pub x1: i16,
    /// First end, y tile.
    pub y1: i16,
    /// Second end, x tile.
    pub x2: i16,
    /// Second end, y tile.
    pub y2: i16,
    /// Owning frequency.
    pub freq: i16,
    /// Brick id.
    pub brick_id: u16,
    /// Server time the brick was placed (ticks).
    pub start_time: u32,
}

impl Wire for Brick {
    const SIZE: usize = 16;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            x1: r.i16()?,
            y1: r.i16()?,
            x2: r.i16()?,
            y2: r.i16()?,
            freq: r.i16()?,
            brick_id: r.u16()?,
            start_time: r.u32()?,
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        for v in [self.x1, self.y1, self.x2, self.y2, self.freq] {
            out.put_i16(v);
        }
        out.put_u16(self.brick_id);
        out.put_u32(self.start_time);
    }
}

/// One damage report entry (9 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DamageData {
    /// Attacker (own pid for wormhole damage).
    pub attacker: i16,
    /// Weapon that hit.
    pub weapon: WeaponInfo,
    /// Energy before the hit.
    pub energy: i16,
    /// Damage dealt.
    pub damage: i16,
    /// Ticks after the packet's timestamp.
    pub time_offset: u8,
}

impl Wire for DamageData {
    const SIZE: usize = 9;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            attacker: r.i16()?,
            weapon: WeaponInfo::read(r)?,
            energy: r.i16()?,
            damage: r.i16()?,
            time_offset: r.u8()?,
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.put_i16(self.attacker);
        self.weapon.write(out);
        out.put_i16(self.energy);
        out.put_i16(self.damage);
        out.put_u8(self.time_offset);
    }
}

/// An LVZ object toggle (2 bytes): bits 0-14 object id, bit 15 set = turn off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct ObjectToggle(pub u16);

impl ObjectToggle {
    /// A toggle for `id` (15 bits).
    pub fn new(id: u16, on: bool) -> Self {
        Self((id & 0x7FFF) | if on { 0 } else { 0x8000 })
    }
    /// Object id.
    pub fn id(self) -> u16 {
        self.0 & 0x7FFF
    }
    /// Whether the object is being shown.
    pub fn on(self) -> bool {
        self.0 & 0x8000 == 0
    }
}

impl Wire for ObjectToggle {
    const SIZE: usize = 2;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.u16().map(Self)
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.put_u16(self.0)
    }
}

/// Which object properties an [`ObjectChange`] updates.
pub mod object_change {
    /// Position.
    pub const POSITION: u8 = 0x01;
    /// Image.
    pub const IMAGE: u8 = 0x02;
    /// Layer.
    pub const LAYER: u8 = 0x04;
    /// Display time.
    pub const TIME: u8 = 0x08;
    /// Display mode.
    pub const MODE: u8 = 0x10;
}

/// An LVZ object change (11 bytes): a change mask then the object record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ObjectChange {
    /// [`object_change`] bits.
    pub mask: u8,
    /// New values (only masked fields matter).
    pub data: ObjectData,
}

impl Wire for ObjectChange {
    const SIZE: usize = 11;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            mask: r.u8()?,
            data: ObjectData::read(r)?,
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.put_u8(self.mask);
        self.data.write(out);
    }
}

fn sign_extend(v: u32, bits: u32) -> i16 {
    let shift = 32 - bits;
    (((v << shift) as i32) >> shift) as i16
}

/// Common fields of a batched position entry (S2C `0x39`/`0x3A`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PackedMotion {
    /// Rotation, 0-39 (6 bits).
    pub rotation: u8,
    /// Low 10 bits of the server timestamp.
    pub time: u16,
    /// X in pixels (14 bits, 0-16383).
    pub x: u16,
    /// Y in pixels (14 bits).
    pub y: u16,
    /// X velocity (signed 14 bits, -8192..8191).
    pub x_speed: i16,
    /// Y velocity (signed 14 bits).
    pub y_speed: i16,
}

impl PackedMotion {
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let rt = r.u16()?;
        let pos = r.u32()?;
        let vel = r.u16()?;
        let hi = r.i8()?;
        let x_speed = (i32::from(hi) << 6) | (i32::from(vel >> 14) << 4) | (pos >> 28) as i32;
        Ok(Self {
            rotation: (rt >> 10) as u8,
            time: rt & 0x3FF,
            x: (pos & 0x3FFF) as u16,
            y: ((pos >> 14) & 0x3FFF) as u16,
            x_speed: x_speed as i16,
            y_speed: sign_extend(u32::from(vel), 14),
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        let xs = self.x_speed as u16 as u32;
        out.put_u16((u16::from(self.rotation) << 10) | (self.time & 0x3FF));
        out.put_u32(
            u32::from(self.x & 0x3FFF) | (u32::from(self.y & 0x3FFF) << 14) | ((xs & 0xF) << 28),
        );
        out.put_u16((self.y_speed as u16 & 0x3FFF) | (((xs >> 4) & 3) as u16) << 14);
        out.put_u8((xs >> 6) as u8);
    }
}

/// One S2C `0x39` entry (10 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SmallBatchedPosition {
    /// Player id (8 bits).
    pub pid: u8,
    /// Motion.
    pub motion: PackedMotion,
}

impl Wire for SmallBatchedPosition {
    const SIZE: usize = 10;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            pid: r.u8()?,
            motion: PackedMotion::read(r)?,
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.put_u8(self.pid);
        self.motion.write(out);
    }
}

/// One S2C `0x3A` entry (11 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LargeBatchedPosition {
    /// Player id (10 bits).
    pub pid: u16,
    /// Status bits 0-5 (UFO and bit 7 are not carried).
    pub status: u8,
    /// Motion.
    pub motion: PackedMotion,
}

impl Wire for LargeBatchedPosition {
    const SIZE: usize = 11;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let w = r.u16()?;
        Ok(Self {
            pid: w & 0x3FF,
            status: (w >> 10) as u8,
            motion: PackedMotion::read(r)?,
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.put_u16((self.pid & 0x3FF) | (u16::from(self.status & 0x3F) << 10));
        self.motion.write(out);
    }
}

/// Reads repeated fixed-size entries filling the rest of the packet; the
/// remainder must be a whole number of entries.
pub(crate) fn read_entries<T: Wire>(r: &mut Reader<'_>, kind: u8) -> Result<Vec<T>, DecodeError> {
    if !r.remaining().is_multiple_of(T::SIZE) {
        return Err(DecodeError::Invalid {
            kind,
            field: "entry list length",
        });
    }
    let mut v = Vec::with_capacity(r.remaining() / T::SIZE);
    while r.remaining() > 0 {
        v.push(T::read(r)?);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_motion_extremes() {
        for (xs, ys) in [(0, 0), (8191, -8192), (-8192, 8191), (-1, 1), (1234, -4321)] {
            let e = SmallBatchedPosition {
                pid: 200,
                motion: PackedMotion {
                    rotation: 39,
                    time: 1023,
                    x: 16383,
                    y: 1,
                    x_speed: xs,
                    y_speed: ys,
                },
            };
            let mut b = Vec::new();
            e.write(&mut b);
            assert_eq!(b.len(), 10);
            assert_eq!(
                SmallBatchedPosition::read(&mut Reader::new(&b, 0x39)).unwrap(),
                e
            );
            let l = LargeBatchedPosition {
                pid: 1023,
                status: 0x3F,
                motion: e.motion,
            };
            let mut b = Vec::new();
            l.write(&mut b);
            assert_eq!(b.len(), 11);
            assert_eq!(
                LargeBatchedPosition::read(&mut Reader::new(&b, 0x3A)).unwrap(),
                l
            );
        }
    }

    #[test]
    fn object_toggle() {
        let t = ObjectToggle::new(1234, false);
        assert_eq!((t.id(), t.on()), (1234, false));
        assert!(ObjectToggle::new(5, true).on());
    }
}
