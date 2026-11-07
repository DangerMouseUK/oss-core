//! Position and weapon packets: C2S `0x03`, S2C `0x05` (weapons/large position)
//! and S2C `0x28` (small position), plus the shared bitfields.

use alloc::vec::Vec;

use crate::DecodeError;
use crate::checksum::position_checksum;
use crate::settings::{get_bits, set_bits};
use crate::wire::{Packet, Reader, Wire, Writer, expect_type};

/// Ship status bits (`status` in position packets).
pub mod status {
    /// Stealth is on.
    pub const STEALTH: u8 = 0x01;
    /// Cloak is on.
    pub const CLOAK: u8 = 0x02;
    /// X-radar is on.
    pub const XRADAR: u8 = 0x04;
    /// Antiwarp is on.
    pub const ANTIWARP: u8 = 0x08;
    /// The ship flashes (it just uncloaked or warped).
    pub const FLASH: u8 = 0x10;
    /// The ship is in a safe zone.
    pub const SAFEZONE: u8 = 0x20;
    /// The ship is a UFO.
    pub const UFO: u8 = 0x40;
    /// Unused by the protocol (some clients set it on input changes).
    pub const INPUT_CHANGE: u8 = 0x80;
}

/// Weapon type codes ([`WeaponInfo::kind`]).
pub mod weapon_type {
    /// No weapon (plain position update).
    pub const NONE: u8 = 0;
    /// Bullet.
    pub const BULLET: u8 = 1;
    /// Bouncing bullet.
    pub const BOUNCE_BULLET: u8 = 2;
    /// Bomb (or mine when [`super::WeaponInfo::alternate`] is set).
    pub const BOMB: u8 = 3;
    /// Proximity bomb (or mine).
    pub const PROX_BOMB: u8 = 4;
    /// Repel.
    pub const REPEL: u8 = 5;
    /// Decoy.
    pub const DECOY: u8 = 6;
    /// Burst.
    pub const BURST: u8 = 7;
    /// Thor's hammer.
    pub const THOR: u8 = 8;
}

/// The packed 16-bit weapon description: type (5 bits), level (2), shrapnel
/// bouncing (1), shrapnel level (2), shrapnel count (5), alternate (1: mines for
/// bombs, multifire for bullets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct WeaponInfo(pub u16);

impl WeaponInfo {
    fn get(self, lo: u32, w: u32) -> u8 {
        get_bits(u32::from(self.0), lo, w) as u8
    }
    fn set(&mut self, lo: u32, w: u32, v: u8) {
        self.0 = set_bits(u32::from(self.0), lo, w, u32::from(v)) as u16;
    }
    /// Weapon type ([`weapon_type`]).
    pub fn kind(self) -> u8 {
        self.get(0, 5)
    }
    /// Sets the weapon type.
    pub fn set_kind(&mut self, v: u8) {
        self.set(0, 5, v)
    }
    /// Weapon level, 0-3 (L1-L4).
    pub fn level(self) -> u8 {
        self.get(5, 2)
    }
    /// Sets the level.
    pub fn set_level(&mut self, v: u8) {
        self.set(5, 2, v)
    }
    /// Whether shrapnel bounces.
    pub fn shrap_bouncing(self) -> bool {
        self.get(7, 1) != 0
    }
    /// Sets shrapnel bouncing.
    pub fn set_shrap_bouncing(&mut self, v: bool) {
        self.set(7, 1, v.into())
    }
    /// Shrapnel level, 0-3.
    pub fn shrap_level(self) -> u8 {
        self.get(8, 2)
    }
    /// Sets the shrapnel level.
    pub fn set_shrap_level(&mut self, v: u8) {
        self.set(8, 2, v)
    }
    /// Shrapnel count, 0-31.
    pub fn shrap(self) -> u8 {
        self.get(10, 5)
    }
    /// Sets the shrapnel count.
    pub fn set_shrap(&mut self, v: u8) {
        self.set(10, 5, v)
    }
    /// Alternate fire: mine instead of bomb, multifire for bullets.
    pub fn alternate(self) -> bool {
        self.get(15, 1) != 0
    }
    /// Sets alternate fire.
    pub fn set_alternate(&mut self, v: bool) {
        self.set(15, 1, v.into())
    }
}

impl Wire for WeaponInfo {
    const SIZE: usize = 2;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.u16().map(Self)
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.put_u16(self.0)
    }
}

/// Optional 10-byte trailer on position packets (sent when the server asks for
/// it, e.g. to spectators with extra info or staff).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExtraPositionData {
    /// Current energy.
    pub energy: u16,
    /// Server-to-client ping (10 ms units).
    pub s2c_ping: u16,
    /// Flag timer (seconds).
    pub timer: u16,
    /// Packed item counts: shields (1 bit), super (1), bursts (4), repels (4),
    /// thors (4), bricks (4), decoys (4), rockets (4), portals (4), 2 unused.
    pub items: u32,
}

impl ExtraPositionData {
    /// Encoded size.
    pub const LEN: usize = 10;

    fn item(&self, lo: u32, w: u32) -> u8 {
        get_bits(self.items, lo, w) as u8
    }
    /// Shields active.
    pub fn shields(&self) -> bool {
        self.item(0, 1) != 0
    }
    /// Super active.
    pub fn super_(&self) -> bool {
        self.item(1, 1) != 0
    }
    /// Burst count.
    pub fn bursts(&self) -> u8 {
        self.item(2, 4)
    }
    /// Repel count.
    pub fn repels(&self) -> u8 {
        self.item(6, 4)
    }
    /// Thor count.
    pub fn thors(&self) -> u8 {
        self.item(10, 4)
    }
    /// Brick count.
    pub fn bricks(&self) -> u8 {
        self.item(14, 4)
    }
    /// Decoy count.
    pub fn decoys(&self) -> u8 {
        self.item(18, 4)
    }
    /// Rocket count.
    pub fn rockets(&self) -> u8 {
        self.item(22, 4)
    }
    /// Portal count.
    pub fn portals(&self) -> u8 {
        self.item(26, 4)
    }
    /// Packs item state into [`Self::items`] (counts are truncated to 4 bits).
    #[allow(clippy::too_many_arguments)]
    pub fn pack_items(
        shields: bool,
        super_: bool,
        bursts: u8,
        repels: u8,
        thors: u8,
        bricks: u8,
        decoys: u8,
        rockets: u8,
        portals: u8,
    ) -> u32 {
        let mut w = set_bits(0, 0, 1, shields.into());
        w = set_bits(w, 1, 1, super_.into());
        for (lo, v) in [
            (2, bursts),
            (6, repels),
            (10, thors),
            (14, bricks),
            (18, decoys),
            (22, rockets),
            (26, portals),
        ] {
            w = set_bits(w, lo, 4, v.into());
        }
        w
    }
}

impl Wire for ExtraPositionData {
    const SIZE: usize = 10;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            energy: r.u16()?,
            s2c_ping: r.u16()?,
            timer: r.u16()?,
            items: r.u32()?,
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.put_u16(self.energy);
        out.put_u16(self.s2c_ping);
        out.put_u16(self.timer);
        out.put_u32(self.items);
    }
}

fn read_extra(r: &mut Reader<'_>) -> Result<Option<ExtraPositionData>, DecodeError> {
    if r.remaining() >= ExtraPositionData::LEN {
        ExtraPositionData::read(r).map(Some)
    } else {
        Ok(None)
    }
}

/// Optional trailer on S2C position packets, chosen per recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PositionTail {
    /// No trailer.
    #[default]
    None,
    /// Energy only (2 bytes).
    Energy(u16),
    /// Full [`ExtraPositionData`] (10 bytes).
    Extra(ExtraPositionData),
}

impl PositionTail {
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(match r.remaining() {
            n if n >= ExtraPositionData::LEN => Self::Extra(ExtraPositionData::read(r)?),
            n if n >= 2 => Self::Energy(r.u16()?),
            _ => Self::None,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::None => {}
            Self::Energy(e) => out.put_u16(*e),
            Self::Extra(x) => x.write(out),
        }
    }

    /// The energy value, if the trailer carries one.
    pub fn energy(&self) -> Option<u16> {
        match self {
            Self::None => None,
            Self::Energy(e) => Some(*e),
            Self::Extra(x) => Some(x.energy),
        }
    }
}

/// C2S `0x03`: the client's position (22 bytes, or 32 with extra data).
///
/// `checksum` is the XOR of the first 22 bytes with the checksum byte taken as 0;
/// [`C2SPosition::encode`] fills it in and [`C2SPosition::checksum_ok`] verifies a
/// decoded packet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct C2SPosition {
    /// Rotation, 0-39.
    pub rotation: i8,
    /// Client's estimate of server time (ticks).
    pub time: u32,
    /// X velocity.
    pub x_speed: i16,
    /// Y position in pixels.
    pub y: i16,
    /// Checksum byte as received (recomputed on encode).
    pub checksum: u8,
    /// [`status`] bits.
    pub status: u8,
    /// X position in pixels.
    pub x: i16,
    /// Y velocity.
    pub y_speed: i16,
    /// Bounty.
    pub bounty: u16,
    /// Energy (or -1 / a placeholder when the client hides it).
    pub energy: i16,
    /// Weapon fired with this update, if any.
    pub weapon: WeaponInfo,
    /// Optional trailer.
    pub extra: Option<ExtraPositionData>,
}

impl C2SPosition {
    /// Length without the extra trailer.
    pub const LEN: usize = 22;
    /// Offset of the checksum byte.
    pub const CHECKSUM_OFFSET: usize = 10;

    /// Whether the received checksum matches the packet contents.
    pub fn checksum_ok(&self) -> bool {
        let mut b = self.to_bytes();
        b[Self::CHECKSUM_OFFSET] = 0;
        position_checksum(&b[..Self::LEN]) == self.checksum
    }
}

impl Packet for C2SPosition {
    const TYPE: u8 = 0x03;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        Ok(Self {
            rotation: r.i8()?,
            time: r.u32()?,
            x_speed: r.i16()?,
            y: r.i16()?,
            checksum: r.u8()?,
            status: r.u8()?,
            x: r.i16()?,
            y_speed: r.i16()?,
            bounty: r.u16()?,
            energy: r.i16()?,
            weapon: WeaponInfo::read(&mut r)?,
            extra: read_extra(&mut r)?,
        })
    }
    /// Writes the packet with a freshly computed checksum.
    fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.put_u8(Self::TYPE);
        out.put_i8(self.rotation);
        out.put_u32(self.time);
        out.put_i16(self.x_speed);
        out.put_i16(self.y);
        out.put_u8(0);
        out.put_u8(self.status);
        out.put_i16(self.x);
        out.put_i16(self.y_speed);
        out.put_u16(self.bounty);
        out.put_i16(self.energy);
        self.weapon.write(out);
        let sum = position_checksum(&out[start..start + Self::LEN]);
        out[start + Self::CHECKSUM_OFFSET] = sum;
        if let Some(e) = &self.extra {
            e.write(out);
        }
    }
}

/// S2C `0x05`: another player's position with a weapon (also used for positions
/// that do not fit the small form). 21 bytes, 23 with energy, 31 with extra data.
///
/// `checksum` is the XOR of the first 21 bytes with the checksum byte taken as 0;
/// encode fills it in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct S2CWeapon {
    /// Rotation, 0-39.
    pub rotation: i8,
    /// Low 16 bits of the server timestamp (ticks).
    pub time: u16,
    /// X position in pixels.
    pub x: i16,
    /// Y velocity.
    pub y_speed: i16,
    /// Player id.
    pub player_id: u16,
    /// X velocity.
    pub x_speed: i16,
    /// Checksum byte as received (recomputed on encode).
    pub checksum: u8,
    /// [`status`] bits.
    pub status: u8,
    /// Client-to-server latency of this update (ticks).
    pub c2s_latency: u8,
    /// Y position in pixels.
    pub y: i16,
    /// Bounty.
    pub bounty: u16,
    /// Weapon fired.
    pub weapon: WeaponInfo,
    /// Optional trailer (energy or full extra data).
    pub tail: PositionTail,
}

impl S2CWeapon {
    /// Length without the extra trailer.
    pub const LEN: usize = 21;
    /// Offset of the checksum byte.
    pub const CHECKSUM_OFFSET: usize = 12;

    /// Whether the received checksum matches the packet contents.
    pub fn checksum_ok(&self) -> bool {
        let mut b = self.to_bytes();
        b[Self::CHECKSUM_OFFSET] = 0;
        position_checksum(&b[..Self::LEN]) == self.checksum
    }
}

impl Packet for S2CWeapon {
    const TYPE: u8 = 0x05;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        Ok(Self {
            rotation: r.i8()?,
            time: r.u16()?,
            x: r.i16()?,
            y_speed: r.i16()?,
            player_id: r.u16()?,
            x_speed: r.i16()?,
            checksum: r.u8()?,
            status: r.u8()?,
            c2s_latency: r.u8()?,
            y: r.i16()?,
            bounty: r.u16()?,
            weapon: WeaponInfo::read(&mut r)?,
            tail: PositionTail::read(&mut r)?,
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.put_u8(Self::TYPE);
        out.put_i8(self.rotation);
        out.put_u16(self.time);
        out.put_i16(self.x);
        out.put_i16(self.y_speed);
        out.put_u16(self.player_id);
        out.put_i16(self.x_speed);
        out.put_u8(0);
        out.put_u8(self.status);
        out.put_u8(self.c2s_latency);
        out.put_i16(self.y);
        out.put_u16(self.bounty);
        self.weapon.write(out);
        let sum = position_checksum(&out[start..start + Self::LEN]);
        out[start + Self::CHECKSUM_OFFSET] = sum;
        self.tail.write(out);
    }
}

/// S2C `0x28`: another player's position, small form (16 bytes, 18 with energy,
/// 26 with extra data). Usable when the player id and bounty fit in a byte and no weapon was
/// fired.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct S2CPosition {
    /// Rotation, 0-39.
    pub rotation: i8,
    /// Low 16 bits of the server timestamp (ticks).
    pub time: u16,
    /// X position in pixels.
    pub x: i16,
    /// Client-to-server latency of this update (ticks).
    pub c2s_latency: u8,
    /// Bounty (low byte).
    pub bounty: u8,
    /// Player id (low byte).
    pub player_id: u8,
    /// [`status`] bits.
    pub status: u8,
    /// Y velocity.
    pub y_speed: i16,
    /// Y position in pixels.
    pub y: i16,
    /// X velocity.
    pub x_speed: i16,
    /// Optional trailer (energy or full extra data).
    pub tail: PositionTail,
}

impl S2CPosition {
    /// Length without the extra trailer.
    pub const LEN: usize = 16;
}

impl Packet for S2CPosition {
    const TYPE: u8 = 0x28;
    fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut r = expect_type(data, Self::TYPE)?;
        Ok(Self {
            rotation: r.i8()?,
            time: r.u16()?,
            x: r.i16()?,
            c2s_latency: r.u8()?,
            bounty: r.u8()?,
            player_id: r.u8()?,
            status: r.u8()?,
            y_speed: r.i16()?,
            y: r.i16()?,
            x_speed: r.i16()?,
            tail: PositionTail::read(&mut r)?,
        })
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.put_u8(Self::TYPE);
        out.put_i8(self.rotation);
        out.put_u16(self.time);
        out.put_i16(self.x);
        out.put_u8(self.c2s_latency);
        out.put_u8(self.bounty);
        out.put_u8(self.player_id);
        out.put_u8(self.status);
        out.put_i16(self.y_speed);
        out.put_i16(self.y);
        out.put_i16(self.x_speed);
        self.tail.write(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weapon() -> WeaponInfo {
        let mut w = WeaponInfo::default();
        w.set_kind(weapon_type::BOMB);
        w.set_level(2);
        w.set_shrap(17);
        w.set_shrap_level(1);
        w.set_shrap_bouncing(true);
        w.set_alternate(true);
        w
    }

    fn extra() -> ExtraPositionData {
        ExtraPositionData {
            energy: 1500,
            s2c_ping: 12,
            timer: 30,
            items: ExtraPositionData::pack_items(true, false, 3, 2, 1, 15, 4, 5, 6),
        }
    }

    #[test]
    fn weapon_bits() {
        let w = weapon();
        assert_eq!(
            (
                w.kind(),
                w.level(),
                w.shrap(),
                w.shrap_level(),
                w.shrap_bouncing(),
                w.alternate()
            ),
            (3, 2, 17, 1, true, true)
        );
        assert_eq!(w.0, 3 | 2 << 5 | 1 << 7 | 1 << 8 | 17 << 10 | 1 << 15);
    }

    #[test]
    fn c2s_position_round_trip() {
        for extra in [None, Some(extra())] {
            let p = C2SPosition {
                rotation: 39,
                time: 0x0102_0304,
                x_speed: -300,
                y: 8000,
                checksum: 0,
                status: status::CLOAK | status::SAFEZONE,
                x: 512 * 16,
                y_speed: 1200,
                bounty: 1000,
                energy: 1700,
                weapon: weapon(),
                extra,
            };
            let b = p.to_bytes();
            assert_eq!(b.len(), if extra.is_some() { 32 } else { 22 });
            let back = C2SPosition::decode(&b).unwrap();
            assert!(back.checksum_ok());
            assert_eq!(position_checksum(&b[..22]), 0);
            assert_eq!(
                C2SPosition {
                    checksum: 0,
                    ..back.clone()
                },
                p
            );
            let mut bad = b.clone();
            bad[5] ^= 1;
            assert!(!C2SPosition::decode(&bad).unwrap().checksum_ok());
            assert_eq!(
                back.extra
                    .map(|e| (e.shields(), e.bursts(), e.bricks(), e.portals())),
                extra.map(|_| (true, 3, 15, 6))
            );
        }
        assert!(C2SPosition::decode(&[0x03; 21]).is_err());
    }

    #[test]
    fn s2c_weapon_round_trip() {
        for (tail, len) in [
            (PositionTail::None, 21),
            (PositionTail::Energy(900), 23),
            (PositionTail::Extra(extra()), 31),
        ] {
            let p = S2CWeapon {
                rotation: 5,
                time: 0xBEEF,
                x: 100,
                y_speed: -1,
                player_id: 300,
                x_speed: 7,
                checksum: 0,
                status: status::FLASH,
                c2s_latency: 9,
                y: 200,
                bounty: 50,
                weapon: weapon(),
                tail,
            };
            let b = p.to_bytes();
            assert_eq!(b.len(), len);
            assert_eq!(position_checksum(&b[..21]), 0);
            let back = S2CWeapon::decode(&b).unwrap();
            assert!(back.checksum_ok());
            assert_eq!(
                S2CWeapon {
                    checksum: 0,
                    ..back
                },
                p
            );
        }
    }

    #[test]
    fn s2c_position_round_trip() {
        for (tail, len) in [
            (PositionTail::None, 16),
            (PositionTail::Energy(900), 18),
            (PositionTail::Extra(extra()), 26),
        ] {
            let p = S2CPosition {
                rotation: 1,
                time: 2,
                x: 3,
                c2s_latency: 4,
                bounty: 5,
                player_id: 6,
                status: 7,
                y_speed: 8,
                y: 9,
                x_speed: -10,
                tail,
            };
            let b = p.to_bytes();
            assert_eq!(b.len(), len);
            assert_eq!(S2CPosition::decode(&b).unwrap(), p);
        }
    }
}
