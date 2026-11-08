//! Wire types and codecs for the SubSpace/Continuum game protocol.
//!
//! Everything here is pure data: no sockets, no clocks. Decoding never panics on
//! malformed input; it returns an error instead. All multi-byte fields are
//! little-endian.
//!
//! * [`settings`]: the arena settings packet ([`ClientSettings`]).
//! * [`checksum`]: CRC-32 and the security/position checksums.
//! * [`s2c`] / [`c2s`]: every game packet, with [`S2CPacket`] / [`C2SPacket`]
//!   dispatch enums; [`position`] and [`common`] hold shared structures.
//! * [`control`]: the `0x00` transport packets ([`CorePacket`]).
//! * [`objects`]: LVZ object records.
//! * [`directory`] and [`billing`]: the directory-server and billing-server
//!   protocols.
//! * [`wire`]: reader/writer helpers, [`Packet`] and [`FixedStr`].
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod billing;
pub mod c2s;
pub mod checksum;
pub mod common;
pub mod control;
pub mod directory;
mod error;
pub mod objects;
pub mod position;
pub mod rng;
pub mod s2c;
pub mod settings;
pub mod wire;

pub use c2s::C2SPacket;
pub use control::CorePacket;
pub use error::DecodeError;
pub use objects::ObjectData;
pub use position::{
    C2SPosition, ExtraPositionData, PositionTail, S2CPosition, S2CWeapon, WeaponInfo,
};
pub use rng::VieRng;
pub use s2c::S2CPacket;
pub use settings::{ClientSettings, ShipSettings, SpawnPosition};
pub use wire::{FixedStr, Packet};

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

#[cfg(test)]
mod proptests;
