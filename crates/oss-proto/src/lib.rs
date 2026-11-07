//! Wire types and codecs for the SubSpace/Continuum game protocol.
//!
//! Everything here is pure data: no sockets, no clocks. Decoding never panics on
//! malformed input; it returns an error instead. All multi-byte fields are
//! little-endian.
//!
//! * [`settings`]: the arena settings packet ([`ClientSettings`]).
//! * [`checksum`]: CRC-32 and the security/position checksums.
//! * [`wire`]: reader/writer helpers and [`FixedStr`].
#![no_std]

extern crate alloc;

pub mod checksum;
pub mod control;
mod error;
pub mod position;
pub mod settings;
pub mod wire;

pub use control::CorePacket;
pub use error::DecodeError;
pub use position::{C2SPosition, ExtraPositionData, S2CPosition, S2CWeapon, WeaponInfo};
pub use settings::{ClientSettings, ShipSettings, SpawnPosition};
pub use wire::{FixedStr, Packet};
