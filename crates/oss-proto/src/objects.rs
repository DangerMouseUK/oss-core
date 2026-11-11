//! LVZ object records, shared by `.lvz` object sections and the object
//! toggle/move packets (S2C `0x35`, `0x36`).

use alloc::vec::Vec;

use crate::DecodeError;
use crate::settings::{get_bits, set_bits};
use crate::wire::{Reader, Wire, Writer};

/// Display layers (`layer` field), back to front.
pub mod layer {
    /// Below everything.
    pub const BELOW_ALL: u8 = 0;
    /// Above the background.
    pub const AFTER_BACKGROUND: u8 = 1;
    /// Above tiles.
    pub const AFTER_TILES: u8 = 2;
    /// Above weapons.
    pub const AFTER_WEAPONS: u8 = 3;
    /// Above ships.
    pub const AFTER_SHIPS: u8 = 4;
    /// Above gauges.
    pub const AFTER_GAUGES: u8 = 5;
    /// Above chat.
    pub const AFTER_CHAT: u8 = 6;
    /// On top of everything.
    pub const TOP_MOST: u8 = 7;
}

/// Display modes (`mode` field).
pub mod mode {
    /// Always shown.
    pub const SHOW_ALWAYS: u8 = 0;
    /// Shown on entering the zone.
    pub const ENTER_ZONE: u8 = 1;
    /// Shown on entering the arena.
    pub const ENTER_ARENA: u8 = 2;
    /// Shown on a kill.
    pub const KILL: u8 = 3;
    /// Shown on death.
    pub const DEATH: u8 = 4;
    /// Toggled by the server.
    pub const SERVER_CONTROLLED: u8 = 5;
}

/// Screen reference points for screen objects (the 4-bit `x_ref`/`y_ref`).
pub mod reference {
    /// Top-left of the screen.
    pub const NORMAL: u8 = 0;
    /// Screen centre (`C`).
    pub const CENTER: u8 = 1;
    /// Bottom-right corner (`B`).
    pub const BOTTOM_RIGHT: u8 = 2;
    /// Stats box, lower right corner (`S`).
    pub const STATS_BOX: u8 = 3;
    /// Top right corner of specials (`G`).
    pub const SPECIALS_TOP_RIGHT: u8 = 4;
    /// Bottom right corner of specials (`F`).
    pub const SPECIALS_BOTTOM_RIGHT: u8 = 5;
    /// Below the energy bar (`E`).
    pub const BELOW_ENERGY: u8 = 6;
    /// Top left of chat (`T`).
    pub const CHAT_TOP_LEFT: u8 = 7;
    /// Top left of radar (`R`).
    pub const RADAR_TOP_LEFT: u8 = 8;
    /// Top left of the radar's text (`O`).
    pub const RADAR_TEXT_TOP_LEFT: u8 = 9;
    /// Top left of weapons (`W`).
    pub const WEAPONS_TOP_LEFT: u8 = 10;
    /// Bottom left of weapons (`V`).
    pub const WEAPONS_BOTTOM_LEFT: u8 = 11;
}

/// One LVZ object, 10 bytes:
///
/// | Bytes | Bits | Field |
/// |-------|------|-------|
/// | 0-1 | bit 0 | map object (1) or screen object (0) |
/// |     | 1-15  | object id |
/// | 2-3 | | map: x in pixels (`i16`); screen: reference (4 bits) + x offset (signed 12 bits) |
/// | 4-5 | | same for y |
/// | 6 | | image index |
/// | 7 | | [`layer`] |
/// | 8-9 | 0-11 | display time (1/10 s, 0 = forever) |
/// |     | 12-15 | [`mode`] |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct ObjectData {
    /// Bit 0 map flag, bits 1-15 id.
    pub id_word: u16,
    /// Raw x word.
    pub x_word: u16,
    /// Raw y word.
    pub y_word: u16,
    /// Image index into the object section's image list.
    pub image: u8,
    /// [`layer`].
    pub layer: u8,
    /// Bits 0-11 display time, 12-15 mode.
    pub time_mode: u16,
}

fn sign12(v: u16) -> i16 {
    ((v << 4) as i16) >> 4
}

impl ObjectData {
    /// Encoded size.
    pub const LEN: usize = 10;

    /// A map object at pixel position (`x`, `y`).
    pub fn map(id: u16, x: i16, y: i16) -> Self {
        let mut o = Self {
            x_word: x as u16,
            y_word: y as u16,
            ..Self::default()
        };
        o.set_id(id);
        o.id_word |= 1;
        o
    }

    /// A screen object at offsets from reference points (offsets are truncated to
    /// signed 12 bits). This is the `CLV2` layout; see [`Self::screen_x`].
    pub fn screen(id: u16, x_ref: u8, x: i16, y_ref: u8, y: i16) -> Self {
        let pack = |r: u8, v: i16| (u16::from(r) & 0xF) | ((v as u16) << 4);
        let mut o = Self {
            x_word: pack(x_ref, x),
            y_word: pack(y_ref, y),
            ..Self::default()
        };
        o.set_id(id);
        o
    }

    /// Whether this is a map object (otherwise a screen object).
    pub fn is_map_object(&self) -> bool {
        self.id_word & 1 != 0
    }
    /// Object id (15 bits).
    pub fn id(&self) -> u16 {
        self.id_word >> 1
    }
    /// Sets the object id.
    pub fn set_id(&mut self, id: u16) {
        self.id_word = (self.id_word & 1) | (id << 1);
    }
    /// Map object x in pixels.
    pub fn map_x(&self) -> i16 {
        self.x_word as i16
    }
    /// Map object y in pixels.
    pub fn map_y(&self) -> i16 {
        self.y_word as i16
    }
    /// Screen object x reference point ([`reference`](mod@reference)), `CLV2` layout.
    pub fn x_ref(&self) -> u8 {
        (self.x_word & 0xF) as u8
    }
    /// Screen object x offset from [`Self::x_ref`].
    ///
    /// This split — reference point in bits 0-3, signed 12-bit offset in bits 4-15 —
    /// is the layout Continuum applies to **`CLV2`** object sections. It does not
    /// apply to `CLV1` sections, whose screen words are not understood;
    /// `oss_formats`'s LVZ reader refuses those rather than mis-reading them.
    pub fn screen_x(&self) -> i16 {
        sign12(self.x_word >> 4)
    }
    /// Screen object y reference point, `CLV2` layout.
    pub fn y_ref(&self) -> u8 {
        (self.y_word & 0xF) as u8
    }
    /// Screen object y offset from [`Self::y_ref`], `CLV2` layout (see
    /// [`Self::screen_x`]).
    pub fn screen_y(&self) -> i16 {
        sign12(self.y_word >> 4)
    }
    /// Display time in 1/10 s (0 = forever).
    pub fn display_time(&self) -> u16 {
        get_bits(self.time_mode.into(), 0, 12) as u16
    }
    /// Sets the display time (truncated to 12 bits).
    pub fn set_display_time(&mut self, t: u16) {
        self.time_mode = set_bits(self.time_mode.into(), 0, 12, t.into()) as u16;
    }
    /// Display [`mode`].
    pub fn mode(&self) -> u8 {
        get_bits(self.time_mode.into(), 12, 4) as u8
    }
    /// Sets the display mode.
    pub fn set_mode(&mut self, m: u8) {
        self.time_mode = set_bits(self.time_mode.into(), 12, 4, m.into()) as u16;
    }

    /// Decodes from exactly 10 bytes.
    pub fn from_bytes(b: [u8; 10]) -> Self {
        let w = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        Self {
            id_word: w(0),
            x_word: w(2),
            y_word: w(4),
            image: b[6],
            layer: b[7],
            time_mode: w(8),
        }
    }

    /// Encodes to 10 bytes.
    pub fn to_bytes(&self) -> [u8; 10] {
        let mut v = Vec::with_capacity(10);
        self.write(&mut v);
        let mut a = [0; 10];
        a.copy_from_slice(&v);
        a
    }
}

impl Wire for ObjectData {
    const SIZE: usize = 10;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.array().map(Self::from_bytes)
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.put_u16(self.id_word);
        out.put_u16(self.x_word);
        out.put_u16(self.y_word);
        out.put_u8(self.image);
        out.put_u8(self.layer);
        out.put_u16(self.time_mode);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_object() {
        let mut o = ObjectData::map(1234, -50, 16000);
        o.image = 3;
        o.layer = layer::AFTER_TILES;
        o.set_display_time(100);
        o.set_mode(mode::SERVER_CONTROLLED);
        let back = ObjectData::from_bytes(o.to_bytes());
        assert_eq!(back, o);
        assert!(back.is_map_object());
        assert_eq!((back.id(), back.map_x(), back.map_y()), (1234, -50, 16000));
        assert_eq!((back.display_time(), back.mode()), (100, 5));
    }

    #[test]
    fn screen_object() {
        let o = ObjectData::screen(7, reference::CENTER, -100, reference::BOTTOM_RIGHT, 2047);
        let back = ObjectData::from_bytes(o.to_bytes());
        assert!(!back.is_map_object());
        assert_eq!(back.id(), 7);
        assert_eq!((back.x_ref(), back.screen_x()), (1, -100));
        assert_eq!((back.y_ref(), back.screen_y()), (2, 2047));
    }
}
