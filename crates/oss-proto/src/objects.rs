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
///
/// The screen split above is the **`CLV2`** one. A `CLV1` section does not split the
/// word at all: its low twelve bits are a signed offset, and the whole word read as an
/// `i16` picks one of three reference points. It has its own accessors
/// ([`clv1_x_ref`](Self::clv1_x_ref) and friends); see [`ObjectLayout`].
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

/// Which layout an object section's screen position words use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectLayout {
    /// `CLV2`: reference index in bits 0-3, signed 12-bit offset in bits 4-15,
    /// the reference being one of the twelve HUD points in [`reference`](mod@reference).
    Clv2,
    /// `CLV1`: the low twelve bits are a signed offset and the whole word, read as an
    /// `i16`, picks one of three reference points ([`Clv1Reference`]). The offset bits
    /// are part of that comparison, so this is not a split into fields.
    Clv1,
}

/// Side of the square box whose bottom-right corner is [`Clv1Reference::CentredBox`].
///
/// What this box *is* has not been established; the arithmetic is what was measured.
pub const CLV1_BOX: i32 = 960;

/// Lowest non-negative word value that reads from [`Clv1Reference::CentredBox`].
///
/// Measured, not derived: the edge was bracketed between word 15000 (top-left) and
/// 15001 (centred box) at two view sizes, 1888x1016 and 1920x1080, on both axes. It
/// is the same number at both, and has no established relation to either — where it
/// comes from is unknown.
pub const CLV1_CENTRED_MIN: i32 = 15001;

/// The reference point a `CLV1` screen object hangs from. Unlike `CLV2`'s twelve HUD
/// anchors there are only three, and they depend on the view size alone, so this crate
/// can resolve them without knowing anything about the HUD.
///
/// Which one applies is decided by the **whole word read as a signed 16-bit value**,
/// not by any field within it — see [`Clv1Reference::from_word`]. Measured from a real
/// Continuum client at two view sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Clv1Reference {
    /// Word 0..=15000: the top-left of the view, `(0, 0)`.
    TopLeft,
    /// Word 15001..=32767: the bottom-right corner of a [`CLV1_BOX`]-square box
    /// centred in the view, `((w + 960) / 2, (h + 960) / 2)`.
    CentredBox,
    /// Word 32768..=65535 (negative as `i16`): the bottom-right of the view, `(w, h)`.
    BottomRight,
}

impl Clv1Reference {
    /// The reference a position word selects: bottom-right when the word is negative
    /// as an `i16`, the centred box at [`CLV1_CENTRED_MIN`] and above, top-left
    /// otherwise.
    ///
    /// The word is not split into fields for this. Its low twelve bits are also the
    /// offset ([`ObjectData::clv1_screen_x`]), so a large negative offset can carry
    /// into the comparison and move the object to a different reference — that is
    /// Continuum's behaviour, not an artefact. It is why words in `0x3000..=0x3FFF`
    /// look inconsistent when they are grouped by their top nibble: the threshold
    /// falls inside that nibble's range, so `0x3A97` (14999) is top-left while
    /// `0x3AA1` (15009) is the centred box.
    pub const fn from_word(word: u16) -> Self {
        let w = word as i16;
        if w < 0 {
            Self::BottomRight
        } else if w as i32 >= CLV1_CENTRED_MIN {
            Self::CentredBox
        } else {
            Self::TopLeft
        }
    }

    /// Where this reference sits in a view `width` x `height` pixels.
    pub const fn point(self, width: i32, height: i32) -> (i32, i32) {
        (self.axis(width), self.axis(height))
    }

    /// One axis of [`point`](Self::point), for a view `extent` pixels along it.
    pub const fn axis(self, extent: i32) -> i32 {
        match self {
            Self::TopLeft => 0,
            Self::CentredBox => (extent + CLV1_BOX) / 2,
            Self::BottomRight => extent,
        }
    }
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
    /// Screen object x reference point under the **`CLV1`** layout, from the whole
    /// word ([`Clv1Reference::from_word`]).
    pub fn clv1_x_ref(&self) -> Clv1Reference {
        Clv1Reference::from_word(self.x_word)
    }

    /// Screen object y reference point under the `CLV1` layout.
    pub fn clv1_y_ref(&self) -> Clv1Reference {
        Clv1Reference::from_word(self.y_word)
    }

    /// Screen object x offset from [`clv1_x_ref`](Self::clv1_x_ref): the low twelve
    /// bits of the word, sign-extended.
    pub fn clv1_screen_x(&self) -> i16 {
        sign12(self.x_word & 0xFFF)
    }

    /// Screen object y offset from [`clv1_y_ref`](Self::clv1_y_ref).
    pub fn clv1_screen_y(&self) -> i16 {
        sign12(self.y_word & 0xFFF)
    }

    /// Where a `CLV1` screen object is drawn in a view `width` x `height` pixels: its
    /// reference point plus its offset, in view pixels. Each axis is decided on its
    /// own word.
    ///
    /// The result is deliberately not clamped. Continuum **clips** such an object at
    /// the view edges rather than dropping it: an image placed left of the view is
    /// drawn with its left part cut off, and only vanishes once nothing is left — a
    /// 1600-pixel-wide image at x = -1385 shows its last 215 pixels, where a 16-pixel
    /// one at the same position shows nothing.
    ///
    /// Only meaningful for a screen object from a `CLV1` section; a map object's
    /// position is [`map_x`](Self::map_x) / [`map_y`](Self::map_y) under either layout.
    pub fn clv1_screen_position(&self, width: i32, height: i32) -> (i32, i32) {
        (
            self.clv1_x_ref().axis(width) + i32::from(self.clv1_screen_x()),
            self.clv1_y_ref().axis(height) + i32::from(self.clv1_screen_y()),
        )
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
