//! SubSpace text is single-byte (Windows-1252 in practice). Bytes map to the
//! Unicode code points with the same value (Latin-1), which is exact for
//! printable ASCII and the accented letters players actually use.

/// Decodes game text.
pub fn from_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// Encodes text for the game; characters outside Latin-1 become `?`.
pub fn to_latin1(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latin1_round_trip() {
        let s = "Zoë says hi ☺";
        let b = to_latin1(s);
        assert_eq!(b.len(), s.chars().count());
        assert_eq!(from_latin1(&b), "Zoë says hi ?");
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(to_latin1(&from_latin1(&all)), all);
    }
}
