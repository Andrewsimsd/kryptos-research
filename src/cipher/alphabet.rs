//! Validated alphabet permutations and explicit forward/inverse lookup.

use super::{CipherError, parameter, validate_text};

/// An immutable ordering of the 26 uppercase ASCII letters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alphabet {
    letters: [u8; 26],
    indices: [u8; 26],
}

impl Default for Alphabet {
    fn default() -> Self {
        Self::standard()
    }
}

impl Alphabet {
    /// Construct standard A–Z without validation or allocation.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            letters: *b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            indices: [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25,
            ],
        }
    }

    /// Validate an explicitly ordered alphabet.
    ///
    /// # Errors
    /// Rejects non-A–Z input, lengths other than 26, and duplicate letters.
    pub fn from_order(order: &str) -> Result<Self, CipherError> {
        validate_text(order)?;
        let letters: [u8; 26] = order
            .as_bytes()
            .try_into()
            .map_err(|_| parameter("alphabet", "must contain exactly 26 letters"))?;
        let mut indices = [26; 26];
        for (index, letter) in (0_u8..26).zip(letters) {
            let slot = usize::from(letter - b'A');
            if indices[slot] != 26 {
                return Err(parameter("alphabet", "each letter must occur exactly once"));
            }
            indices[slot] = index;
        }
        Ok(Self { letters, indices })
    }

    /// Deduplicate a keyword, then append unused letters in A–Z order.
    ///
    /// # Errors
    /// Rejects empty keywords and any non-uppercase-ASCII character.
    ///
    /// # Examples
    /// ```
    /// use kryptos_research::cipher::alphabet::Alphabet;
    /// assert_eq!(Alphabet::keyed("KRYPTOS")?.order(), "KRYPTOSABCDEFGHIJLMNQUVWXZ");
    /// # Ok::<(), kryptos_research::cipher::CipherError>(())
    /// ```
    pub fn keyed(keyword: &str) -> Result<Self, CipherError> {
        validate_text(keyword)?;
        if keyword.is_empty() {
            return Err(parameter("keyword", "must not be empty"));
        }
        let mut seen = [false; 26];
        let mut order = String::with_capacity(26);
        for letter in keyword.bytes().chain(b'A'..=b'Z') {
            if !seen[usize::from(letter - b'A')] {
                seen[usize::from(letter - b'A')] = true;
                order.push(char::from(letter));
            }
        }
        Self::from_order(&order)
    }

    /// Return letters in index order.
    #[must_use]
    pub fn order(&self) -> String {
        self.letters.iter().copied().map(char::from).collect()
    }

    /// Look up an uppercase letter's index.
    ///
    /// # Errors
    /// Rejects bytes outside ASCII A–Z.
    pub fn index(&self, letter: u8) -> Result<u8, CipherError> {
        if !letter.is_ascii_uppercase() {
            return Err(CipherError::InvalidSymbol {
                index: 0,
                symbol: char::from(letter),
            });
        }
        Ok(self.index_unchecked(letter))
    }

    /// Look up the letter at an index in 0–25.
    ///
    /// # Errors
    /// Rejects indices outside 0–25; does not implicitly reduce modulo 26.
    pub fn letter(&self, index: u8) -> Result<u8, CipherError> {
        self.letters
            .get(usize::from(index))
            .copied()
            .ok_or_else(|| parameter("alphabet index", "must be in 0..26"))
    }

    /// Rotate left, reducing the rotation count modulo 26.
    #[must_use]
    pub fn rotated(&self, amount: usize) -> Self {
        let mut letters = self.letters;
        letters.rotate_left(amount % 26);
        Self::from_letters(letters)
    }

    /// Reverse all 26 positions.
    #[must_use]
    pub fn reversed(&self) -> Self {
        let mut letters = self.letters;
        letters.reverse();
        Self::from_letters(letters)
    }

    fn from_letters(letters: [u8; 26]) -> Self {
        let mut indices = [0; 26];
        for (index, letter) in (0_u8..26).zip(letters) {
            indices[usize::from(letter - b'A')] = index;
        }
        Self { letters, indices }
    }

    // Callers validate ASCII text before entering cipher loops.
    pub(crate) fn index_unchecked(&self, letter: u8) -> u8 {
        self.indices[usize::from(letter - b'A')]
    }
    pub(crate) fn letter_unchecked(&self, index: u8) -> u8 {
        self.letters[usize::from(index)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_and_inverse_maps_cover_every_letter() {
        let alphabet = Alphabet::keyed("REPEATED").unwrap();
        for letter in b'A'..=b'Z' {
            assert_eq!(alphabet.letter(alphabet.index(letter).unwrap()), Ok(letter));
        }
    }

    #[test]
    fn keyword_deduplication_preserves_first_occurrence() {
        assert_eq!(
            Alphabet::keyed("REPEATED").unwrap().order(),
            "REPATDBCFGHIJKLMNOQSUVWXYZ"
        );
    }

    #[test]
    fn invalid_orders_and_empty_keys_are_rejected() {
        for input in [
            "",
            "A",
            "AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "abcdefghijklmnopqrstuvwxYZ",
            "ABCDEFGHIJKLMNOPQRSTUVWXY?",
        ] {
            assert!(Alphabet::from_order(input).is_err());
        }
        assert!(Alphabet::keyed("").is_err());
    }

    #[test]
    fn rotation_and_reversal_have_independent_expected_orders() {
        assert_eq!(
            Alphabet::standard().rotated(27).reversed().order(),
            "AZYXWVUTSRQPONMLKJIHGFEDCB"
        );
    }

    #[test]
    fn invalid_lookup_inputs_return_errors() {
        assert!(Alphabet::standard().index(0).is_err() && Alphabet::standard().letter(26).is_err());
    }

    #[test]
    fn maximum_rotation_does_not_overflow() {
        assert_eq!(
            Alphabet::standard().rotated(usize::MAX),
            Alphabet::standard().rotated(usize::MAX % 26)
        );
    }
}
