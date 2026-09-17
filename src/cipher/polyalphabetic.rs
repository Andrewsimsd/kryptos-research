//! Repeating Vigenère, Beaufort and variant Beaufort under explicit alphabets.

use serde::{Deserialize, Serialize};

use super::{CipherError, PositionTrace, Transform, alphabet::Alphabet, parameter, validate_text};

/// The declared arithmetic convention, always modulo 26.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Equation {
    /// Encryption c = p + k; decryption p = c - k.
    Vigenere,
    /// Encryption c = k - p; decryption p = k - c.
    Beaufort,
    /// Encryption c = p - k; decryption p = c + k.
    VariantBeaufort,
}

/// A direction, without inferring it from the supplied text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Plaintext to ciphertext.
    Encrypt,
    /// Ciphertext to plaintext.
    Decrypt,
}

/// Immutable repeating-key cipher with separate plaintext/ciphertext/key maps.
#[derive(Debug, Clone)]
pub struct RepeatingCipher {
    plain: Alphabet,
    cipher: Alphabet,
    key_alphabet: Alphabet,
    key: Vec<u8>,
    equation: Equation,
}

impl RepeatingCipher {
    /// Build an explicitly aligned model. Keyword positions use `key_alphabet`.
    ///
    /// # Errors
    /// Rejects empty or non-A–Z keywords.
    pub fn new(
        plain: Alphabet,
        cipher: Alphabet,
        key_alphabet: Alphabet,
        keyword: &str,
        equation: Equation,
    ) -> Result<Self, CipherError> {
        validate_text(keyword)?;
        if keyword.is_empty() {
            return Err(parameter("keyword", "must not be empty"));
        }
        let key = keyword
            .bytes()
            .map(|letter| key_alphabet.index_unchecked(letter))
            .collect();
        Ok(Self {
            plain,
            cipher,
            key_alphabet,
            key,
            equation,
        })
    }

    /// Encrypt, with `offset` selecting the initial keyword position modulo length.
    ///
    /// # Errors
    /// Rejects non-A–Z plaintext. Empty plaintext is valid.
    pub fn encrypt(&self, plaintext: &str, offset: usize) -> Result<Transform, CipherError> {
        self.transform(plaintext, offset, Direction::Encrypt)
    }

    /// Decrypt with the same offset used for encryption.
    ///
    /// # Errors
    /// Rejects non-A–Z ciphertext. Empty ciphertext is valid.
    pub fn decrypt(&self, ciphertext: &str, offset: usize) -> Result<Transform, CipherError> {
        self.transform(ciphertext, offset, Direction::Decrypt)
    }

    /// Canonicalize repeated complete key cycles and their phase.
    ///
    /// Equivalence is restricted to the exact three alphabets and equation;
    /// no equivalence across alphabet rotations or sign conventions is claimed.
    #[must_use]
    pub fn canonical_id(&self, offset: usize) -> String {
        let period = (1..=self.key.len())
            .find(|&period| {
                self.key.len() % period == 0
                    && self
                        .key
                        .iter()
                        .enumerate()
                        .all(|(i, value)| *value == self.key[i % period])
            })
            .unwrap_or(self.key.len());
        let key: Vec<_> = self.key[..period]
            .iter()
            .cycle()
            .skip(offset % period)
            .take(period)
            .copied()
            .collect();
        format!(
            "repeat-v1:{:?}:{}:{}:{}:{key:?}",
            self.equation,
            self.plain.order(),
            self.cipher.order(),
            self.key_alphabet.order()
        )
    }

    fn transform(
        &self,
        input: &str,
        offset: usize,
        direction: Direction,
    ) -> Result<Transform, CipherError> {
        let keys = self
            .key
            .iter()
            .cycle()
            .skip(offset % self.key.len())
            .copied();
        transform_with_keys(
            input,
            &self.plain,
            &self.cipher,
            self.equation,
            direction,
            keys,
        )
    }
}

pub(crate) fn transform_with_keys(
    input: &str,
    plain: &Alphabet,
    cipher: &Alphabet,
    equation: Equation,
    direction: Direction,
    keys: impl Iterator<Item = u8>,
) -> Result<Transform, CipherError> {
    validate_text(input)?;
    let (from, to) = match direction {
        Direction::Encrypt => (plain, cipher),
        Direction::Decrypt => (cipher, plain),
    };
    let mut text = String::with_capacity(input.len());
    let mut trace = Vec::with_capacity(input.len());
    for (index, (letter, key)) in input.bytes().zip(keys).enumerate() {
        let value = from.index_unchecked(letter);
        let output_value = match (equation, direction) {
            (Equation::Vigenere, Direction::Encrypt)
            | (Equation::VariantBeaufort, Direction::Decrypt) => (value + key) % 26,
            (Equation::Vigenere, Direction::Decrypt)
            | (Equation::VariantBeaufort, Direction::Encrypt) => (value + 26 - key) % 26,
            (Equation::Beaufort, _) => (key + 26 - value) % 26,
        };
        let output = char::from(to.letter_unchecked(output_value));
        text.push(output);
        trace.push(PositionTrace {
            output_index: index,
            input_index: index,
            input: char::from(letter),
            output,
            input_value: Some(value),
            key_value: Some(key),
            output_value: Some(output_value),
        });
    }
    if text.len() != input.len() {
        return Err(parameter("key stream", "must cover every input letter"));
    }
    Ok(Transform { text, trace })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn standard(key: &str, equation: Equation) -> RepeatingCipher {
        RepeatingCipher::new(
            Alphabet::standard(),
            Alphabet::standard(),
            Alphabet::standard(),
            key,
            equation,
        )
        .unwrap()
    }

    #[test]
    fn classic_vigenere_known_answer_matches() {
        assert_eq!(
            standard("LEMON", Equation::Vigenere)
                .encrypt("ATTACKATDAWN", 0)
                .unwrap()
                .text,
            "LXFOPVEFRNHR"
        );
    }

    #[test]
    fn all_three_equations_match_manual_wraparound_examples() {
        for (equation, expected) in [
            (Equation::Vigenere, "BZ"),
            (Equation::Beaufort, "DL"),
            (Equation::VariantBeaufort, "XP"),
        ] {
            assert_eq!(
                standard("CF", equation).encrypt("ZU", 0).unwrap().text,
                expected
            );
        }
    }

    #[test]
    fn all_letter_pairs_are_invertible_under_each_equation() {
        for equation in [
            Equation::Vigenere,
            Equation::Beaufort,
            Equation::VariantBeaufort,
        ] {
            for key in b'A'..=b'Z' {
                let cipher = standard(&char::from(key).to_string(), equation);
                let encrypted = cipher.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 0).unwrap();
                assert_eq!(
                    cipher.decrypt(&encrypted.text, 0).unwrap().text,
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                );
            }
        }
    }

    #[test]
    fn maximum_offset_is_reduced_without_overflow() {
        let cipher = standard("BC", Equation::Vigenere);
        assert_eq!(cipher.encrypt("AAA", usize::MAX).unwrap().text, "CBC");
    }

    #[test]
    fn canonical_identifier_removes_complete_cycles_and_phase_equivalence() {
        assert_eq!(
            standard("ABCABC", Equation::Vigenere).canonical_id(1),
            standard("BCABCA", Equation::Vigenere).canonical_id(0)
        );
    }

    #[test]
    fn canonical_identifier_keeps_distinct_equations() {
        assert_ne!(
            standard("ABC", Equation::Vigenere).canonical_id(0),
            standard("ABC", Equation::Beaufort).canonical_id(0)
        );
    }

    #[test]
    fn invalid_and_empty_keys_are_rejected() {
        for keyword in ["", "a", "A?", "é"] {
            assert!(
                RepeatingCipher::new(
                    Alphabet::standard(),
                    Alphabet::standard(),
                    Alphabet::standard(),
                    keyword,
                    Equation::Vigenere
                )
                .is_err()
            );
        }
    }

    #[test]
    fn empty_text_has_no_trace_and_invalid_text_is_rejected() {
        let cipher = standard("A", Equation::Vigenere);
        assert!(
            cipher.encrypt("", 0).unwrap().trace.is_empty() && cipher.decrypt("A?", 0).is_err()
        );
    }

    #[test]
    fn traces_expose_actual_values_at_each_position() {
        let trace = standard("Z", Equation::Vigenere)
            .encrypt("B", 0)
            .unwrap()
            .trace;
        assert_eq!(
            trace[0],
            PositionTrace {
                input_index: 0,
                output_index: 0,
                input: 'B',
                output: 'A',
                input_value: Some(1),
                key_value: Some(25),
                output_value: Some(0)
            }
        );
    }

    #[test]
    fn short_explicit_key_stream_cannot_silently_truncate_input() {
        assert!(
            transform_with_keys(
                "AB",
                &Alphabet::standard(),
                &Alphabet::standard(),
                Equation::Vigenere,
                Direction::Encrypt,
                [0].into_iter()
            )
            .is_err()
        );
    }
}
