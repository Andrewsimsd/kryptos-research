//! ACA Gromark alphabet construction and bounded additive recurrences.

use super::{
    CipherError, Transform,
    alphabet::Alphabet,
    parameter,
    permutation::Permutation,
    polyalphabetic::{Direction, Equation, transform_with_keys},
    validate_text,
};

/// Recurrence including its primer, with arithmetic in a declared integer base.
///
/// For zero-based position $i$, primer length $r$, and base $b$, the key digits
/// satisfy $k_{i+r}=(k_i+k_{i+1})\bmod b$ with $0\le k_i<b$.
/// This is modular integer arithmetic, not finite-field arithmetic.
// Clippy reads LaTeX subscripts as prose identifiers; Rustdoc needs the math intact.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recurrence {
    base: u8,
    primer: Vec<u8>,
}

impl Recurrence {
    /// Validate bases 2–26, lengths 2–32, and every digit below the base.
    ///
    /// # Errors
    /// Returns [`CipherError`] for any parameter outside those explicit bounds.
    pub fn new(base: u8, primer: Vec<u8>) -> Result<Self, CipherError> {
        if !(2..=26).contains(&base) {
            return Err(parameter("base", "must be in 2..=26"));
        }
        if !(2..=32).contains(&primer.len()) {
            return Err(parameter("primer", "length must be in 2..=32"));
        }
        if primer.iter().any(|&digit| digit >= base) {
            return Err(parameter(
                "primer",
                "each digit must be smaller than the base",
            ));
        }
        Ok(Self { base, primer })
    }

    /// Generate a prefix, including primer digits; zero length returns no digits.
    ///
    /// # Errors
    /// Rejects output lengths that cannot be allocated.
    pub fn generate(&self, length: usize) -> Result<Vec<u8>, CipherError> {
        let mut digits = Vec::new();
        digits
            .try_reserve_exact(length)
            .map_err(|_| parameter("length", "cannot allocate this many digits"))?;
        digits.extend(self.primer.iter().take(length).copied());
        for index in self.primer.len()..length {
            digits.push(
                (digits[index - self.primer.len()] + digits[index - self.primer.len() + 1])
                    % self.base,
            );
        }
        Ok(digits)
    }
}

/// ACA standard Gromark: standard plaintext alphabet and a transposed keyed alphabet.
#[derive(Debug, Clone)]
pub struct Gromark {
    alphabet: Alphabet,
    recurrence: Recurrence,
}

impl Gromark {
    /// Deduplicate the keyword, fill its keyed alphabet in rows, and read columns
    /// in alphabetical keyword order. Use a five-digit base-10 primer.
    ///
    /// # Errors
    /// Rejects empty/non-A–Z keywords and primer digits above nine.
    pub fn new(keyword: &str, primer: [u8; 5]) -> Result<Self, CipherError> {
        Ok(Self {
            alphabet: aca_transposed_alphabet(keyword)?,
            recurrence: Recurrence::new(10, primer.to_vec())?,
        })
    }

    /// Return the constructed ciphertext alphabet.
    #[must_use]
    pub fn alphabet(&self) -> &Alphabet {
        &self.alphabet
    }

    /// Generate the numeric key used for a message of the given length.
    ///
    /// # Errors
    /// Rejects lengths that cannot be allocated.
    pub fn numeric_key(&self, length: usize) -> Result<Vec<u8>, CipherError> {
        self.recurrence.generate(length)
    }

    /// Encrypt without emitting the transmitted primer or terminal check digit.
    ///
    /// # Errors
    /// Rejects non-A–Z plaintext or an unallocatable numeric key.
    pub fn encrypt(&self, plaintext: &str) -> Result<Transform, CipherError> {
        self.transform(plaintext, Direction::Encrypt)
    }

    /// Decrypt ciphertext letters only, using the constructor's supplied primer.
    ///
    /// # Errors
    /// Rejects non-A–Z ciphertext or an unallocatable numeric key.
    pub fn decrypt(&self, ciphertext: &str) -> Result<Transform, CipherError> {
        self.transform(ciphertext, Direction::Decrypt)
    }

    /// Identify the actual ciphertext alphabet and primer, merging keyword aliases.
    #[must_use]
    pub fn canonical_id(&self) -> String {
        format!(
            "aca-gromark-v1:{}:{:?}",
            self.alphabet.order(),
            self.recurrence.primer
        )
    }

    fn transform(&self, input: &str, direction: Direction) -> Result<Transform, CipherError> {
        validate_text(input)?;
        transform_with_keys(
            input,
            &Alphabet::standard(),
            &self.alphabet,
            Equation::Vigenere,
            direction,
            self.numeric_key(input.len())?.into_iter(),
        )
    }
}

/// Construct the ACA Gromark transposed keyed alphabet.
///
/// The keyword is deduplicated in first-occurrence order. Its keyword-fill
/// alphabet is written rowwise at the deduplicated keyword width, then ragged
/// columns are read in alphabetical order of the deduplicated keyword letters.
///
/// # Errors
///
/// Rejects empty or non-uppercase-ASCII keywords.
pub fn aca_transposed_alphabet(keyword: &str) -> Result<Alphabet, CipherError> {
    let keyed = Alphabet::keyed(keyword)?;
    let mut unique = Vec::new();
    for letter in keyword.bytes() {
        if !unique.contains(&letter) {
            unique.push(letter);
        }
    }
    let mut columns: Vec<_> = (0..unique.len()).collect();
    columns.sort_by_key(|&index| unique[index]);
    let order = Permutation::columnar(26, &columns, false)?
        .apply(&keyed.order())?
        .text;
    Alphabet::from_order(&order)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aca_alphabet_construction_matches_worked_example() {
        assert_eq!(
            aca_transposed_alphabet("ENIGMA").unwrap().order(),
            "AJRXEBKSYGFPVIDOUMHQWNCLTZ"
        );
    }

    #[test]
    fn aca_full_message_matches_known_answer() {
        let cipher = Gromark::new("ENIGMA", [2, 3, 4, 5, 2]).unwrap();
        assert_eq!(
            cipher
                .encrypt("THEREAREUPTOTENSUBSTITUTESPERLETTER")
                .unwrap()
                .text,
            "NFYCKBTIJCNWZYCACJNAYNLQPWWSTWPJQFL"
        );
    }

    #[test]
    fn aca_numeric_stream_includes_primer_and_last_used_check_digit() {
        let digits = Recurrence::new(10, vec![2, 3, 4, 5, 2])
            .unwrap()
            .generate(35)
            .unwrap();
        assert_eq!(
            digits
                .into_iter()
                .map(|digit| char::from(b'0' + digit))
                .collect::<String>(),
            "23452579772664982037023072537978066"
        );
    }

    #[test]
    fn repeated_keyword_letters_do_not_create_extra_columns() {
        assert_eq!(
            Gromark::new("REPEATED", [0; 5]).unwrap().canonical_id(),
            Gromark::new("REPATD", [0; 5]).unwrap().canonical_id()
        );
    }

    #[test]
    fn recurrence_prefix_boundaries_and_modular_base_are_explicit() {
        let recurrence = Recurrence::new(3, vec![2, 2]).unwrap();
        for (length, expected) in [
            (0, vec![]),
            (1, vec![2]),
            (2, vec![2, 2]),
            (6, vec![2, 2, 1, 0, 1, 1]),
        ] {
            assert_eq!(recurrence.generate(length).unwrap(), expected);
        }
    }

    #[test]
    fn invalid_recurrence_domains_are_rejected() {
        for (base, primer) in [
            (1, vec![0, 0]),
            (27, vec![0, 0]),
            (10, vec![]),
            (10, vec![1]),
            (10, vec![0; 33]),
            (10, vec![0, 10]),
        ] {
            assert!(Recurrence::new(base, primer).is_err());
        }
        assert!(
            Recurrence::new(26, vec![25, 25])
                .unwrap()
                .generate(usize::MAX)
                .is_err()
        );
    }

    #[test]
    fn gromark_handles_empty_messages_and_rejects_invalid_text_and_primers() {
        let cipher = Gromark::new("A", [0; 5]).unwrap();
        assert!(
            cipher.encrypt("").unwrap().trace.is_empty()
                && cipher.decrypt("?").is_err()
                && Gromark::new("A", [10; 5]).is_err()
        );
    }
}
