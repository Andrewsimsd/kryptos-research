//! Exact evaluation of finite, explicitly ordered alphabet constructions.
//!
//! This module tests a deliberately small family of plaintext and ciphertext
//! alphabet orders against recurrence-derived crib equations. It does not score
//! language or infer plaintext outside the frozen cribs.

pub mod batch;

use crate::cipher::{CipherError, alphabet::Alphabet, parameter};
use serde::{Deserialize, Serialize};

/// One evaluated equation in the aligned two-alphabet additive model.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Equation {
    /// Zero-based message position.
    pub position: usize,
    /// Known plaintext letter.
    pub plaintext: char,
    /// Corresponding ciphertext letter.
    pub ciphertext: char,
    /// Plaintext letter index in the selected alphabet.
    pub plaintext_index: u8,
    /// Ciphertext letter index in the selected, rotated alphabet.
    pub ciphertext_index: u8,
    /// Supplied key value before reduction modulo 26.
    pub key: u8,
    /// Difference `ciphertext_index - plaintext_index` modulo 26.
    pub observed_residue: u8,
    /// Required residue after reducing [`Self::key`] modulo 26.
    pub required_residue: u8,
}

impl Equation {
    /// Return whether this equation satisfies the additive model.
    #[must_use]
    pub const fn matches(&self) -> bool {
        self.observed_residue == self.required_residue
    }
}

/// Complete evaluation of one alphabet pair and recurrence key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// Number of matching equations among all supplied cribs.
    pub match_count: usize,
    /// First mismatching equation in ascending message-position order.
    pub first_mismatch: Option<Equation>,
    /// Every equation, retained for compatible candidates.
    pub equations: Vec<Equation>,
}

/// Evaluate every supplied crib equation without early termination.
///
/// Retaining a match count over the complete crib set permits an auditable
/// histogram while [`Evaluation::first_mismatch`] remains a compact rejection
/// certificate.
///
/// # Errors
///
/// Key values are reduced modulo 26. Returns an error if a crib position lies
/// outside either the ciphertext or key, or if a supplied symbol is outside
/// uppercase ASCII A-Z.
pub fn evaluate(
    plaintext_alphabet: &Alphabet,
    ciphertext_alphabet: &Alphabet,
    ciphertext: &str,
    cribs: &[(usize, u8)],
    key: &[u8],
) -> Result<Evaluation, CipherError> {
    let mut equations = Vec::with_capacity(cribs.len());
    let mut match_count = 0;
    let mut first_mismatch = None;
    for &(position, plaintext) in cribs {
        let ciphertext_letter = ciphertext
            .as_bytes()
            .get(position)
            .copied()
            .ok_or_else(|| parameter("crib position", "must be inside ciphertext"))?;
        let required = key
            .get(position)
            .copied()
            .ok_or_else(|| parameter("crib position", "must be inside key"))?;
        let plaintext_index = plaintext_alphabet.index(plaintext)?;
        let ciphertext_index = ciphertext_alphabet.index(ciphertext_letter)?;
        let equation = Equation {
            position,
            plaintext: char::from(plaintext),
            ciphertext: char::from(ciphertext_letter),
            plaintext_index,
            ciphertext_index,
            key: required,
            observed_residue: (ciphertext_index + 26 - plaintext_index) % 26,
            required_residue: required % 26,
        };
        if equation.matches() {
            match_count += 1;
        } else if first_mismatch.is_none() {
            first_mismatch = Some(equation.clone());
        }
        equations.push(equation);
    }
    Ok(Evaluation {
        match_count,
        first_mismatch,
        equations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_is_leftward_and_wraps_residues() {
        let plain = Alphabet::standard();
        let cipher = Alphabet::standard().rotated(1);
        let result = evaluate(&plain, &cipher, "A", &[(0, b'Z')], &[2]).unwrap();
        assert_eq!(result.equations[0].ciphertext_index, 25);
        assert_eq!(result.equations[0].observed_residue, 0);
    }

    #[test]
    fn common_rotation_preserves_every_equation() {
        let plain = Alphabet::keyed("KRYPTOS").unwrap();
        let cipher = Alphabet::standard().reversed();
        let cribs = [(0, b'A'), (1, b'Z')];
        let first = evaluate(&plain, &cipher, "ZA", &cribs, &[3, 7]).unwrap();
        let second =
            evaluate(&plain.rotated(9), &cipher.rotated(9), "ZA", &cribs, &[3, 7]).unwrap();
        assert_eq!(
            first
                .equations
                .iter()
                .map(|equation| equation.observed_residue)
                .collect::<Vec<_>>(),
            second
                .equations
                .iter()
                .map(|equation| equation.observed_residue)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn planted_candidate_retains_all_equations() {
        let alphabet = Alphabet::standard();
        let result = evaluate(
            &alphabet,
            &alphabet,
            "BCD",
            &[(0, b'A'), (1, b'A'), (2, b'A')],
            &[1, 2, 3],
        )
        .unwrap();
        assert_eq!((result.match_count, result.first_mismatch), (3, None));
    }

    #[test]
    fn first_mismatch_uses_message_order_after_full_evaluation() {
        let alphabet = Alphabet::standard();
        let result = evaluate(
            &alphabet,
            &alphabet,
            "BBC",
            &[(0, b'A'), (1, b'A'), (2, b'A')],
            &[1, 2, 3],
        )
        .unwrap();
        assert_eq!(result.match_count, 1);
        assert_eq!(result.first_mismatch.unwrap().position, 1);
    }

    #[test]
    fn out_of_range_positions_are_errors() {
        let alphabet = Alphabet::standard();
        assert!(evaluate(&alphabet, &alphabet, "A", &[(1, b'A')], &[0]).is_err());
        assert!(evaluate(&alphabet, &alphabet, "A", &[(0, b'A')], &[]).is_err());
    }

    #[test]
    fn arbitrary_byte_keys_are_reduced_modulo_twenty_six() {
        let alphabet = Alphabet::standard();
        for (ciphertext, key, residue) in [("Z", 25, 25), ("A", 26, 0), ("V", 255, 21)] {
            let result = evaluate(&alphabet, &alphabet, ciphertext, &[(0, b'A')], &[key]).unwrap();
            assert_eq!(
                (
                    result.match_count,
                    result.equations[0].key,
                    result.equations[0].required_residue
                ),
                (1, key, residue)
            );
        }
    }
}
