//! Reversible cipher primitives with explicit alphabet and position conventions.
//!
//! Inputs are normalized ASCII A–Z. These implementations reproduce known
//! fixtures; they do not identify the mechanism used for Kryptos K4.

pub mod alphabet;
pub mod constraints;
pub mod gromark;
pub mod permutation;
pub mod polyalphabetic;

use std::{error::Error, fmt};

use serde::Serialize;

/// Invalid text, key, or transformation parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    /// A character violates the explicitly selected normalization convention.
    InvalidSymbol {
        /// UTF-8 byte offset in the supplied string.
        index: usize,
        /// The rejected character.
        symbol: char,
    },
    /// A key or model parameter violates its documented domain.
    InvalidParameter {
        /// Name of the offending parameter.
        name: &'static str,
        /// Explanation of the valid domain.
        reason: &'static str,
    },
    /// A fixed-size transformation received the wrong message length.
    LengthMismatch {
        /// Required number of letters.
        expected: usize,
        /// Supplied number of letters.
        actual: usize,
    },
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSymbol { index, symbol } => write!(
                f,
                "invalid symbol {symbol:?} at byte {index}; expected ASCII A-Z"
            ),
            Self::InvalidParameter { name, reason } => write!(f, "invalid {name}: {reason}"),
            Self::LengthMismatch { expected, actual } => {
                write!(f, "expected {expected} letters, received {actual}")
            }
        }
    }
}

impl Error for CipherError {}

pub(crate) fn parameter(name: &'static str, reason: &'static str) -> CipherError {
    CipherError::InvalidParameter { name, reason }
}

pub(crate) fn validate_text(input: &str) -> Result<(), CipherError> {
    for (index, symbol) in input.char_indices() {
        if !symbol.is_ascii_uppercase() {
            return Err(CipherError::InvalidSymbol { index, symbol });
        }
    }
    Ok(())
}

/// Uppercase ASCII letters and remove only ASCII whitespace.
///
/// This is opt-in; cipher operations never call it implicitly. Empty input is
/// valid. Punctuation and digits are rejected rather than silently removed.
///
/// # Errors
/// Returns [`CipherError::InvalidSymbol`] for any other character.
///
/// # Examples
/// ```
/// use kryptos_research::cipher::normalize_candidate;
/// assert_eq!(normalize_candidate("east north\neast")?, "EASTNORTHEAST");
/// # Ok::<(), kryptos_research::cipher::CipherError>(())
/// ```
pub fn normalize_candidate(input: &str) -> Result<String, CipherError> {
    let mut output = String::with_capacity(input.len());
    for (index, symbol) in input.char_indices() {
        if symbol.is_ascii_alphabetic() {
            output.push(symbol.to_ascii_uppercase());
        } else if !symbol.is_ascii_whitespace() {
            return Err(CipherError::InvalidSymbol { index, symbol });
        }
    }
    Ok(output)
}

/// One output position and the actual intermediate values used to compute it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PositionTrace {
    /// Zero-based output position within this stage.
    pub output_index: usize,
    /// Zero-based source input position within this stage.
    pub input_index: usize,
    /// Original input letter.
    pub input: char,
    /// Computed output letter.
    pub output: char,
    /// Alphabet index of input; absent for a pure permutation.
    pub input_value: Option<u8>,
    /// Numeric key residue; absent for a pure permutation.
    pub key_value: Option<u8>,
    /// Alphabet index of output; absent for a pure permutation.
    pub output_value: Option<u8>,
}

/// Text and a complete per-position explanation of one transformation stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Transform {
    /// Computed uppercase ASCII output.
    pub text: String,
    /// One record per output letter, in output order.
    pub trace: Vec<PositionTrace>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_is_explicit_and_preserves_only_allowed_characters() {
        assert_eq!(normalize_candidate("a z\t\r\n"), Ok("AZ".into()));
    }

    #[test]
    fn punctuation_digits_unicode_and_non_ascii_spaces_are_rejected() {
        for text in ["?", "1", "é", "A\u{a0}B"] {
            assert!(normalize_candidate(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn empty_normalization_is_valid() {
        assert_eq!(normalize_candidate(""), Ok(String::new()));
    }
}
