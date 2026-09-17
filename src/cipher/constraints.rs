//! Candidate crib checks and exact transport through pull permutations.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{CipherError, parameter, permutation::Permutation, validate_text};

/// One known plaintext letter at a zero-based final position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Crib {
    /// Zero-based position.
    pub position: usize,
    /// Known uppercase ASCII letter.
    pub letter: char,
}

/// A candidate's relation to the supplied cribs, not a cipher-family verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ConstraintCheck {
    /// All supplied positions agree; does not authenticate the candidate.
    Pass,
    /// First mismatch in position order, with a checkable witness.
    Mismatch {
        /// Zero-based final position.
        position: usize,
        /// Published or supplied expected letter.
        expected: char,
        /// Actual candidate letter.
        actual: char,
    },
}

pub(crate) fn validated(
    cribs: &[Crib],
    length: usize,
) -> Result<BTreeMap<usize, char>, CipherError> {
    let mut known = BTreeMap::new();
    for crib in cribs {
        if crib.position >= length || !crib.letter.is_ascii_uppercase() {
            return Err(parameter(
                "crib",
                "requires an in-range position and uppercase ASCII letter",
            ));
        }
        if known
            .insert(crib.position, crib.letter)
            .is_some_and(|previous| previous != crib.letter)
        {
            return Err(parameter(
                "cribs",
                "contradictory letters at the same position",
            ));
        }
    }
    Ok(known)
}

/// Check a candidate without modifying its text or positions.
///
/// # Errors
/// Rejects invalid text, wrong length, out-of-range cribs and conflicting cribs.
pub fn validate_constraints(
    candidate: &str,
    length: usize,
    cribs: &[Crib],
) -> Result<ConstraintCheck, CipherError> {
    validate_text(candidate)?;
    if candidate.len() != length {
        return Err(CipherError::LengthMismatch {
            expected: length,
            actual: candidate.len(),
        });
    }
    for (position, expected) in validated(cribs, length)? {
        let actual = char::from(candidate.as_bytes()[position]);
        if actual != expected {
            return Ok(ConstraintCheck::Mismatch {
                position,
                expected,
                actual,
            });
        }
    }
    Ok(ConstraintCheck::Pass)
}

/// Transport output-position constraints to input positions through a pull map.
///
/// For `out[j] = in[map[j]]`, an output crib at j becomes an input crib at
/// `map[j]`. Transport in the other direction using [`Permutation::inverse`].
///
/// # Errors
/// Rejects invalid or contradictory output cribs.
pub fn transport_to_input(cribs: &[Crib], map: &Permutation) -> Result<Vec<Crib>, CipherError> {
    let mut transported: Vec<_> = validated(cribs, map.indices().len())?
        .into_iter()
        .map(|(position, letter)| Crib {
            position: map.indices()[position],
            letter,
        })
        .collect();
    transported.sort_by_key(|crib| crib.position);
    Ok(transported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatch_identifies_exact_final_position() {
        assert_eq!(
            validate_constraints(
                "ABC",
                3,
                &[Crib {
                    position: 2,
                    letter: 'D'
                }]
            )
            .unwrap(),
            ConstraintCheck::Mismatch {
                position: 2,
                expected: 'D',
                actual: 'C'
            }
        );
    }

    #[test]
    fn transport_uses_source_indices_not_the_inverse_direction() {
        let map = Permutation::new(vec![2, 0, 1]).unwrap();
        assert_eq!(
            transport_to_input(
                &[Crib {
                    position: 0,
                    letter: 'C'
                }],
                &map
            )
            .unwrap(),
            vec![Crib {
                position: 2,
                letter: 'C'
            }]
        );
    }

    #[test]
    fn matching_and_empty_constraints_pass() {
        assert_eq!(
            validate_constraints("", 0, &[]).unwrap(),
            ConstraintCheck::Pass
        );
        assert_eq!(
            validate_constraints(
                "A",
                1,
                &[Crib {
                    position: 0,
                    letter: 'A'
                }; 2]
            )
            .unwrap(),
            ConstraintCheck::Pass
        );
    }

    #[test]
    fn invalid_length_symbols_ranges_and_conflicts_are_errors() {
        for (text, length, cribs) in [
            ("A", 2, vec![]),
            ("?", 1, vec![]),
            (
                "A",
                1,
                vec![Crib {
                    position: usize::MAX,
                    letter: 'A',
                }],
            ),
            (
                "A",
                1,
                vec![Crib {
                    position: 0,
                    letter: 'é',
                }],
            ),
            (
                "A",
                1,
                vec![
                    Crib {
                        position: 0,
                        letter: 'A',
                    },
                    Crib {
                        position: 0,
                        letter: 'B',
                    },
                ],
            ),
        ] {
            assert!(validate_constraints(text, length, &cribs).is_err());
        }
    }
}
