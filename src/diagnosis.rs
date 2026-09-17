//! Exact necessary-condition checks for direct, aligned baseline models.
//!
//! These exclusions do not transfer to internal stages of compound ciphers.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::evidence::{ALPHABET, Evidence};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Position {
    index_zero_based: usize,
    #[serde(rename = "position_one_based")]
    human_index: usize,
    plaintext: char,
    ciphertext: char,
    vigenere_key_value: u8,
}

impl Position {
    fn new(index: usize, plaintext: u8, ciphertext: u8) -> Self {
        Self {
            index_zero_based: index,
            human_index: index + 1,
            plaintext: char::from(plaintext),
            ciphertext: char::from(ciphertext),
            vigenere_key_value: (ciphertext + 26 - plaintext) % 26,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Rejected,
    NecessaryConditionPassed,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Witness {
    LetterDeficit {
        letter: char,
        available: u32,
        required: usize,
        positions_zero_based: Vec<usize>,
    },
    MappingConflict {
        direction: &'static str,
        first: Position,
        second: Position,
    },
    FixedPoint {
        position: Position,
    },
    PeriodConflict {
        residue: usize,
        first: Position,
        second: Position,
    },
}

#[derive(Debug, Serialize)]
struct Check {
    family: &'static str,
    assumptions: Vec<&'static str>,
    status: Status,
    witness: Option<Witness>,
}

impl Check {
    fn new(family: &'static str, assumptions: Vec<&'static str>, witness: Option<Witness>) -> Self {
        Self {
            family,
            assumptions,
            status: status(witness.as_ref()),
            witness,
        }
    }
}

#[derive(Debug, Serialize)]
struct CoincidenceIndex {
    numerator: u32,
    denominator: u32,
    value: f64,
}

#[derive(Debug, Serialize)]
struct PeriodCheck {
    period: usize,
    status: Status,
    constrained_slots: usize,
    unconstrained_slots: usize,
    witness: Option<Witness>,
}

#[derive(Debug, Serialize)]
struct VigenereReport {
    equation: &'static str,
    alphabet: &'static str,
    periods: Vec<PeriodCheck>,
    surviving_periods: Vec<usize>,
}

/// Serializable diagnosis, including each model's assumptions and witnesses.
///
/// Produced by [`diagnose`]. JSON schema version 1 is independent of the evidence
/// schema. `necessary_condition_passed` does not assert recovered text or a key.
/// The experiment runner binds this report to the evidence-file SHA-256 hash.
#[derive(Debug, Serialize)]
pub struct DiagnosisReport {
    schema_version: u32,
    evidence_id: String,
    ciphertext_length: usize,
    known_plaintext_count: usize,
    letter_counts: BTreeMap<char, u32>,
    ic: CoincidenceIndex,
    positions: Vec<Position>,
    checks: Vec<Check>,
    vigenere: VigenereReport,
}

/// Check the validated evidence against the direct, aligned baseline models.
///
/// Covers pure permutation, fixed single-letter encryption/decryption maps,
/// no-self-encryption, and standard A-Z additive Vigenère periods 1 through 97.
/// A global key phase merely renames residues and does not change consistency.
/// Includes raw counts, the exact IC ratio, and anchored-position traces.
/// This function performs no I/O, probabilistic tests, or heuristic search.
///
/// # Examples
///
/// ```
/// use kryptos_research::{diagnosis::diagnose, evidence::Evidence};
/// let evidence = Evidence::from_json(include_str!("../evidence/k4.json"))?;
/// let json = serde_json::to_value(diagnose(&evidence))?;
/// assert_eq!(json["ic"]["numerator"], 336);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub fn diagnose(evidence: &Evidence) -> DiagnosisReport {
    let ciphertext = evidence.ciphertext().as_bytes();
    let positions: Vec<_> = evidence
        .known_letters()
        .map(|(index, letter)| Position::new(index, letter, ciphertext[index]))
        .collect();
    let mut letter_counts: BTreeMap<_, _> =
        ALPHABET.chars().map(|letter| (letter, 0_u32)).collect();
    for byte in ciphertext {
        *letter_counts.entry(char::from(*byte)).or_default() += 1;
    }
    let checks = baseline_checks(&positions, &letter_counts);
    let periods: Vec<_> = (1..=ciphertext.len())
        .map(|period| check_period(&positions, period))
        .collect();
    let surviving_periods = periods
        .iter()
        .filter(|check| check.witness.is_none())
        .map(|check| check.period)
        .collect();
    let numerator = letter_counts
        .values()
        .map(|count| count * count.saturating_sub(1))
        .sum();
    // Evidence enforces exactly 97 symbols. Preserve the integer ratio so the
    // decimal approximation cannot be mistaken for the underlying measurement.
    let denominator = 97 * 96;
    DiagnosisReport {
        schema_version: 1,
        evidence_id: evidence.id().to_owned(),
        ciphertext_length: ciphertext.len(),
        known_plaintext_count: positions.len(),
        letter_counts,
        ic: CoincidenceIndex {
            numerator,
            denominator,
            value: f64::from(numerator) / f64::from(denominator),
        },
        positions,
        checks,
        vigenere: VigenereReport {
            equation: "c_i = p_i + k_(i mod t) (mod 26)",
            alphabet: ALPHABET,
            periods,
            surviving_periods,
        },
    }
}

fn status(witness: Option<&Witness>) -> Status {
    if witness.is_some() {
        Status::Rejected
    } else {
        Status::NecessaryConditionPassed
    }
}

fn baseline_checks(positions: &[Position], counts: &BTreeMap<char, u32>) -> Vec<Check> {
    vec![
        Check::new(
            "pure_transposition",
            vec![
                "A permutation of exactly the 97 baseline letters",
                "No substitution, addition, omission, or padding",
                "Anchors are in final normalized plaintext positions",
            ],
            transposition_witness(positions, counts),
        ),
        Check::new(
            "fixed_monoalphabetic_encryption",
            vec![
                "One deterministic plaintext-to-ciphertext letter map at all aligned positions",
                "No transposition, changing alphabets, or context-dependent mapping",
            ],
            mapping_witness(positions, true),
        ),
        Check::new(
            "fixed_monoalphabetic_decryption",
            vec![
                "One deterministic ciphertext-to-plaintext letter map at all aligned positions",
                "No transposition, changing alphabets, or context-dependent mapping",
            ],
            mapping_witness(positions, false),
        ),
        Check::new(
            "no_self_encryption",
            vec![
                "The final aligned encryption forbids P_i = C_i at every position",
                "This restriction is not inferred for internal stages of a compound cipher",
            ],
            positions
                .iter()
                .find(|position| position.plaintext == position.ciphertext)
                .map(|position| Witness::FixedPoint {
                    position: position.clone(),
                }),
        ),
    ]
}

fn transposition_witness(positions: &[Position], counts: &BTreeMap<char, u32>) -> Option<Witness> {
    for letter in ALPHABET.chars() {
        let required_positions: Vec<_> = positions
            .iter()
            .filter(|position| position.plaintext == letter)
            .map(|position| position.index_zero_based)
            .collect();
        let available = counts.get(&letter).copied().unwrap_or(0);
        if required_positions.len() > available as usize {
            return Some(Witness::LetterDeficit {
                letter,
                available,
                required: required_positions.len(),
                positions_zero_based: required_positions,
            });
        }
    }
    None
}

fn mapping_witness(positions: &[Position], encryption: bool) -> Option<Witness> {
    for (index, first) in positions.iter().enumerate() {
        for second in &positions[index + 1..] {
            let conflict = if encryption {
                first.plaintext == second.plaintext && first.ciphertext != second.ciphertext
            } else {
                first.ciphertext == second.ciphertext && first.plaintext != second.plaintext
            };
            if conflict {
                return Some(Witness::MappingConflict {
                    direction: if encryption {
                        "encryption"
                    } else {
                        "decryption"
                    },
                    first: first.clone(),
                    second: second.clone(),
                });
            }
        }
    }
    None
}

/// Callers enumerate nonzero periods 1..=97, bounding division and allocation.
fn check_period(positions: &[Position], period: usize) -> PeriodCheck {
    let mut first_by_residue: Vec<Option<&Position>> = vec![None; period];
    let mut witness = None;
    for position in positions {
        let residue = position.index_zero_based % period;
        if let Some(first) = first_by_residue[residue] {
            if first.vigenere_key_value != position.vigenere_key_value && witness.is_none() {
                witness = Some(Witness::PeriodConflict {
                    residue,
                    first: first.clone(),
                    second: position.clone(),
                });
            }
        } else {
            first_by_residue[residue] = Some(position);
        }
    }
    let constrained_slots = positions
        .iter()
        .map(|position| position.index_zero_based % period)
        .collect::<BTreeSet<_>>()
        .len();
    PeriodCheck {
        period,
        status: status(witness.as_ref()),
        constrained_slots,
        unconstrained_slots: period - constrained_slots,
        witness,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_report() -> DiagnosisReport {
        diagnose(&Evidence::from_json(include_str!("../evidence/k4.json")).unwrap())
    }

    #[test]
    fn published_baseline_has_exact_coincidence_ratio() {
        let report = baseline_report();
        assert_eq!((report.ic.numerator, report.ic.denominator), (336, 9312));
    }

    #[test]
    fn published_baseline_has_expected_period_survivors() {
        assert_eq!(
            baseline_report().vigenere.surviving_periods,
            [27, 28, 29].into_iter().chain(53..=97).collect::<Vec<_>>()
        );
    }

    #[test]
    fn transposition_certificate_counts_anchored_es() {
        assert_eq!(
            baseline_report().checks[0].witness,
            Some(Witness::LetterDeficit {
                letter: 'E',
                available: 2,
                required: 3,
                positions_zero_based: vec![21, 30, 64],
            })
        );
    }

    #[test]
    fn earliest_aligned_fixed_point_is_at_human_position_33() {
        assert_eq!(
            baseline_report().checks[3].witness,
            Some(Witness::FixedPoint {
                position: Position::new(32, b'S', b'S'),
            })
        );
    }

    #[test]
    fn period_certificates_have_incompatible_equations() {
        for check in baseline_report().vigenere.periods {
            if let Some(Witness::PeriodConflict {
                residue,
                first,
                second,
            }) = check.witness
            {
                assert!(
                    first.index_zero_based % check.period == residue
                        && second.index_zero_based % check.period == residue
                        && first.vigenere_key_value != second.vigenere_key_value
                );
            }
        }
    }

    #[test]
    fn key_residues_cover_all_letter_pairs_without_underflow() {
        for plain in b'A'..=b'Z' {
            for cipher in b'A'..=b'Z' {
                let position = Position::new(0, plain, cipher);
                assert_eq!(
                    (plain - b'A' + position.vigenere_key_value) % 26,
                    cipher - b'A'
                );
            }
        }
    }

    #[test]
    fn planted_repeating_key_with_phase_passes_its_period() {
        for period in 1..=97 {
            let key: Vec<_> = (0_u8..26).cycle().take(period).collect();
            for phase in [0, 1, 25, 97] {
                let positions: Vec<_> = (0..97)
                    .map(|index| {
                        let cipher = b'A' + u8::try_from(index % 26).unwrap();
                        let plain =
                            b'A' + (cipher - b'A' + 26 - key[(index + phase) % period]) % 26;
                        Position::new(index, plain, cipher)
                    })
                    .collect();
                assert_eq!(
                    check_period(&positions, period).status,
                    Status::NecessaryConditionPassed
                );
            }
        }
    }

    #[test]
    fn empty_constraints_reject_nothing_and_leave_all_slots_free() {
        let check = check_period(&[], 97);
        assert_eq!(
            (
                check.status,
                check.constrained_slots,
                check.unconstrained_slots
            ),
            (Status::NecessaryConditionPassed, 0, 97)
        );
    }

    #[test]
    fn single_constraint_leaves_other_key_slots_free() {
        let check = check_period(&[Position::new(96, b'Z', b'A')], 97);
        assert_eq!(
            (check.constrained_slots, check.unconstrained_slots),
            (1, 96)
        );
    }

    #[test]
    fn period_one_rejects_two_distinct_required_shifts() {
        assert_eq!(
            check_period(
                &[Position::new(0, b'A', b'A'), Position::new(1, b'A', b'B')],
                1
            )
            .status,
            Status::Rejected
        );
    }

    #[test]
    fn consistent_mappings_pass_in_both_directions() {
        let positions = [
            Position::new(0, b'A', b'B'),
            Position::new(1, b'A', b'B'),
            Position::new(2, b'Z', b'A'),
        ];
        assert!(
            mapping_witness(&positions, true).is_none()
                && mapping_witness(&positions, false).is_none()
        );
    }

    #[test]
    fn distinct_inputs_with_one_output_only_reject_decryption_map() {
        let positions = [Position::new(0, b'A', b'B'), Position::new(1, b'C', b'B')];
        assert!(
            mapping_witness(&positions, true).is_none()
                && mapping_witness(&positions, false).is_some()
        );
    }

    #[test]
    fn equal_letter_inventory_does_not_reject_transposition() {
        let positions = [Position::new(0, b'A', b'B'), Position::new(1, b'B', b'A')];
        assert!(transposition_witness(&positions, &BTreeMap::from([('A', 1), ('B', 1)])).is_none());
    }
}
