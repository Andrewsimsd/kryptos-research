//! Bounded decimal-primer batches and explicit crib-equation witnesses.

use super::{Decision, FeasibilityReport, solve};
use crate::{
    cipher::{CipherError, alphabet::Alphabet, constraints::Crib, gromark::Recurrence, parameter},
    evidence::Evidence,
};
use serde::{Deserialize, Serialize};

/// Explicit primer list and deterministic offset-attempt budget per primer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Supported schema is 1.
    pub schema_version: u32,
    /// 1–100 strictly increasing, nonzero five-digit decimal strings.
    pub primers: Vec<String>,
    /// Per-primer offset-attempt cap, in 1–10,000,000.
    pub attempt_limit: u32,
}

impl Request {
    fn validate(&self) -> Result<(), CipherError> {
        if self.schema_version != 1
            || !(1..=10_000_000).contains(&self.attempt_limit)
            || !(1..=100).contains(&self.primers.len())
            || self
                .primers
                .iter()
                .any(|p| p.len() != 5 || !p.bytes().all(|b| b.is_ascii_digit()) || p == "00000")
            || self.primers.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(parameter(
                "feasibility request",
                "requires schema 1, 1-100 sorted unique nonzero five-digit primers and attempt limit 1..=10000000",
            ));
        }
        Ok(())
    }
}

/// One directly checked crib equation under the complete witness alphabets.
#[derive(Debug, Serialize)]
pub struct CribEquation {
    /// Zero-based message position.
    pub position: usize,
    /// Known plaintext letter.
    pub plaintext: char,
    /// Corresponding ciphertext letter.
    pub ciphertext: char,
    /// Running key digit at this position.
    pub key: u8,
    /// Index of the plaintext letter in the witness alphabet.
    pub plaintext_index: u8,
    /// Index of the ciphertext letter in the witness alphabet.
    pub ciphertext_index: u8,
}

/// Decision and witness for one supplied primer.
#[derive(Debug, Serialize)]
pub struct PrimerResult {
    /// Original five-digit string, preserving leading zeros.
    pub primer: String,
    /// Numeric key at the 97 message positions; no extra check digit.
    pub expanded_key: String,
    /// Components, search work and decision.
    pub report: FeasibilityReport,
    /// All 24 equations for feasible results; empty for other decisions.
    pub crib_equations: Vec<CribEquation>,
}

/// Complete output for an explicit, bounded primer list.
#[derive(Debug, Serialize)]
pub struct BatchReport {
    /// Output schema version.
    pub schema_version: u32,
    /// Validated evidence identifier.
    pub evidence_id: String,
    /// Actual per-primer attempt limit.
    pub attempt_limit: u32,
    /// Results in supplied primer order.
    pub results: Vec<PrimerResult>,
}

/// Evaluate the aligned two-alphabet model for each explicitly supplied primer.
///
/// The base-10 recurrence includes the primer and has offset zero. Complete
/// alphabets are compatibility witnesses, not proposed historical keys.
/// # Errors
/// Rejects an invalid [`Request`], allocation failure, or an internally
/// inconsistent witness. Budget-limited results remain explicit in the output.
pub fn evaluate(evidence: &Evidence, request: &Request) -> Result<BatchReport, CipherError> {
    request.validate()?;
    let cribs: Vec<_> = evidence
        .known_letters()
        .map(|(position, letter)| Crib {
            position,
            letter: char::from(letter),
        })
        .collect();
    let mut results = Vec::new();
    for primer in &request.primers {
        let key = Recurrence::new(10, primer.bytes().map(|b| b - b'0').collect())?.generate(97)?;
        let report = solve(evidence.ciphertext(), &cribs, &key, request.attempt_limit)?;
        let crib_equations = equations(evidence, &key, &report.decision)?;
        results.push(PrimerResult {
            primer: primer.clone(),
            expanded_key: key.iter().map(|&k| char::from(b'0' + k)).collect(),
            report,
            crib_equations,
        });
    }
    Ok(BatchReport {
        schema_version: 1,
        evidence_id: evidence.id().to_owned(),
        attempt_limit: request.attempt_limit,
        results,
    })
}

fn equations(
    evidence: &Evidence,
    key: &[u8],
    decision: &Decision,
) -> Result<Vec<CribEquation>, CipherError> {
    let Decision::Feasible {
        plaintext_alphabet,
        ciphertext_alphabet,
        ..
    } = decision
    else {
        return Ok(Vec::new());
    };
    let plain = Alphabet::from_order(plaintext_alphabet)?;
    let cipher = Alphabet::from_order(ciphertext_alphabet)?;
    evidence
        .known_letters()
        .map(|(position, letter)| {
            let encrypted = evidence.ciphertext().as_bytes()[position];
            let plaintext_index = plain.index(letter)?;
            let ciphertext_index = cipher.index(encrypted)?;
            if (plaintext_index + key[position]) % 26 != ciphertext_index {
                return Err(parameter(
                    "alphabet witness",
                    "a generated alphabet pair violates a crib equation",
                ));
            }
            Ok(CribEquation {
                position,
                plaintext: char::from(letter),
                ciphertext: char::from(encrypted),
                key: key[position],
                plaintext_index,
                ciphertext_index,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_schema_primer_lists_and_budgets_are_rejected() {
        for primers in [
            vec![],
            vec!["00000"],
            vec!["1234"],
            vec!["1234a"],
            vec!["１２３４５"],
            vec!["00001", "00001"],
            vec!["00002", "00001"],
        ] {
            assert!(
                Request {
                    schema_version: 1,
                    primers: primers.into_iter().map(str::to_owned).collect(),
                    attempt_limit: 100
                }
                .validate()
                .is_err()
            );
        }
        for (schema_version, attempt_limit) in [(2, 100), (1, 0), (1, 10_000_001)] {
            assert!(
                Request {
                    schema_version,
                    primers: vec!["00001".into()],
                    attempt_limit
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            serde_json::from_str::<Request>(
                r#"{"schema_version":1,"primers":["00001"],"attempt_limit":10,"extra":0}"#
            )
            .is_err()
        );
    }

    #[test]
    fn incorrect_witness_is_an_error_and_nonwitness_has_no_trace() {
        let evidence = Evidence::from_json(include_str!("../../evidence/k4.json")).unwrap();
        let decision = Decision::Feasible {
            plaintext_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ".into(),
            ciphertext_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ".into(),
            offsets: vec![],
        };
        assert!(equations(&evidence, &[0; 97], &decision).is_err());
        assert!(
            equations(&evidence, &[0; 97], &Decision::BudgetExhausted)
                .unwrap()
                .is_empty()
        );
    }
}
