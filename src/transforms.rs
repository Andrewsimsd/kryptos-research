//! Strict JSON requests for explicit, reversible cipher pipelines.
//!
//! Stages are declared in encryption order. Decryption reverses their order and
//! inverts each stage. There are no named K1/K2/K3 shortcuts or plaintext lookups.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, error::Error, fmt};

use crate::cipher::{
    CipherError, Transform,
    alphabet::Alphabet,
    gromark::Gromark,
    permutation::Permutation,
    polyalphabetic::{Direction, Equation, RepeatingCipher},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    schema_version: u32,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    input: String,
    direction: Direction,
    stages: Vec<Stage>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
enum Stage {
    Repeating {
        plaintext_alphabet: String,
        ciphertext_alphabet: String,
        key_alphabet: String,
        keyword: String,
        equation: Equation,
        offset: usize,
    },
    Gromark {
        keyword: String,
        primer: [u8; 5],
    },
    Columnar {
        column_order: Vec<usize>,
        reverse_rows: bool,
        inverse: bool,
    },
}

/// Invalid JSON, invalid pipeline structure, or a model execution error.
#[derive(Debug)]
pub enum BatchError {
    /// JSON failed to match the strict, versioned request schema.
    Json(serde_json::Error),
    /// The batch has unsupported version, missing stages, or invalid case IDs.
    Structure(&'static str),
    /// One named case has an invalid key, alphabet, message or route.
    Cipher {
        /// Identifier of the failing case.
        case_id: String,
        /// Original validation failure.
        source: CipherError,
    },
}

impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "invalid transform JSON: {error}"),
            Self::Structure(message) => write!(f, "invalid transform batch: {message}"),
            Self::Cipher { case_id, source } => write!(f, "case {case_id}: {source}"),
        }
    }
}

impl Error for BatchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Cipher { source, .. } => Some(source),
            Self::Structure(_) => None,
        }
    }
}

#[derive(Debug, Serialize)]
struct CaseResult {
    id: String,
    direction: Direction,
    output: String,
    canonical_encryption_stages: Vec<String>,
    stages: Vec<Transform>,
}

/// Serializable outputs and complete stage traces, in the request's case order.
///
/// `canonical_encryption_stages` always uses encryption order; `stages` uses
/// execution order (reversed during decryption). See [`execute_batch`].
#[derive(Debug, Serialize)]
pub struct BatchResult {
    schema_version: u32,
    cases: Vec<CaseResult>,
}

impl Stage {
    fn execute(
        &self,
        input: &str,
        direction: Direction,
    ) -> Result<(String, Transform), CipherError> {
        match self {
            Self::Repeating {
                plaintext_alphabet,
                ciphertext_alphabet,
                key_alphabet,
                keyword,
                equation,
                offset,
            } => {
                let cipher = RepeatingCipher::new(
                    Alphabet::from_order(plaintext_alphabet)?,
                    Alphabet::from_order(ciphertext_alphabet)?,
                    Alphabet::from_order(key_alphabet)?,
                    keyword,
                    *equation,
                )?;
                let result = match direction {
                    Direction::Encrypt => cipher.encrypt(input, *offset)?,
                    Direction::Decrypt => cipher.decrypt(input, *offset)?,
                };
                Ok((cipher.canonical_id(*offset), result))
            }
            Self::Gromark { keyword, primer } => {
                let cipher = Gromark::new(keyword, *primer)?;
                let result = match direction {
                    Direction::Encrypt => cipher.encrypt(input)?,
                    Direction::Decrypt => cipher.decrypt(input)?,
                };
                Ok((cipher.canonical_id(), result))
            }
            Self::Columnar {
                column_order,
                reverse_rows,
                inverse,
            } => {
                let map = Permutation::columnar(input.len(), column_order, *reverse_rows)?;
                let encryption = if *inverse { map.inverse() } else { map };
                let canonical = encryption.canonical_id();
                let execution = match direction {
                    Direction::Encrypt => encryption,
                    Direction::Decrypt => encryption.inverse(),
                };
                Ok((canonical, execution.apply(input)?))
            }
        }
    }
}

/// Execute normalized messages under explicitly declared pipeline models.
///
/// Schema 1 has `cases`, each with `id`, `input`, `direction` (`encrypt` or
/// `decrypt`) and nonempty `stages` in encryption order. Stage families are
/// `repeating`, `gromark` and `columnar`; all their parameters are required.
/// The reproducible examples live in `fixtures/known-answers.json` and the
/// complete conventions in `docs/cipher-conventions.md`.
///
/// # Errors
/// Returns [`BatchError`] for malformed or unknown JSON fields, unsupported
/// version, empty/duplicate case IDs, empty pipelines, or invalid model inputs.
/// A malformed case fails the whole batch; no partial results are returned.
pub fn execute_batch(input: &str) -> Result<BatchResult, BatchError> {
    let batch: Batch = serde_json::from_str(input).map_err(BatchError::Json)?;
    if batch.schema_version != 1 {
        return Err(BatchError::Structure("schema_version must be 1"));
    }
    let mut identifiers = BTreeSet::new();
    let mut results = Vec::with_capacity(batch.cases.len());
    for case in batch.cases {
        if case.id.trim().is_empty() || !identifiers.insert(case.id.clone()) {
            return Err(BatchError::Structure(
                "case IDs must be nonempty and unique",
            ));
        }
        if case.stages.is_empty() {
            return Err(BatchError::Structure("each case needs at least one stage"));
        }
        let mut output = case.input;
        let mut canonical = vec![String::new(); case.stages.len()];
        let mut traces = Vec::with_capacity(case.stages.len());
        for step in 0..case.stages.len() {
            let index = match case.direction {
                Direction::Encrypt => step,
                Direction::Decrypt => case.stages.len() - 1 - step,
            };
            let (id, result) = case.stages[index]
                .execute(&output, case.direction)
                .map_err(|source| BatchError::Cipher {
                    case_id: case.id.clone(),
                    source,
                })?;
            canonical[index] = id;
            output.clone_from(&result.text);
            traces.push(result);
        }
        results.push(CaseResult {
            id: case.id,
            direction: case.direction,
            output,
            canonical_encryption_stages: canonical,
            stages: traces,
        });
    }
    Ok(BatchResult {
        schema_version: 1,
        cases: results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reverse_execution_order_restores_two_stage_plaintext() {
        let stage1 =
            json!({"family":"columnar","column_order":[1,0],"reverse_rows":false,"inverse":false});
        let stage2 =
            json!({"family":"columnar","column_order":[2,0,1],"reverse_rows":true,"inverse":false});
        let request = json!({"schema_version":1,"cases":[{"id":"manual","input":"EFABCD","direction":"decrypt","stages":[stage1,stage2]}]});
        assert_eq!(
            execute_batch(&request.to_string()).unwrap().cases[0].output,
            "ABCDEF"
        );
    }

    #[test]
    fn schema_and_empty_pipeline_errors_are_rejected() {
        for value in [
            json!({"schema_version":2,"cases":[]}),
            json!({"schema_version":1,"cases":[],"typo":0}),
            json!({"schema_version":1,"cases":[{"id":"a","input":"A","direction":"encrypt","stages":[]}]}),
        ] {
            assert!(execute_batch(&value.to_string()).is_err());
        }
    }

    #[test]
    fn duplicate_ids_and_invalid_models_return_errors() {
        let case = json!({"id":"a","input":"A","direction":"encrypt","stages":[{"family":"gromark","keyword":"A","primer":[0,0,0,0,0]}]});
        let duplicate = json!({"schema_version":1,"cases":[case.clone(),case.clone()]});
        assert!(execute_batch(&duplicate.to_string()).is_err());
        let mut bad = case;
        bad["stages"][0]["primer"] = json!([10, 0, 0, 0, 0]);
        let error =
            execute_batch(&json!({"schema_version":1,"cases":[bad]}).to_string()).unwrap_err();
        assert!(error.source().is_some() && error.to_string().contains("case a"));
    }
}
