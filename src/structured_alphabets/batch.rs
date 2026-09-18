//! Strict batch schema and complete Cartesian structured-alphabet evaluation.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::{Equation, evaluate};
use crate::{
    cipher::{CipherError, alphabet::Alphabet, gromark::Recurrence, parameter},
    evidence::Evidence,
};
use serde::{Deserialize, Serialize};

const EXPECTED_MODELS: usize = 39 * 4 * 4 * 26;

/// A named permutation used as an alphabet construction.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Construction {
    /// Stable identifier used in canonical candidate IDs.
    pub id: String,
    /// Explicit 26-letter permutation before rotation.
    pub order: String,
}

/// One ordered plaintext/ciphertext construction pair.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphabetPair {
    /// Identifier of the unrotated plaintext construction.
    pub plaintext: String,
    /// Identifier of the ciphertext construction.
    pub ciphertext: String,
}

/// Complete finite domain for the structured-alphabet experiment.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Supported schema is 1.
    pub schema_version: u32,
    /// Exact sorted primer domain.
    pub primers: Vec<String>,
    /// Four named, unique alphabet constructions.
    pub constructions: Vec<Construction>,
    /// All 16 ordered construction pairs in Cartesian order.
    pub alphabet_pairs: Vec<AlphabetPair>,
    /// Sorted, unique left rotations of the ciphertext alphabet.
    pub ciphertext_rotations: Vec<u8>,
    /// Recurrence stream offset; this experiment requires zero.
    pub key_offset: u8,
}

impl Request {
    fn validate(&self) -> Result<Vec<Alphabet>, CipherError> {
        if self.schema_version != 1
            || self.key_offset != 0
            || self.primers.len() != 39
            || self.primers.iter().any(|primer| {
                primer.len() != 5
                    || primer == "00000"
                    || !primer.bytes().all(|byte| byte.is_ascii_digit())
            })
            || self.primers.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(parameter(
                "structured alphabet request",
                "requires schema 1, key offset zero and 39 sorted unique nonzero five-digit primers",
            ));
        }
        if self.constructions.len() != 4 {
            return Err(parameter(
                "constructions",
                "requires exactly four named constructions",
            ));
        }
        let mut identifiers = HashSet::new();
        let mut orders = HashSet::new();
        let mut alphabets = Vec::with_capacity(self.constructions.len());
        for construction in &self.constructions {
            if construction.id.is_empty()
                || !construction
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                || !identifiers.insert(construction.id.as_str())
                || !orders.insert(construction.order.as_str())
            {
                return Err(parameter(
                    "constructions",
                    "identifiers and alphabet orders must be nonempty and unique",
                ));
            }
            alphabets.push(Alphabet::from_order(&construction.order)?);
        }
        let expected_pairs: Vec<_> = self
            .constructions
            .iter()
            .flat_map(|plain| {
                self.constructions
                    .iter()
                    .map(move |cipher| (plain.id.as_str(), cipher.id.as_str()))
            })
            .collect();
        if self.alphabet_pairs.len() != expected_pairs.len()
            || self
                .alphabet_pairs
                .iter()
                .zip(expected_pairs)
                .any(|(actual, expected)| {
                    (actual.plaintext.as_str(), actual.ciphertext.as_str()) != expected
                })
        {
            return Err(parameter(
                "alphabet pairs",
                "must be the complete ordered Cartesian product in construction order",
            ));
        }
        if self.ciphertext_rotations != (0_u8..26).collect::<Vec<_>>() {
            return Err(parameter(
                "ciphertext rotations",
                "must contain every value 0..25 exactly once in ascending order",
            ));
        }
        Ok(alphabets)
    }
}

/// Identity of one canonical model in the registered Cartesian product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    /// Stable, colon-separated canonical identifier.
    pub id: String,
    /// Five-digit decimal primer.
    pub primer: String,
    /// Unrotated plaintext construction identifier.
    pub plaintext_construction: String,
    /// Ciphertext construction identifier before rotation.
    pub ciphertext_construction: String,
    /// Left rotation applied to the ciphertext alphabet.
    pub ciphertext_rotation: u8,
}

/// A rejected candidate and its first true mismatching equation.
#[derive(Debug, Serialize)]
pub struct Rejection {
    /// Canonical candidate identity.
    #[serde(flatten)]
    pub candidate: Candidate,
    /// Total matching equations among all 24 cribs.
    pub match_count: usize,
    /// Earliest mismatch in ascending message position.
    pub first_mismatch: Equation,
}

/// A candidate satisfying every crib equation.
#[derive(Debug, Serialize)]
pub struct Survivor {
    /// Canonical candidate identity.
    #[serde(flatten)]
    pub candidate: Candidate,
    /// Expanded 97-digit recurrence stream.
    pub expanded_key: String,
    /// Rotated plaintext alphabet order; plaintext rotation is fixed at zero.
    pub plaintext_alphabet: String,
    /// Left-rotated ciphertext alphabet order.
    pub ciphertext_alphabet: String,
    /// Complete 24-equation trace.
    pub equations: Vec<Equation>,
}

/// Aggregate counts and complete decisions for the finite registered domain.
#[derive(Debug, Serialize)]
pub struct BatchReport {
    /// Output schema version.
    pub schema_version: u32,
    /// Validated evidence identifier.
    pub evidence_id: String,
    /// Number of canonical models evaluated.
    pub models_evaluated: usize,
    /// Number of individual crib equations evaluated.
    pub equation_evaluations: usize,
    /// Count of models by number of matching equations.
    pub match_histogram: BTreeMap<usize, usize>,
    /// Every rejected model in canonical order.
    pub rejections: Vec<Rejection>,
    /// Every fully compatible model in canonical order.
    pub survivors: Vec<Survivor>,
}

/// Exhaustively evaluate the request's canonical Cartesian product.
///
/// Plaintext rotation is fixed at zero. This is complete because adding the
/// same rotation to both alphabet orders preserves every index difference.
///
/// # Errors
///
/// Rejects malformed or incomplete domains, invalid alphabets and any internal
/// duplicate candidate identifier.
pub fn evaluate_request(
    evidence: &Evidence,
    request: &Request,
) -> Result<BatchReport, CipherError> {
    let alphabets = request.validate()?;
    let by_id: HashMap<_, _> = request
        .constructions
        .iter()
        .zip(&alphabets)
        .map(|(construction, alphabet)| (construction.id.as_str(), alphabet))
        .collect();
    let cribs: Vec<_> = evidence.known_letters().collect();
    let mut identifiers = HashSet::with_capacity(EXPECTED_MODELS);
    let mut match_histogram = BTreeMap::new();
    let mut rejections = Vec::new();
    let mut survivors = Vec::new();

    for primer in &request.primers {
        let key = Recurrence::new(10, primer.bytes().map(|byte| byte - b'0').collect())?
            .generate(evidence.ciphertext().len())?;
        let expanded_key: String = key.iter().map(|&digit| char::from(b'0' + digit)).collect();
        for pair in &request.alphabet_pairs {
            let plaintext_alphabet = by_id[&pair.plaintext.as_str()];
            let ciphertext_base = by_id[&pair.ciphertext.as_str()];
            for &rotation in &request.ciphertext_rotations {
                let candidate = Candidate {
                    id: format!(
                        "{}:{}:{}:{rotation:02}",
                        primer, pair.plaintext, pair.ciphertext
                    ),
                    primer: primer.clone(),
                    plaintext_construction: pair.plaintext.clone(),
                    ciphertext_construction: pair.ciphertext.clone(),
                    ciphertext_rotation: rotation,
                };
                if !identifiers.insert(candidate.id.clone()) {
                    return Err(parameter(
                        "candidate domain",
                        "duplicate canonical identifier",
                    ));
                }
                let ciphertext_alphabet = ciphertext_base.rotated(usize::from(rotation));
                let evaluated = evaluate(
                    plaintext_alphabet,
                    &ciphertext_alphabet,
                    evidence.ciphertext(),
                    &cribs,
                    &key,
                )?;
                *match_histogram.entry(evaluated.match_count).or_insert(0) += 1;
                if let Some(first_mismatch) = evaluated.first_mismatch {
                    rejections.push(Rejection {
                        candidate,
                        match_count: evaluated.match_count,
                        first_mismatch,
                    });
                } else {
                    survivors.push(Survivor {
                        candidate,
                        expanded_key: expanded_key.clone(),
                        plaintext_alphabet: plaintext_alphabet.order(),
                        ciphertext_alphabet: ciphertext_alphabet.order(),
                        equations: evaluated.equations,
                    });
                }
            }
        }
    }
    if identifiers.len() != EXPECTED_MODELS {
        return Err(parameter(
            "candidate domain",
            "canonical model coverage differs from 39*4*4*26",
        ));
    }
    Ok(BatchReport {
        schema_version: 1,
        evidence_id: evidence.id().to_owned(),
        models_evaluated: identifiers.len(),
        equation_evaluations: identifiers.len() * cribs.len(),
        match_histogram,
        rejections,
        survivors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request_value() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../fixtures/structured-alphabets-request.json"
        ))
        .unwrap()
    }

    #[test]
    fn registered_request_has_exact_cartesian_coverage() {
        let request: Request = serde_json::from_value(request_value()).unwrap();
        assert_eq!(request.validate().unwrap().len(), 4);
    }

    #[test]
    fn malformed_domains_are_rejected() {
        for mutate in [
            "schema",
            "primer",
            "construction",
            "pair",
            "rotation",
            "offset",
        ] {
            let mut value = request_value();
            match mutate {
                "schema" => value["schema_version"] = json!(2),
                "primer" => value["primers"][1] = value["primers"][0].clone(),
                "construction" => {
                    value["constructions"][1]["order"] = value["constructions"][0]["order"].clone();
                }
                "pair" => value["alphabet_pairs"]
                    .as_array_mut()
                    .unwrap()
                    .pop()
                    .map_or((), drop),
                "rotation" => value["ciphertext_rotations"][25] = json!(24),
                "offset" => value["key_offset"] = json!(1),
                _ => unreachable!(),
            }
            let request: Request = serde_json::from_value(value).unwrap();
            assert!(request.validate().is_err(), "mutation {mutate}");
        }
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut value = request_value();
        value["extra"] = json!(true);
        assert!(serde_json::from_value::<Request>(value).is_err());
    }

    #[test]
    fn planted_full_batch_emits_a_complete_rotated_survivor() {
        let request: Request = serde_json::from_value(request_value()).unwrap();
        let primer = &request.primers[0];
        let key = Recurrence::new(10, primer.bytes().map(|byte| byte - b'0').collect())
            .unwrap()
            .generate(97)
            .unwrap();
        let mut manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../evidence/k4.json")).unwrap();
        manifest["evidence_id"] = json!("STRUCTURED-ALPHABETS-PLANTED");
        let mut ciphertext = [b'X'; 97];
        for anchor in manifest["anchors"].as_array_mut().unwrap() {
            let start = usize::try_from(anchor["start"].as_u64().unwrap()).unwrap();
            let plaintext = anchor["plaintext"].as_str().unwrap().as_bytes();
            for (offset, &letter) in plaintext.iter().enumerate() {
                ciphertext[start + offset] = b'A' + ((letter - b'A' + key[start + offset]) % 26);
            }
            anchor["ciphertext"] = json!(
                ciphertext[start..start + plaintext.len()]
                    .iter()
                    .copied()
                    .map(char::from)
                    .collect::<String>()
            );
        }
        let ciphertext: String = ciphertext.iter().copied().map(char::from).collect();
        let lines = [
            &ciphertext[..4],
            &ciphertext[4..35],
            &ciphertext[35..66],
            &ciphertext[66..97],
        ];
        manifest["ciphertext"] = json!(ciphertext);
        manifest["physical_lines"] = json!(lines);
        let transcription_ciphertext = manifest["ciphertext"].clone();
        let transcription_lines = manifest["physical_lines"].clone();
        for transcription in manifest["transcriptions"].as_array_mut().unwrap() {
            transcription["ciphertext"] = transcription_ciphertext.clone();
            transcription["physical_lines"] = transcription_lines.clone();
        }
        let evidence = Evidence::from_json(&manifest.to_string()).unwrap();
        let report = evaluate_request(&evidence, &request).unwrap();
        let survivor = report
            .survivors
            .iter()
            .find(|survivor| survivor.candidate.id == "10319:az-forward:az-forward:00")
            .unwrap();
        assert_eq!(survivor.expanded_key.len(), 97);
        assert_eq!(survivor.plaintext_alphabet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert_eq!(survivor.ciphertext_alphabet, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert!(survivor.equations.len() == 24 && survivor.equations.iter().all(Equation::matches));
        let serialized = serde_json::to_value(&report).unwrap();
        assert_eq!(
            serialized["survivors"][0]["equations"]
                .as_array()
                .unwrap()
                .len(),
            24
        );
    }
}
