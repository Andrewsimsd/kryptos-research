//! Strict parsing of the versioned, source-linked K4 evidence manifest.

use std::{collections::BTreeSet, error::Error, fmt};

use serde::Deserialize;

/// The standard alphabet used by this milestone's direct additive model.
pub const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// A manifest parsing or validation failure.
#[derive(Debug)]
pub enum EvidenceError {
    /// The input is not JSON matching the evidence schema.
    Json(serde_json::Error),
    /// A structurally readable manifest violates an evidence invariant.
    Invalid(String),
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "invalid evidence JSON: {error}"),
            Self::Invalid(message) => write!(f, "invalid evidence: {message}"),
        }
    }
}

impl Error for EvidenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    evidence_id: String,
    alphabet: String,
    indexing: String,
    normalization: String,
    ciphertext: String,
    physical_lines: Vec<String>,
    known_plaintext_count: usize,
    anchors: Vec<Anchor>,
    source_ids: Vec<String>,
    transcriptions: Vec<Transcription>,
    unresolved_issues: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    id: String,
    start: usize,
    end: usize,
    ciphertext: String,
    plaintext: String,
    source_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transcription {
    source_id: String,
    physical_lines: Vec<String>,
    ciphertext: String,
}

/// Validated, immutable evidence for the 97-letter baseline.
///
/// Construct with [`Evidence::from_json`]. Ciphertext bytes are guaranteed to be
/// uppercase ASCII and known plaintext positions are distinct and in bounds.
/// Structural validation cannot authenticate sources; see the source ledger.
#[derive(Debug)]
pub struct Evidence {
    id: String,
    ciphertext: String,
    known_plaintext: Vec<Option<u8>>,
}

impl Evidence {
    /// Parse and validate a version-1 evidence manifest without normalizing it.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError`] for malformed JSON, unknown fields, unsupported
    /// conventions, non-ASCII letters, incorrect line lengths, missing source
    /// references, inconsistent transcriptions, overlapping or invalid anchors,
    /// or a known-plaintext count other than 24. Whitespace and punctuation in
    /// cipher strings are rejected rather than silently removed.
    ///
    /// # Examples
    ///
    /// ```
    /// use kryptos_research::evidence::Evidence;
    /// let evidence = Evidence::from_json(include_str!("../evidence/k4.json"))?;
    /// assert_eq!(evidence.ciphertext().len(), 97);
    /// # Ok::<(), kryptos_research::evidence::EvidenceError>(())
    /// ```
    pub fn from_json(input: &str) -> Result<Self, EvidenceError> {
        let manifest: Manifest = serde_json::from_str(input).map_err(EvidenceError::Json)?;
        validate_conventions(&manifest)?;
        validate_transcriptions(&manifest)?;
        let known_plaintext = validate_anchors(&manifest)?;
        Ok(Self {
            id: manifest.evidence_id,
            ciphertext: manifest.ciphertext,
            known_plaintext,
        })
    }

    /// Return the human-readable version label; artifact identity uses SHA-256.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Return the unchanged, validated ASCII ciphertext.
    #[must_use]
    pub fn ciphertext(&self) -> &str {
        &self.ciphertext
    }

    /// Iterate over `(zero_based_position, ASCII_plaintext_letter)` anchors.
    pub fn known_letters(&self) -> impl Iterator<Item = (usize, u8)> + '_ {
        self.known_plaintext
            .iter()
            .enumerate()
            .filter_map(|(index, letter)| letter.map(|letter| (index, letter)))
    }
}

fn require(condition: bool, message: impl Into<String>) -> Result<(), EvidenceError> {
    if condition {
        Ok(())
    } else {
        Err(EvidenceError::Invalid(message.into()))
    }
}

fn validate_conventions(manifest: &Manifest) -> Result<(), EvidenceError> {
    require(manifest.schema_version == 1, "schema_version must be 1")?;
    require(
        !manifest.evidence_id.trim().is_empty(),
        "evidence_id is empty",
    )?;
    require(
        manifest.alphabet == ALPHABET,
        "alphabet must be standard A-Z",
    )?;
    require(
        manifest.indexing == "zero_based_half_open",
        "indexing must be zero_based_half_open",
    )?;
    require(
        manifest.normalization == "uppercase_ascii_no_whitespace_no_question_mark",
        "unsupported normalization convention",
    )?;
    require(
        manifest.ciphertext.len() == 97
            && manifest
                .ciphertext
                .bytes()
                .all(|byte| byte.is_ascii_uppercase()),
        "ciphertext must contain exactly 97 uppercase ASCII letters",
    )?;
    require(
        manifest
            .physical_lines
            .iter()
            .map(String::len)
            .collect::<Vec<_>>()
            == [4, 31, 31, 31]
            && manifest.physical_lines.concat() == manifest.ciphertext,
        "physical_lines must reproduce ciphertext with lengths 4,31,31,31",
    )?;
    let source_ids: BTreeSet<_> = manifest.source_ids.iter().collect();
    require(
        source_ids.len() == manifest.source_ids.len()
            && source_ids.len() >= 2
            && source_ids.iter().all(|id| !id.trim().is_empty()),
        "source_ids must contain at least two distinct nonempty references",
    )?;
    require(
        manifest
            .unresolved_issues
            .iter()
            .all(|issue| !issue.trim().is_empty()),
        "unresolved_issues cannot contain empty entries",
    )
}

fn validate_transcriptions(manifest: &Manifest) -> Result<(), EvidenceError> {
    let mut sources = BTreeSet::new();
    for transcription in &manifest.transcriptions {
        require(
            manifest.source_ids.contains(&transcription.source_id)
                && sources.insert(&transcription.source_id),
            "transcriptions must cite distinct declared sources",
        )?;
        require(
            transcription.ciphertext == manifest.ciphertext
                && transcription.physical_lines == manifest.physical_lines,
            format!(
                "transcription {} disagrees with baseline",
                transcription.source_id
            ),
        )?;
    }
    require(
        sources.len() >= 2,
        "at least two agreeing transcriptions are required",
    )
}

fn validate_anchors(manifest: &Manifest) -> Result<Vec<Option<u8>>, EvidenceError> {
    let mut known = vec![None; manifest.ciphertext.len()];
    let mut ids = BTreeSet::new();
    for anchor in &manifest.anchors {
        require(
            !anchor.id.trim().is_empty() && ids.insert(&anchor.id),
            "anchor IDs must be nonempty and unique",
        )?;
        require(
            anchor.start < anchor.end && anchor.end <= known.len(),
            format!("anchor {} has an invalid half-open range", anchor.id),
        )?;
        require(
            anchor.plaintext.len() == anchor.end - anchor.start
                && anchor
                    .plaintext
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase()),
            format!(
                "anchor {} plaintext must match its range and use A-Z",
                anchor.id
            ),
        )?;
        require(
            manifest.ciphertext[anchor.start..anchor.end] == anchor.ciphertext,
            format!("anchor {} ciphertext disagrees with its slice", anchor.id),
        )?;
        require(
            !anchor.source_ids.is_empty()
                && anchor
                    .source_ids
                    .iter()
                    .all(|id| manifest.source_ids.contains(id)),
            format!("anchor {} must cite declared sources", anchor.id),
        )?;
        for (index, letter) in (anchor.start..anchor.end).zip(anchor.plaintext.bytes()) {
            require(
                known[index].is_none(),
                format!("anchor {} overlaps at index {index}", anchor.id),
            )?;
            known[index] = Some(letter);
        }
    }
    require(
        manifest.known_plaintext_count == 24 && known.iter().flatten().count() == 24,
        "baseline must contain exactly 24 distinct known plaintext letters",
    )?;
    Ok(known)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn baseline() -> Value {
        serde_json::from_str(include_str!("../evidence/k4.json")).unwrap()
    }

    #[test]
    fn published_baseline_has_expected_known_positions() {
        let evidence = Evidence::from_json(&baseline().to_string()).unwrap();
        assert_eq!(
            evidence.known_letters().map(|(i, _)| i).collect::<Vec<_>>(),
            (21..34).chain(63..74).collect::<Vec<_>>()
        );
    }

    #[test]
    fn malformed_or_empty_json_is_rejected() {
        for input in ["", "{", "null", "{}"] {
            assert!(Evidence::from_json(input).is_err(), "{input}");
        }
    }

    #[test]
    fn invalid_manifest_fields_are_rejected() {
        let changes = [
            ("/schema_version", json!(2)),
            ("/evidence_id", json!("")),
            ("/alphabet", json!("ZYX")),
            ("/indexing", json!("one_based")),
            ("/normalization", json!("strip_punctuation")),
            ("/ciphertext", json!("é".repeat(97))),
            ("/ciphertext", json!("A".repeat(96) + "?")),
            ("/ciphertext", json!("A".repeat(98))),
            ("/physical_lines/0", json!("OBKR ")),
            ("/known_plaintext_count", json!(23)),
            ("/source_ids", json!(["S001", "S001"])),
            ("/source_ids", json!([""])),
            ("/transcriptions", json!([])),
            ("/transcriptions/1/source_id", json!("S001")),
            ("/transcriptions/0/ciphertext", json!("A".repeat(97))),
            ("/unresolved_issues", json!([""])),
            ("/anchors/0/start", json!(97)),
            ("/anchors/0/end", json!(usize::MAX)),
            ("/anchors/0/end", json!(21)),
            ("/anchors/0/start", json!(-1)),
            ("/anchors/0/plaintext", json!("East")),
            ("/anchors/0/plaintext", json!("")),
            ("/anchors/0/ciphertext", json!("AAAA")),
            ("/anchors/0/source_ids", json!(["absent"])),
            ("/anchors/0/source_ids", json!([])),
            ("/anchors/0/id", json!("")),
            ("/anchors/1/id", json!("EAST")),
            ("/anchors", json!([])),
        ];
        for (pointer, value) in changes {
            let mut manifest = baseline();
            *manifest.pointer_mut(pointer).unwrap() = value;
            assert!(
                Evidence::from_json(&manifest.to_string()).is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn overlap_is_rejected_even_if_letters_agree() {
        let mut manifest = baseline();
        let mut duplicate = manifest["anchors"][0].clone();
        duplicate["id"] = json!("duplicate");
        manifest["anchors"].as_array_mut().unwrap().push(duplicate);
        assert!(
            Evidence::from_json(&manifest.to_string())
                .unwrap_err()
                .to_string()
                .contains("overlaps")
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut manifest = baseline();
        manifest["implicit_padding"] = json!(true);
        assert!(Evidence::from_json(&manifest.to_string()).is_err());
    }

    #[test]
    fn json_error_retains_its_source() {
        assert!(Evidence::from_json("{").unwrap_err().source().is_some());
    }
}
