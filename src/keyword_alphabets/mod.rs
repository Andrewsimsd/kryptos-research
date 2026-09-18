//! Registered keyword-derived alphabet construction, calibration and K4 search.
//!
//! The finite domain is deliberately limited to three evidenced K4 words, two
//! constructors, two orientations, all ordered alphabet pairs, and relative
//! rotations. Calibration uses only planted plaintext and the same 24 known
//! positions; K4 evaluation never infers or scores unknown plaintext.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{
    cipher::{
        CipherError, alphabet::Alphabet, gromark::Recurrence, gromark::aca_transposed_alphabet,
        parameter,
    },
    evidence::Evidence,
    structured_alphabets::{Equation, evaluate},
};
use serde::{Deserialize, Serialize};

/// Number of registered decimal primers.
pub const PRIMER_COUNT: usize = 39;
/// Number of derived base alphabet orders.
pub const BASE_COUNT: usize = 12;
/// Number of canonical physical candidates.
pub const CANDIDATE_COUNT: usize = PRIMER_COUNT * BASE_COUNT * BASE_COUNT * 26;
const CRIB_COUNT: usize = 24;
const MESSAGE_LENGTH: usize = 97;
const REGISTERED_PRIMERS: [&str; PRIMER_COUNT] = [
    "10319", "12042", "16795", "16953", "20173", "20707", "22856", "26717", "30016", "30640",
    "30690", "30987", "36650", "38175", "38254", "38888", "40909", "44157", "52654", "54258",
    "56852", "58456", "60101", "60319", "62389", "66953", "70094", "70173", "70410", "70460",
    "72856", "80303", "84393", "84501", "84551", "88254", "94157", "98800", "98850",
];

/// A sourced keyword and its declared experimental role.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeywordSpec {
    /// Stable lowercase identifier.
    pub id: String,
    /// Uppercase keyword supplied to both constructors.
    pub keyword: String,
    /// Source identifier in the frozen evidence ledger.
    pub source_id: String,
    /// Historical role or explicit repurposing disclosure.
    pub role: String,
}

/// Deterministic planted-calibration settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationSpec {
    /// Nonzero xorshift32 seed.
    pub seed: u32,
    /// Exactly one case per ordered base-alphabet pair.
    pub case_count: usize,
    /// Planted plaintext/ciphertext length.
    pub message_length: usize,
    /// Frozen generator description.
    pub rng: String,
    /// Frozen assignment rule.
    pub assignment: String,
}

/// Complete registered keyword-alphabet domain.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Supported schema is 1.
    pub schema_version: u32,
    /// Exact sorted 39-primer domain.
    pub primers: Vec<String>,
    /// Exact sourced keyword hypotheses.
    pub keywords: Vec<KeywordSpec>,
    /// `keyword_fill` followed by `aca_gromark_transposed`.
    pub constructors: Vec<String>,
    /// `forward` followed by `reversed`.
    pub orientations: Vec<String>,
    /// All relative ciphertext rotations in ascending order.
    pub ciphertext_rotations: Vec<u8>,
    /// Required recurrence stream offset, zero.
    pub key_offset: u8,
    /// Planted calibration contract.
    pub calibration: CalibrationSpec,
}

/// One runtime-derived base order.
#[derive(Debug, Clone)]
pub struct BaseOrder {
    /// Stable physical construction identifier.
    pub id: String,
    /// Constructed alphabet.
    pub alphabet: Alphabet,
}

/// Decoded fields of a canonical candidate index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CandidateCoordinates {
    /// Primer offset in the request.
    pub primer_index: usize,
    /// Plaintext base-order offset.
    pub plaintext_base_index: usize,
    /// Ciphertext base-order offset.
    pub ciphertext_base_index: usize,
    /// Relative left rotation of the ciphertext alphabet.
    pub ciphertext_rotation: u8,
}

/// Signature-bucket counts for all physical candidates.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureCensus {
    /// Physical candidates, retaining construction identities across collisions.
    pub physical_candidates: usize,
    /// Distinct 24-letter predicted-crib signatures.
    pub distinct_signatures: usize,
    /// Buckets containing one candidate.
    pub singleton_buckets: usize,
    /// Buckets containing two candidates.
    pub doubleton_buckets: usize,
    /// Candidates belonging to singleton buckets.
    pub unique_physical_candidates: usize,
    /// Largest observed bucket.
    pub maximum_bucket_size: usize,
}

/// Exact primary-operation counts for the calibration phase.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationOperations {
    /// Candidate/crib equations evaluated for the signature census.
    pub signature_equation_evaluations: usize,
    /// Positions encrypted to construct planted ciphertexts.
    pub planted_encryption_positions: usize,
    /// Positions decrypted through reconstructed recovered candidates.
    pub planted_decryption_positions: usize,
    /// Recovered plaintext positions encrypted for the final round trip.
    pub planted_reencryption_positions: usize,
}

impl CalibrationOperations {
    /// Return the sum of all declared calibration operation units.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.signature_equation_evaluations
            + self.planted_encryption_positions
            + self.planted_decryption_positions
            + self.planted_reencryption_positions
    }
}

/// Result of one planted full-message recovery case.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FullMessageChecks {
    /// Whether decoded-model decryption recovers all plaintext.
    pub plaintext_recovery_matches: bool,
    /// Whether the recovered plaintext reencrypts to the planted ciphertext.
    pub recovered_plaintext_reencrypts: bool,
    /// Whether both full-message checks pass.
    pub passed: bool,
}

/// Result of one planted full-message recovery case.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationCase {
    /// Case number, equal to ordered-pair number.
    pub case_index: usize,
    /// True candidate in the complete canonical domain.
    pub true_candidate_index: usize,
    /// Candidate indices recovered from ciphertext and 24 known letters only.
    pub recovered_candidate_indices: Vec<usize>,
    /// Whether the true physical candidate is retained.
    pub true_candidate_retained: bool,
    /// Full-message inverse and forward checks through the decoded recovered ID.
    pub full_message: FullMessageChecks,
    /// Whether the crib signature identifies one physical candidate.
    pub unique_recovery: bool,
    /// Planted ciphertext retained for independent regeneration.
    pub ciphertext: String,
}

/// Complete deterministic calibration report used as the K4 gate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CalibrationReport {
    /// Output schema version.
    pub schema_version: u32,
    /// Evidence manifest used for crib positions and letters.
    pub evidence_id: String,
    /// Registered candidate count.
    pub candidate_count: usize,
    /// Complete signature census.
    pub signature_census: SignatureCensus,
    /// Exact primary-operation counts for this calibration.
    pub operation_counts: CalibrationOperations,
    /// All planted cases.
    pub cases: Vec<CalibrationCase>,
    /// Cases retaining their true physical candidate.
    pub retained_cases: usize,
    /// Cases recovering the exact 97-letter planted plaintext.
    pub plaintext_recovery_cases: usize,
    /// Cases whose recovered plaintext reencrypts exactly.
    pub reencryption_cases: usize,
    /// Cases passing both full-message checks.
    pub full_message_recovery_cases: usize,
    /// Cases with a singleton physical recovery set.
    pub unique_recovery_cases: usize,
    /// True only when every mandatory calibration gate passes.
    pub passed: bool,
}

/// A complete trace for a K4-compatible candidate.
#[derive(Debug, Serialize)]
pub struct Survivor {
    /// Canonical index into the complete physical domain.
    pub candidate_index: usize,
    /// Decoded index fields.
    pub coordinates: CandidateCoordinates,
    /// Five-digit primer.
    pub primer: String,
    /// Plaintext base-order identifier.
    pub plaintext_base: String,
    /// Ciphertext base-order identifier.
    pub ciphertext_base: String,
    /// Expanded 97-digit recurrence key.
    pub expanded_key: String,
    /// Complete plaintext alphabet order.
    pub plaintext_alphabet: String,
    /// Complete rotated ciphertext alphabet order.
    pub ciphertext_alphabet: String,
    /// All 24 checked equations.
    pub equations: Vec<Equation>,
}

/// Compact complete K4 evaluation.
#[derive(Debug, Serialize)]
pub struct K4Report {
    /// Output schema version.
    pub schema_version: u32,
    /// Evidence identifier.
    pub evidence_id: String,
    /// Number of physical candidates evaluated.
    pub candidate_count: usize,
    /// Total crib equations evaluated.
    pub equation_evaluations: usize,
    /// Exact index formula for decoding parallel arrays.
    pub candidate_index_encoding: String,
    /// Matching crib count at every canonical candidate index.
    pub match_counts: Vec<u8>,
    /// First mismatching crib ordinal, or null for a survivor.
    pub first_mismatch_crib_indices: Vec<Option<u8>>,
    /// Histogram of match counts.
    pub match_histogram: BTreeMap<u8, usize>,
    /// Complete traces for compatible candidates.
    pub survivors: Vec<Survivor>,
}

impl Request {
    fn validate(&self) -> Result<(), CipherError> {
        let expected_keywords = [
            ("kryptos", "KRYPTOS", "S210", "tableau_keyword"),
            (
                "palimpsest",
                "PALIMPSEST",
                "S203",
                "k1_indicator_repurposed",
            ),
            ("abscissa", "ABSCISSA", "S203", "k2_indicator_repurposed"),
        ];
        if self.schema_version != 1
            || self
                .primers
                .iter()
                .map(String::as_str)
                .ne(REGISTERED_PRIMERS)
            || self.keywords.len() != expected_keywords.len()
            || self
                .keywords
                .iter()
                .zip(expected_keywords)
                .any(|(actual, expected)| {
                    (
                        actual.id.as_str(),
                        actual.keyword.as_str(),
                        actual.source_id.as_str(),
                        actual.role.as_str(),
                    ) != expected
                })
            || self.constructors != ["keyword_fill", "aca_gromark_transposed"]
            || self.orientations != ["forward", "reversed"]
            || self.ciphertext_rotations != (0_u8..26).collect::<Vec<_>>()
            || self.key_offset != 0
            || self.calibration.seed == 0
            || self.calibration.case_count != BASE_COUNT * BASE_COUNT
            || self.calibration.message_length != MESSAGE_LENGTH
            || self.calibration.rng != "xorshift32(13,17,5); modulo-26 letter selection"
            || self.calibration.assignment
                != "case=ordered_pair_index; primer=case%39; rotation=case%26"
        {
            return Err(parameter(
                "keyword alphabet request",
                "request differs from the exact registered keyword, construction, rotation or calibration domain",
            ));
        }
        Ok(())
    }

    /// Derive and validate all 12 physical base orders.
    ///
    /// # Errors
    ///
    /// Rejects an invalid request, construction failure, duplicate order, or
    /// two distinct base orders equivalent under rotation.
    pub fn base_orders(&self) -> Result<Vec<BaseOrder>, CipherError> {
        self.validate()?;
        let mut result = Vec::with_capacity(BASE_COUNT);
        let mut orders = HashSet::new();
        let mut rotation_classes = HashSet::new();
        for keyword in &self.keywords {
            for constructor in &self.constructors {
                let forward = if constructor == "keyword_fill" {
                    Alphabet::keyed(&keyword.keyword)?
                } else {
                    aca_transposed_alphabet(&keyword.keyword)?
                };
                for orientation in &self.orientations {
                    let alphabet = if orientation == "forward" {
                        forward.clone()
                    } else {
                        forward.reversed()
                    };
                    let order = alphabet.order();
                    if !orders.insert(order.clone())
                        || !rotation_classes.insert(minimum_rotation(&order))
                    {
                        return Err(parameter(
                            "keyword alphabet orders",
                            "base orders must be unique, including up to rotation",
                        ));
                    }
                    result.push(BaseOrder {
                        id: format!("{}:{constructor}:{orientation}", keyword.id),
                        alphabet,
                    });
                }
            }
        }
        if result.len() != BASE_COUNT {
            return Err(parameter(
                "keyword alphabet orders",
                "expected exactly 12 base orders",
            ));
        }
        Ok(result)
    }
}

fn minimum_rotation(order: &str) -> String {
    (0..26)
        .map(|amount| format!("{}{}", &order[amount..], &order[..amount]))
        .min()
        .unwrap_or_default()
}

/// Encode canonical candidate coordinates.
///
/// # Errors
///
/// Rejects any coordinate outside the registered dimensions.
pub fn encode_candidate(coordinates: &CandidateCoordinates) -> Result<usize, CipherError> {
    if coordinates.primer_index >= PRIMER_COUNT
        || coordinates.plaintext_base_index >= BASE_COUNT
        || coordinates.ciphertext_base_index >= BASE_COUNT
        || coordinates.ciphertext_rotation >= 26
    {
        return Err(parameter(
            "candidate coordinates",
            "coordinate outside registered domain",
        ));
    }
    Ok(
        (((coordinates.primer_index * BASE_COUNT + coordinates.plaintext_base_index) * BASE_COUNT
            + coordinates.ciphertext_base_index)
            * 26)
            + usize::from(coordinates.ciphertext_rotation),
    )
}

/// Decode a canonical candidate index.
///
/// # Errors
///
/// Rejects indices at or above [`CANDIDATE_COUNT`].
pub fn decode_candidate(mut index: usize) -> Result<CandidateCoordinates, CipherError> {
    if index >= CANDIDATE_COUNT {
        return Err(parameter("candidate index", "must be below 146016"));
    }
    let ciphertext_rotation = u8::try_from(index % 26)
        .map_err(|_| parameter("candidate index", "rotation conversion failed"))?;
    index /= 26;
    let ciphertext_base_index = index % BASE_COUNT;
    index /= BASE_COUNT;
    let plaintext_base_index = index % BASE_COUNT;
    let primer_index = index / BASE_COUNT;
    Ok(CandidateCoordinates {
        primer_index,
        plaintext_base_index,
        ciphertext_base_index,
        ciphertext_rotation,
    })
}

fn expanded_key(primer: &str) -> Result<Vec<u8>, CipherError> {
    Recurrence::new(10, primer.bytes().map(|byte| byte - b'0').collect())?.generate(MESSAGE_LENGTH)
}

fn signature(
    evidence: &Evidence,
    key: &[u8],
    plaintext: &Alphabet,
    ciphertext: &Alphabet,
) -> Result<[u8; CRIB_COUNT], CipherError> {
    let mut result = [0; CRIB_COUNT];
    for (slot, (position, letter)) in evidence.known_letters().enumerate() {
        let plain_index = plaintext.index(letter)?;
        result[slot] = ciphertext.letter((plain_index + key[position]) % 26)?;
    }
    Ok(result)
}

fn signature_index(
    evidence: &Evidence,
    request: &Request,
    bases: &[BaseOrder],
) -> Result<HashMap<[u8; CRIB_COUNT], Vec<usize>>, CipherError> {
    let keys: Vec<_> = request
        .primers
        .iter()
        .map(|primer| expanded_key(primer))
        .collect::<Result<_, _>>()?;
    let mut index = HashMap::new();
    for candidate_index in 0..CANDIDATE_COUNT {
        let coordinates = decode_candidate(candidate_index)?;
        let cipher = bases[coordinates.ciphertext_base_index]
            .alphabet
            .rotated(usize::from(coordinates.ciphertext_rotation));
        let key = &keys[coordinates.primer_index];
        let value = signature(
            evidence,
            key,
            &bases[coordinates.plaintext_base_index].alphabet,
            &cipher,
        )?;
        index
            .entry(value)
            .or_insert_with(Vec::new)
            .push(candidate_index);
    }
    Ok(index)
}

fn census(index: &HashMap<[u8; CRIB_COUNT], Vec<usize>>) -> SignatureCensus {
    SignatureCensus {
        physical_candidates: index.values().map(Vec::len).sum(),
        distinct_signatures: index.len(),
        singleton_buckets: index.values().filter(|bucket| bucket.len() == 1).count(),
        doubleton_buckets: index.values().filter(|bucket| bucket.len() == 2).count(),
        unique_physical_candidates: index
            .values()
            .filter(|bucket| bucket.len() == 1)
            .map(Vec::len)
            .sum(),
        maximum_bucket_size: index.values().map(Vec::len).max().unwrap_or(0),
    }
}

#[derive(Debug)]
struct XorShift32(u32);

impl XorShift32 {
    fn next(&mut self) -> u32 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        self.0 = value;
        value
    }

    fn text(&mut self, length: usize) -> String {
        (0..length)
            .map(|_| char::from(b'A' + u8::try_from(self.next() % 26).unwrap_or(0)))
            .collect()
    }
}

fn encrypt(
    plaintext: &str,
    key: &[u8],
    plain_alphabet: &Alphabet,
    cipher_alphabet: &Alphabet,
) -> Result<String, CipherError> {
    if plaintext.len() != key.len() {
        return Err(parameter(
            "keyword encryption",
            "text and key lengths must match",
        ));
    }
    plaintext
        .bytes()
        .enumerate()
        .map(|(position, letter)| {
            let plain = plain_alphabet.index(letter)?;
            cipher_alphabet
                .letter((plain + key[position]) % 26)
                .map(char::from)
        })
        .collect()
}

fn decrypt(
    ciphertext: &str,
    key: &[u8],
    plain_alphabet: &Alphabet,
    cipher_alphabet: &Alphabet,
) -> Result<String, CipherError> {
    if ciphertext.len() != key.len() {
        return Err(parameter(
            "keyword decryption",
            "text and key lengths must match",
        ));
    }
    ciphertext
        .bytes()
        .enumerate()
        .map(|(position, letter)| {
            let cipher = cipher_alphabet.index(letter)?;
            plain_alphabet
                .letter((cipher + 26 - (key[position] % 26)) % 26)
                .map(char::from)
        })
        .collect()
}

fn recover_full_message(
    candidate_index: usize,
    ciphertext: &str,
    expected_plaintext: &str,
    request: &Request,
    bases: &[BaseOrder],
) -> Result<(bool, bool), CipherError> {
    let coordinates = decode_candidate(candidate_index)?;
    let key = expanded_key(&request.primers[coordinates.primer_index])?;
    let plaintext_alphabet = &bases[coordinates.plaintext_base_index].alphabet;
    let ciphertext_alphabet = bases[coordinates.ciphertext_base_index]
        .alphabet
        .rotated(usize::from(coordinates.ciphertext_rotation));
    let recovered = decrypt(ciphertext, &key, plaintext_alphabet, &ciphertext_alphabet)?;
    let plaintext_matches = recovered == expected_plaintext;
    let reencrypted = encrypt(&recovered, &key, plaintext_alphabet, &ciphertext_alphabet)?;
    Ok((plaintext_matches, reencrypted == ciphertext))
}

/// Generate the exhaustive signature census and 144 planted calibration cases.
///
/// # Errors
///
/// Rejects an invalid request or any failed alphabet, key, or encryption step.
pub fn calibrate(evidence: &Evidence, request: &Request) -> Result<CalibrationReport, CipherError> {
    let bases = request.base_orders()?;
    let signatures = signature_index(evidence, request, &bases)?;
    let signature_census = census(&signatures);
    let mut rng = XorShift32(request.calibration.seed);
    let mut cases = Vec::with_capacity(request.calibration.case_count);
    for case_index in 0..request.calibration.case_count {
        let coordinates = CandidateCoordinates {
            primer_index: case_index % PRIMER_COUNT,
            plaintext_base_index: case_index / BASE_COUNT,
            ciphertext_base_index: case_index % BASE_COUNT,
            ciphertext_rotation: u8::try_from(case_index % 26)
                .map_err(|_| parameter("calibration", "rotation conversion failed"))?,
        };
        let true_candidate_index = encode_candidate(&coordinates)?;
        let key = expanded_key(&request.primers[coordinates.primer_index])?;
        let mut plaintext = rng.text(request.calibration.message_length).into_bytes();
        for (position, letter) in evidence.known_letters() {
            plaintext[position] = letter;
        }
        let plaintext = String::from_utf8(plaintext)
            .map_err(|_| parameter("calibration plaintext", "must remain ASCII"))?;
        let plain_alphabet = &bases[coordinates.plaintext_base_index].alphabet;
        let cipher_alphabet = bases[coordinates.ciphertext_base_index]
            .alphabet
            .rotated(usize::from(coordinates.ciphertext_rotation));
        let ciphertext = encrypt(&plaintext, &key, plain_alphabet, &cipher_alphabet)?;
        let crib_signature: [u8; CRIB_COUNT] = evidence
            .known_letters()
            .map(|(position, _)| ciphertext.as_bytes()[position])
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| parameter("calibration", "expected 24 crib letters"))?;
        let recovered = signatures.get(&crib_signature).cloned().unwrap_or_default();
        let (plaintext_recovery_matches, recovered_plaintext_reencrypts) = recovered
            .iter()
            .find(|&&candidate| candidate == true_candidate_index)
            .map_or(Ok((false, false)), |&candidate| {
                recover_full_message(candidate, &ciphertext, &plaintext, request, &bases)
            })?;
        let full_message_recovery_matches =
            plaintext_recovery_matches && recovered_plaintext_reencrypts;
        cases.push(CalibrationCase {
            case_index,
            true_candidate_index,
            true_candidate_retained: recovered.contains(&true_candidate_index),
            full_message: FullMessageChecks {
                plaintext_recovery_matches,
                recovered_plaintext_reencrypts,
                passed: full_message_recovery_matches,
            },
            unique_recovery: recovered.len() == 1,
            recovered_candidate_indices: recovered,
            ciphertext,
        });
    }
    let retained_cases = cases
        .iter()
        .filter(|case| case.true_candidate_retained)
        .count();
    let plaintext_recovery_cases = cases
        .iter()
        .filter(|case| case.full_message.plaintext_recovery_matches)
        .count();
    let reencryption_cases = cases
        .iter()
        .filter(|case| case.full_message.recovered_plaintext_reencrypts)
        .count();
    let full_message_recovery_cases = cases.iter().filter(|case| case.full_message.passed).count();
    let unique_recovery_cases = cases.iter().filter(|case| case.unique_recovery).count();
    let planted_positions = request.calibration.case_count * request.calibration.message_length;
    Ok(CalibrationReport {
        schema_version: 2,
        evidence_id: evidence.id().to_owned(),
        candidate_count: CANDIDATE_COUNT,
        signature_census,
        operation_counts: CalibrationOperations {
            signature_equation_evaluations: CANDIDATE_COUNT * CRIB_COUNT,
            planted_encryption_positions: planted_positions,
            planted_decryption_positions: planted_positions,
            planted_reencryption_positions: planted_positions,
        },
        passed: retained_cases == request.calibration.case_count
            && plaintext_recovery_cases == request.calibration.case_count
            && reencryption_cases == request.calibration.case_count
            && full_message_recovery_cases == request.calibration.case_count,
        cases,
        retained_cases,
        plaintext_recovery_cases,
        reencryption_cases,
        full_message_recovery_cases,
        unique_recovery_cases,
    })
}

/// Evaluate K4 only after reproducing the supplied calibration report exactly.
///
/// # Errors
///
/// Rejects any calibration disagreement or incomplete gate, invalid request,
/// or failed candidate evaluation.
pub fn evaluate_k4(
    evidence: &Evidence,
    request: &Request,
    supplied_calibration: &CalibrationReport,
) -> Result<K4Report, CipherError> {
    let expected_calibration = calibrate(evidence, request)?;
    if !supplied_calibration.passed || supplied_calibration != &expected_calibration {
        return Err(parameter(
            "keyword calibration",
            "supplied calibration must exactly match a complete passing regeneration",
        ));
    }
    let bases = request.base_orders()?;
    let cribs: Vec<_> = evidence.known_letters().collect();
    let keys: Vec<_> = request
        .primers
        .iter()
        .map(|primer| expanded_key(primer))
        .collect::<Result<_, _>>()?;
    let mut match_counts = Vec::with_capacity(CANDIDATE_COUNT);
    let mut first_mismatch_crib_indices = Vec::with_capacity(CANDIDATE_COUNT);
    let mut match_histogram = BTreeMap::new();
    let mut survivors = Vec::new();
    for candidate_index in 0..CANDIDATE_COUNT {
        let coordinates = decode_candidate(candidate_index)?;
        let key = &keys[coordinates.primer_index];
        let plain = &bases[coordinates.plaintext_base_index];
        let cipher_base = &bases[coordinates.ciphertext_base_index];
        let cipher = cipher_base
            .alphabet
            .rotated(usize::from(coordinates.ciphertext_rotation));
        let result = evaluate(&plain.alphabet, &cipher, evidence.ciphertext(), &cribs, key)?;
        let match_count = u8::try_from(result.match_count)
            .map_err(|_| parameter("match count", "does not fit u8"))?;
        let mismatch = result
            .equations
            .iter()
            .position(|equation| !equation.matches())
            .map(u8::try_from)
            .transpose()
            .map_err(|_| parameter("mismatch index", "does not fit u8"))?;
        match_counts.push(match_count);
        first_mismatch_crib_indices.push(mismatch);
        *match_histogram.entry(match_count).or_insert(0) += 1;
        if mismatch.is_none() {
            survivors.push(Survivor {
                candidate_index,
                coordinates: coordinates.clone(),
                primer: request.primers[coordinates.primer_index].clone(),
                plaintext_base: plain.id.clone(),
                ciphertext_base: cipher_base.id.clone(),
                expanded_key: key.iter().map(|&digit| char::from(b'0' + digit)).collect(),
                plaintext_alphabet: plain.alphabet.order(),
                ciphertext_alphabet: cipher.order(),
                equations: result.equations,
            });
        }
    }
    Ok(K4Report {
        schema_version: 2,
        evidence_id: evidence.id().to_owned(),
        candidate_count: CANDIDATE_COUNT,
        equation_evaluations: CANDIDATE_COUNT * CRIB_COUNT,
        candidate_index_encoding: "((((primer_index*12)+plaintext_base_index)*12+ciphertext_base_index)*26)+ciphertext_rotation".to_owned(),
        match_counts,
        first_mismatch_crib_indices,
        match_histogram,
        survivors,
    })
}

#[cfg(test)]
mod tests;
