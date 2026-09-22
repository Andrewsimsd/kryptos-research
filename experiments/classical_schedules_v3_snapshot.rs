//! Exact symbolic census of bounded classical polyalphabetic key schedules.
//!
//! The census uses the standard `A=0, ..., Z=25` alphabet and identity route.
//! Free seed residues are represented symbolically; the implementation never
//! enumerates the exponentially large set of concrete keys.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::cipher::{CipherError, parameter, validate_text};

const MODULUS: u8 = 26;
const MAX_PERIOD: usize = 32;
const RESET_BOUNDARIES: [usize; 3] = [4, 35, 66];

/// One known plaintext letter at a zero-based ciphertext position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Crib {
    /// Zero-based aligned position.
    pub position: usize,
    /// Known uppercase ASCII plaintext letter.
    pub plaintext: char,
}

/// One independent exact-search case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    /// Stable caller-supplied identifier.
    pub id: String,
    /// Uppercase ASCII ciphertext.
    pub ciphertext: String,
    /// Known aligned plaintext letters.
    pub cribs: Vec<Crib>,
}

/// Strict request for the complete registered census.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Must be one.
    pub schema_version: u8,
    /// Cases in desired output order.
    pub cases: Vec<Case>,
    /// Maximum template checks across all cases.
    pub operation_cap: u64,
}

/// Arithmetic convention retained for autokey templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Equation {
    /// `C = P + K`.
    Vigenere,
    /// `C = K - P`.
    Beaufort,
    /// `C = P - K`.
    VariantBeaufort,
}

/// Feedback source for an autokey schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feedback {
    /// Append recovered plaintext.
    Plaintext,
    /// Append ciphertext.
    Ciphertext,
}

/// A canonical template that is compatible with every supplied crib.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Survivor {
    /// Stable canonical identifier.
    pub template_id: String,
    /// `repeating_interrupted`, `progressive`, or `autokey`.
    pub family: &'static str,
    /// Canonical equation label.
    pub equation: String,
    /// Seed period or seed length.
    pub period: usize,
    /// Nonzero increment for progressive schedules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub increment: Option<u8>,
    /// Reset positions for interrupted schedules.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resets: Vec<usize>,
    /// Autokey feedback source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feedback: Option<Feedback>,
    /// Seed residues, with unconstrained components represented by `null`.
    pub fixed_seed: Vec<Option<u8>>,
    /// Number of unconstrained seed coordinates.
    pub free_seed_components: usize,
    /// Exact concrete-stream multiplicity, represented as a decimal string.
    pub concrete_stream_multiplicity: String,
    /// Deterministic zero-filled seed witness.
    pub witness_seed: String,
    /// Complete plaintext under the witness.
    pub witness_plaintext: String,
    /// Complete key stream under the witness.
    pub witness_key: String,
}

/// Exact result for one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaseResult {
    /// Caller-supplied identifier.
    pub id: String,
    /// Number of canonical templates checked.
    pub templates_checked: u64,
    /// Compatible templates in canonical identifier order.
    pub survivors: Vec<Survivor>,
}

/// Complete census report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Output schema version.
    pub schema_version: u8,
    /// Registered raw parameter tuples.
    pub raw_parameter_tuples: u64,
    /// Distinct repeating/interrupted coordinate maps on 97 positions.
    pub canonical_coordinate_maps: usize,
    /// Canonical symbolic templates per case.
    pub canonical_templates: usize,
    /// Per-family template counts.
    pub template_counts: BTreeMap<&'static str, usize>,
    /// Actual template checks.
    pub operations: u64,
    /// Results in request order.
    pub cases: Vec<CaseResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Template {
    Coordinate {
        map: Vec<usize>,
        period: usize,
        resets: Vec<usize>,
        beaufort: bool,
    },
    Progressive {
        period: usize,
        increment: u8,
        beaufort: bool,
    },
    Autokey {
        period: usize,
        equation: Equation,
        feedback: Feedback,
    },
}

impl Request {
    fn validate(&self) -> Result<(), CipherError> {
        if self.schema_version != 1 {
            return Err(parameter("schema_version", "must be one"));
        }
        if self.cases.is_empty() {
            return Err(parameter("cases", "must not be empty"));
        }
        if self.operation_cap == 0 {
            return Err(parameter("operation_cap", "must be positive"));
        }
        let mut ids = BTreeSet::new();
        for case in &self.cases {
            if case.id.is_empty() || !ids.insert(&case.id) {
                return Err(parameter("case id", "must be nonempty and unique"));
            }
            validate_text(&case.ciphertext)?;
            if case.ciphertext.is_empty() {
                return Err(parameter("ciphertext", "must not be empty"));
            }
            let mut positions = BTreeSet::new();
            for crib in &case.cribs {
                if crib.position >= case.ciphertext.len() || !positions.insert(crib.position) {
                    return Err(parameter("crib position", "must be in range and unique"));
                }
                if !crib.plaintext.is_ascii_uppercase() {
                    return Err(parameter(
                        "crib plaintext",
                        "must be one uppercase ASCII letter",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Enumerate the fixed canonical domain and solve every request case exactly.
///
/// # Errors
/// Rejects malformed requests and operation caps smaller than the complete
/// census. A cap never turns an unfinished case into a rejection.
pub fn evaluate(request: &Request) -> Result<Report, CipherError> {
    request.validate()?;
    let templates = templates(97);
    let required = u64::try_from(templates.len() * request.cases.len())
        .map_err(|_| parameter("operation_cap", "required count overflowed"))?;
    if required > request.operation_cap {
        return Err(parameter(
            "operation_cap",
            "too small for the complete canonical census",
        ));
    }
    let mut cases = Vec::with_capacity(request.cases.len());
    for case in &request.cases {
        let mut survivors: Vec<_> = templates.iter().filter_map(|t| solve(case, t)).collect();
        survivors.sort_by(|a, b| a.template_id.cmp(&b.template_id));
        cases.push(CaseResult {
            id: case.id.clone(),
            templates_checked: templates.len() as u64,
            survivors,
        });
    }
    Ok(Report {
        schema_version: 1,
        raw_parameter_tuples: 65_856,
        canonical_coordinate_maps: coordinate_maps(97).len(),
        canonical_templates: templates.len(),
        template_counts: BTreeMap::from([
            ("autokey", 192),
            ("progressive", 1_600),
            ("repeating_interrupted", 400),
        ]),
        operations: required,
        cases,
    })
}

fn templates(length: usize) -> Vec<Template> {
    let mut out = Vec::with_capacity(2_192);
    for (map, period, resets) in coordinate_maps(length) {
        for beaufort in [false, true] {
            out.push(Template::Coordinate {
                map: map.clone(),
                period,
                resets: resets.clone(),
                beaufort,
            });
        }
    }
    for period in 1..=MAX_PERIOD {
        for increment in 1..MODULUS {
            for beaufort in [false, true] {
                out.push(Template::Progressive {
                    period,
                    increment,
                    beaufort,
                });
            }
        }
    }
    for period in 1..=MAX_PERIOD {
        for feedback in [Feedback::Plaintext, Feedback::Ciphertext] {
            for equation in [
                Equation::Vigenere,
                Equation::Beaufort,
                Equation::VariantBeaufort,
            ] {
                out.push(Template::Autokey {
                    period,
                    equation,
                    feedback,
                });
            }
        }
    }
    out
}

fn coordinate_maps(length: usize) -> Vec<(Vec<usize>, usize, Vec<usize>)> {
    let subsets = [
        vec![],
        vec![RESET_BOUNDARIES[0]],
        vec![RESET_BOUNDARIES[1]],
        vec![RESET_BOUNDARIES[2]],
        vec![RESET_BOUNDARIES[0], RESET_BOUNDARIES[1]],
        vec![RESET_BOUNDARIES[0], RESET_BOUNDARIES[2]],
        vec![RESET_BOUNDARIES[1], RESET_BOUNDARIES[2]],
    ];
    let mut maps = BTreeMap::<Vec<usize>, (usize, Vec<usize>)>::new();
    for period in 1..=MAX_PERIOD {
        for resets in &subsets {
            let map = (0..length)
                .map(|position| {
                    let start = resets
                        .iter()
                        .copied()
                        .filter(|&r| r <= position)
                        .max()
                        .unwrap_or(0);
                    (position - start) % period
                })
                .collect::<Vec<_>>();
            maps.entry(map).or_insert_with(|| (period, resets.clone()));
        }
    }
    maps.into_iter()
        .map(|(map, (period, resets))| (map, period, resets))
        .collect()
}

fn solve(case: &Case, template: &Template) -> Option<Survivor> {
    match template {
        Template::Coordinate {
            map,
            period,
            resets,
            beaufort,
        } => {
            let required = case.cribs.iter().map(|crib| {
                let c = value(case.ciphertext.as_bytes()[crib.position]);
                let p = value(crib.plaintext as u8);
                (
                    map[crib.position],
                    if *beaufort { add(c, p) } else { sub(c, p) },
                )
            });
            finish_free(
                case,
                template,
                *period,
                required,
                resets.clone(),
                None,
                None,
                *beaufort,
            )
        }
        Template::Progressive {
            period,
            increment,
            beaufort,
        } => {
            let required = case.cribs.iter().map(|crib| {
                let c = value(case.ciphertext.as_bytes()[crib.position]);
                let p = value(crib.plaintext as u8);
                let key = if *beaufort { add(c, p) } else { sub(c, p) };
                let step = u8::try_from(crib.position / period).unwrap() % MODULUS;
                (crib.position % period, sub(key, mul(step, *increment)))
            });
            finish_free(
                case,
                template,
                *period,
                required,
                vec![],
                Some(*increment),
                None,
                *beaufort,
            )
        }
        Template::Autokey {
            period,
            equation,
            feedback,
        } => solve_autokey(case, *period, *equation, *feedback),
    }
}

fn finish_free(
    case: &Case,
    template: &Template,
    period: usize,
    required: impl Iterator<Item = (usize, u8)>,
    resets: Vec<usize>,
    increment: Option<u8>,
    feedback: Option<Feedback>,
    beaufort: bool,
) -> Option<Survivor> {
    let mut fixed = vec![None; period];
    for (coordinate, residue) in required {
        if fixed[coordinate].is_some_and(|old| old != residue) {
            return None;
        }
        fixed[coordinate] = Some(residue);
    }
    let seed: Vec<u8> = fixed.iter().map(|x| x.unwrap_or(0)).collect();
    let keys = key_stream(template, &seed, &case.ciphertext, None);
    let plaintext = decrypt(&case.ciphertext, &keys, beaufort, Equation::Vigenere);
    witness(
        case, template, fixed, seed, plaintext, keys, resets, increment, feedback,
    )
}

fn solve_autokey(
    case: &Case,
    period: usize,
    equation: Equation,
    feedback: Feedback,
) -> Option<Survivor> {
    // Each plaintext expression is `coefficient * seed[coordinate] + constant`.
    let mut expressions = Vec::<(i8, usize, u8)>::with_capacity(case.ciphertext.len());
    let mut fixed = vec![None; period];
    for (i, &cipher) in case.ciphertext.as_bytes().iter().enumerate() {
        let c = value(cipher);
        let expression = if i < period {
            match equation {
                Equation::Vigenere => (-1, i, c),
                Equation::VariantBeaufort => (1, i, c),
                Equation::Beaufort => (1, i, neg(c)),
            }
        } else if feedback == Feedback::Ciphertext {
            let key = value(case.ciphertext.as_bytes()[i - period]);
            (0, 0, decrypt_value(c, key, equation))
        } else {
            let (a, coordinate, b) = expressions[i - period];
            match equation {
                Equation::Vigenere => (-a, coordinate, sub(c, b)),
                Equation::VariantBeaufort => (a, coordinate, add(c, b)),
                Equation::Beaufort => (a, coordinate, sub(b, c)),
            }
        };
        expressions.push(expression);
    }
    for crib in &case.cribs {
        let p = value(crib.plaintext as u8);
        let (a, coordinate, b) = expressions[crib.position];
        if a == 0 {
            if b != p {
                return None;
            }
        } else {
            let residue = if a == 1 { sub(p, b) } else { sub(b, p) };
            if fixed[coordinate].is_some_and(|old| old != residue) {
                return None;
            }
            fixed[coordinate] = Some(residue);
        }
    }
    let seed: Vec<_> = fixed.iter().map(|x| x.unwrap_or(0)).collect();
    let keys = key_stream(
        &Template::Autokey {
            period,
            equation,
            feedback,
        },
        &seed,
        &case.ciphertext,
        Some(equation),
    );
    let plaintext = decrypt_autokey(&case.ciphertext, &seed, equation, feedback);
    witness(
        case,
        &Template::Autokey {
            period,
            equation,
            feedback,
        },
        fixed,
        seed,
        plaintext,
        keys,
        vec![],
        None,
        Some(feedback),
    )
}

fn witness(
    case: &Case,
    template: &Template,
    fixed: Vec<Option<u8>>,
    seed: Vec<u8>,
    plaintext: String,
    keys: Vec<u8>,
    resets: Vec<usize>,
    increment: Option<u8>,
    feedback: Option<Feedback>,
) -> Option<Survivor> {
    if case
        .cribs
        .iter()
        .any(|c| plaintext.as_bytes()[c.position] != c.plaintext as u8)
    {
        return None;
    }
    let free = fixed.iter().filter(|x| x.is_none()).count();
    let (family, equation, period) = match template {
        Template::Coordinate {
            period, beaufort, ..
        } => (
            "repeating_interrupted",
            canonical_equation(*beaufort).to_owned(),
            *period,
        ),
        Template::Progressive {
            period, beaufort, ..
        } => (
            "progressive",
            canonical_equation(*beaufort).to_owned(),
            *period,
        ),
        Template::Autokey {
            period, equation, ..
        } => (
            "autokey",
            format!("{equation:?}")
                .to_lowercase()
                .replace("variantbeaufort", "variant_beaufort"),
            *period,
        ),
    };
    let id = template_id(template);
    Some(Survivor {
        template_id: id,
        family,
        equation,
        period,
        increment,
        resets,
        feedback,
        fixed_seed: fixed,
        free_seed_components: free,
        concrete_stream_multiplicity: pow26(free),
        witness_seed: letters(&seed),
        witness_plaintext: plaintext,
        witness_key: letters(&keys),
    })
}

fn template_id(template: &Template) -> String {
    match template {
        Template::Coordinate {
            map,
            period,
            resets,
            beaufort,
        } => format!(
            "coord:{:02}:{}:{}:{}",
            period,
            resets
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join("-"),
            canonical_equation(*beaufort),
            map.iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Template::Progressive {
            period,
            increment,
            beaufort,
        } => format!(
            "progressive:{period:02}:{increment:02}:{}",
            canonical_equation(*beaufort)
        ),
        Template::Autokey {
            period,
            equation,
            feedback,
        } => format!(
            "autokey:{period:02}:{}:{}",
            match feedback {
                Feedback::Plaintext => "plaintext",
                Feedback::Ciphertext => "ciphertext",
            },
            match equation {
                Equation::Vigenere => "vigenere",
                Equation::Beaufort => "beaufort",
                Equation::VariantBeaufort => "variant_beaufort",
            }
        ),
    }
}

fn canonical_equation(beaufort: bool) -> &'static str {
    if beaufort {
        "beaufort"
    } else {
        "vigenere_or_variant"
    }
}

fn key_stream(
    template: &Template,
    seed: &[u8],
    ciphertext: &str,
    equation: Option<Equation>,
) -> Vec<u8> {
    match template {
        Template::Coordinate { map, .. } => {
            map[..ciphertext.len()].iter().map(|&j| seed[j]).collect()
        }
        Template::Progressive {
            period, increment, ..
        } => (0..ciphertext.len())
            .map(|i| add(seed[i % period], mul((i / period % 26) as u8, *increment)))
            .collect(),
        Template::Autokey { feedback, .. } => {
            let plaintext = decrypt_autokey(ciphertext, seed, equation.unwrap(), *feedback);
            (0..ciphertext.len())
                .map(|i| {
                    if i < seed.len() {
                        seed[i]
                    } else if *feedback == Feedback::Ciphertext {
                        value(ciphertext.as_bytes()[i - seed.len()])
                    } else {
                        value(plaintext.as_bytes()[i - seed.len()])
                    }
                })
                .collect()
        }
    }
}

fn decrypt_autokey(
    ciphertext: &str,
    seed: &[u8],
    equation: Equation,
    feedback: Feedback,
) -> String {
    let mut plain = Vec::with_capacity(ciphertext.len());
    for (i, &c) in ciphertext.as_bytes().iter().enumerate() {
        let key = if i < seed.len() {
            seed[i]
        } else if feedback == Feedback::Ciphertext {
            value(ciphertext.as_bytes()[i - seed.len()])
        } else {
            value(plain[i - seed.len()])
        };
        plain.push(b'A' + decrypt_value(value(c), key, equation));
    }
    String::from_utf8(plain).unwrap()
}

fn decrypt(ciphertext: &str, keys: &[u8], beaufort: bool, _: Equation) -> String {
    ciphertext
        .bytes()
        .zip(keys)
        .map(|(c, k)| {
            char::from(
                b'A' + if beaufort {
                    sub(*k, value(c))
                } else {
                    sub(value(c), *k)
                },
            )
        })
        .collect()
}
fn decrypt_value(c: u8, k: u8, equation: Equation) -> u8 {
    match equation {
        Equation::Vigenere => sub(c, k),
        Equation::VariantBeaufort => add(c, k),
        Equation::Beaufort => sub(k, c),
    }
}
fn value(letter: u8) -> u8 {
    letter - b'A'
}
fn add(a: u8, b: u8) -> u8 {
    (a + b) % 26
}
fn sub(a: u8, b: u8) -> u8 {
    (a + 26 - b) % 26
}
fn neg(a: u8) -> u8 {
    sub(0, a)
}
fn mul(a: u8, b: u8) -> u8 {
    ((u16::from(a) * u16::from(b)) % 26) as u8
}
fn letters(values: &[u8]) -> String {
    values.iter().map(|v| char::from(b'A' + v)).collect()
}
fn pow26(power: usize) -> String {
    (0..power).fold(String::from("1"), |n, _| decimal_mul(&n, 26))
}
fn decimal_mul(number: &str, factor: u32) -> String {
    let mut carry = 0;
    let mut out = Vec::new();
    for b in number.bytes().rev() {
        let x = u32::from(b - b'0') * factor + carry;
        out.push((x % 10) as u8 + b'0');
        carry = x / 10;
    }
    while carry > 0 {
        out.push((carry % 10) as u8 + b'0');
        carry /= 10;
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(ciphertext: &str, known: &[(usize, char)]) -> Case {
        Case {
            id: "x".into(),
            ciphertext: ciphertext.into(),
            cribs: known
                .iter()
                .map(|&(position, plaintext)| Crib {
                    position,
                    plaintext,
                })
                .collect(),
        }
    }

    #[test]
    fn registered_counts_and_coordinate_deduplication_are_exact() {
        assert_eq!(coordinate_maps(97).len(), 200);
        let all = templates(97);
        assert_eq!(all.len(), 2_192);
        assert_eq!(
            all.iter()
                .filter(|x| matches!(x, Template::Coordinate { .. }))
                .count(),
            400
        );
        assert_eq!(
            all.iter()
                .filter(|x| matches!(x, Template::Progressive { .. }))
                .count(),
            1_600
        );
        assert_eq!(
            all.iter()
                .filter(|x| matches!(x, Template::Autokey { .. }))
                .count(),
            192
        );
    }

    #[test]
    fn sign_phase_origin_and_zero_increment_equivalences_are_explicit() {
        assert_eq!(sub(2, 5), neg(sub(5, 2)));
        assert_eq!(
            (0..5).map(|i| (i + 2) % 5).collect::<BTreeSet<_>>(),
            (0..5).collect()
        );
        for q in 0..26 {
            assert_eq!(add(q, 7), add(add(q, 3), 4));
        }
        let repeat: Vec<_> = (0..97).map(|i| i % 7).collect();
        let progressive: Vec<_> = (0..97)
            .map(|i| add((i % 7) as u8, mul((i / 7) as u8, 0)))
            .collect();
        assert_eq!(
            repeat.into_iter().map(|x| x as u8).collect::<Vec<_>>(),
            progressive
        );
    }

    #[test]
    fn distinct_nonzero_progressions_and_autokey_equations_are_not_collapsed() {
        assert_ne!(
            (0..97)
                .map(|i| add((i % 3) as u8, (i / 3 % 26) as u8))
                .collect::<Vec<_>>(),
            (0..97)
                .map(|i| add((i % 3) as u8, mul((i / 3 % 26) as u8, 2)))
                .collect::<Vec<_>>()
        );
        let c = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let seed = [3];
        let outputs: BTreeSet<_> = [
            Equation::Vigenere,
            Equation::Beaufort,
            Equation::VariantBeaufort,
        ]
        .into_iter()
        .map(|e| decrypt_autokey(c, &seed, e, Feedback::Plaintext))
        .collect();
        assert_eq!(outputs.len(), 3);
    }

    #[test]
    fn underconstrained_survivors_have_zero_filled_exact_witnesses() {
        let request = Request {
            schema_version: 1,
            cases: vec![case("BBBB", &[(0, 'A')])],
            operation_cap: 2_192,
        };
        let report = evaluate(&request).unwrap();
        assert_eq!(report.operations, 2_192);
        for survivor in &report.cases[0].survivors {
            assert_eq!(survivor.witness_plaintext.as_bytes()[0], b'A');
            assert_eq!(
                survivor.concrete_stream_multiplicity,
                pow26(survivor.free_seed_components)
            );
        }
    }

    #[test]
    fn plaintext_autokey_propagates_across_unknown_gaps() {
        let plaintext = "ATTACKATDAWN";
        let seed = [11, 4, 12];
        let mut key = seed.to_vec();
        key.extend(plaintext.bytes().take(plaintext.len() - 3).map(value));
        let cipher: String = plaintext
            .bytes()
            .zip(&key)
            .map(|(p, k)| char::from(b'A' + add(value(p), *k)))
            .collect();
        let result = solve_autokey(
            &case(&cipher, &[(0, 'A'), (6, 'A'), (11, 'N')]),
            3,
            Equation::Vigenere,
            Feedback::Plaintext,
        )
        .unwrap();
        assert_eq!(result.fixed_seed[0], Some(11));
        assert_eq!(result.witness_plaintext.as_bytes()[11], b'N');
    }

    #[test]
    fn resets_change_coordinates_at_declared_boundaries() {
        let maps = coordinate_maps(97);
        let (_, _, resets) = maps
            .iter()
            .find(|(_, p, r)| *p == 5 && r == &vec![4, 35])
            .unwrap();
        assert_eq!(resets, &[4, 35]);
    }

    #[test]
    fn invalid_requests_and_cap_edges_are_rejected() {
        let valid = case("ABC", &[(0, 'A')]);
        for request in [
            Request {
                schema_version: 2,
                cases: vec![valid.clone()],
                operation_cap: 2192,
            },
            Request {
                schema_version: 1,
                cases: vec![],
                operation_cap: 2192,
            },
            Request {
                schema_version: 1,
                cases: vec![valid.clone()],
                operation_cap: 2191,
            },
            Request {
                schema_version: 1,
                cases: vec![case("ABC", &[(3, 'A')])],
                operation_cap: 2192,
            },
            Request {
                schema_version: 1,
                cases: vec![case("ABC", &[(0, 'A'), (0, 'B')])],
                operation_cap: 2192,
            },
        ] {
            assert!(evaluate(&request).is_err());
        }
        assert!(
            evaluate(&Request {
                schema_version: 1,
                cases: vec![valid],
                operation_cap: 2192
            })
            .is_ok()
        );
    }
}
