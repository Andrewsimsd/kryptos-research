//! Necessary constraints for aligned additive ciphers with two unknown alphabets.
//!
//! The model is `c(ciphertext[i]) - p(plaintext[i]) = key[i] (mod 26)`.
//! [`PrimerConstraints`] eliminates unknown alphabet coordinates within graph
//! components. Passing these checks does not establish that component offsets
//! can be chosen to complete two permutations, or recover any unknown plaintext.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;

use crate::{
    cipher::{
        CipherError,
        constraints::{Crib, validated},
        gromark::Recurrence,
        parameter, validate_text,
    },
    evidence::Evidence,
};

type Expression = BTreeMap<usize, i32>;

/// One signed term in a relation derived from known plaintext equations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct KeyTerm {
    /// Zero-based key/crib position.
    pub position: usize,
    /// Integer multiplier, applied before reduction modulo 26.
    pub coefficient: i32,
}

/// A necessary congruence, with its derivation encoded as signed crib equations.
///
/// Summing the same coefficients times `c(C_i) - p(P_i)` yields either zero
/// (equality) or a difference of distinct letters in one alphabet (inequality).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct KeyRelation {
    /// Whether the signed sum must equal zero modulo 26; otherwise it must not.
    pub equal_zero: bool,
    /// Nonzero coefficients in increasing position order, normalized up to sign.
    pub terms: Vec<KeyTerm>,
}

impl KeyRelation {
    fn holds(&self, key: &[u8]) -> bool {
        let sum: i32 = self
            .terms
            .iter()
            .map(|term| term.coefficient * i32::from(key[term.position]))
            .sum();
        (sum.rem_euclid(26) == 0) == self.equal_zero
    }
}

#[derive(Debug, Clone, Copy)]
struct Edge {
    position: usize,
    plain: usize,
    cipher: usize,
}

/// Deterministically derived constraints for a fixed ciphertext and crib set.
///
/// # Examples
/// ```
/// use kryptos_research::{cipher::constraints::Crib, primers::PrimerConstraints};
/// let cribs = [Crib { position: 0, letter: 'A' }, Crib { position: 1, letter: 'A' }];
/// let constraints = PrimerConstraints::new("BC", &cribs)?;
/// assert_eq!(constraints.first_violation(&[1, 2])?, None);
/// assert!(constraints.first_violation(&[1, 1])?.is_some());
/// # Ok::<(), kryptos_research::cipher::CipherError>(())
/// ```
#[derive(Debug, Serialize)]
pub struct PrimerConstraints {
    length: usize,
    simple_count: usize,
    relations: Vec<KeyRelation>,
}

impl PrimerConstraints {
    /// Derive two-edge conditions, cycle equations and within-component
    /// alphabet inequalities. Duplicate identical cribs are coalesced.
    ///
    /// # Errors
    /// Rejects non-A–Z text, invalid positions, or conflicting crib letters.
    pub fn new(ciphertext: &str, cribs: &[Crib]) -> Result<Self, CipherError> {
        validate_text(ciphertext)?;
        let edges: Vec<_> = validated(cribs, ciphertext.len())?
            .into_iter()
            .map(|(position, letter)| Edge {
                position,
                plain: (letter as usize) - usize::from(b'A'),
                cipher: usize::from(ciphertext.as_bytes()[position] - b'A') + 26,
            })
            .collect();
        let simple = simple_relations(&edges);
        let simple_count = simple.len();
        let mut relations: Vec<_> = simple.iter().cloned().collect();
        relations.extend(graph_relations(&edges).difference(&simple).cloned());
        Ok(Self {
            length: ciphertext.len(),
            simple_count,
            relations,
        })
    }

    /// Return the first violated relation, or `None` if all necessary checks pass.
    ///
    /// A longer key is permitted (unused suffix digits are validated too).
    /// # Errors
    /// Rejects keys shorter than the ciphertext or digits outside 0–25.
    pub fn first_violation(&self, key: &[u8]) -> Result<Option<usize>, CipherError> {
        if key.len() < self.length || key.iter().any(|&digit| digit >= 26) {
            return Err(parameter(
                "numeric key",
                "requires enough digits, all in 0..26",
            ));
        }
        Ok(self
            .relations
            .iter()
            .position(|relation| !relation.holds(key)))
    }

    /// Relations in evaluation order; indices are rejection certificate IDs.
    #[must_use]
    pub fn relations(&self) -> &[KeyRelation] {
        &self.relations
    }
}

fn expression_difference(left: &Expression, right: &Expression) -> Expression {
    let mut result = left.clone();
    for (&position, &coefficient) in right {
        *result.entry(position).or_default() -= coefficient;
    }
    result.retain(|_, coefficient| *coefficient != 0);
    result
}

fn insert_relation(set: &mut BTreeSet<KeyRelation>, equal_zero: bool, expression: &Expression) {
    let Some(&first) = expression.values().find(|&&coefficient| coefficient != 0) else {
        return;
    };
    let sign = first.signum();
    set.insert(KeyRelation {
        equal_zero,
        terms: expression
            .iter()
            .filter(|(_, coefficient)| **coefficient != 0)
            .map(|(&position, &coefficient)| KeyTerm {
                position,
                coefficient: coefficient * sign,
            })
            .collect(),
    });
}

fn simple_relations(edges: &[Edge]) -> BTreeSet<KeyRelation> {
    let mut relations = BTreeSet::new();
    for (index, left) in edges.iter().enumerate() {
        for right in &edges[index + 1..] {
            if left.plain == right.plain || left.cipher == right.cipher {
                insert_relation(
                    &mut relations,
                    left.plain == right.plain && left.cipher == right.cipher,
                    &BTreeMap::from([(left.position, 1), (right.position, -1)]),
                );
            }
        }
    }
    relations
}

fn forest(edges: &[Edge]) -> (Vec<Option<Expression>>, [usize; 52]) {
    let mut potentials = vec![None; 52];
    let mut components = [usize::MAX; 52];
    for root in 0..52 {
        if potentials[root].is_some() || !edges.iter().any(|e| e.plain == root || e.cipher == root)
        {
            continue;
        }
        potentials[root] = Some(Expression::new());
        components[root] = root;
        let mut queue = VecDeque::from([root]);
        while let Some(node) = queue.pop_front() {
            for edge in edges {
                let (next, sign) = if edge.plain == node {
                    (edge.cipher, 1)
                } else if edge.cipher == node {
                    (edge.plain, -1)
                } else {
                    continue;
                };
                if potentials[next].is_some() {
                    continue;
                }
                if let Some(mut expression) = potentials[node].clone() {
                    *expression.entry(edge.position).or_default() += sign;
                    potentials[next] = Some(expression);
                    components[next] = root;
                    queue.push_back(next);
                }
            }
        }
    }
    (potentials, components)
}

fn graph_relations(edges: &[Edge]) -> BTreeSet<KeyRelation> {
    let (potentials, components) = forest(edges);
    let mut relations = BTreeSet::new();
    for edge in edges {
        if let (Some(plain), Some(cipher)) = (&potentials[edge.plain], &potentials[edge.cipher]) {
            let mut expression = expression_difference(cipher, plain);
            *expression.entry(edge.position).or_default() -= 1;
            insert_relation(&mut relations, true, &expression);
        }
    }
    for left in 0..52 {
        for right in left + 1..52 {
            if left / 26 == right / 26 && components[left] == components[right] {
                if let (Some(a), Some(b)) = (&potentials[left], &potentials[right]) {
                    insert_relation(&mut relations, false, &expression_difference(a, b));
                }
            }
        }
    }
    relations
}

/// A primer that passes necessary conditions; no alphabet pair is supplied.
#[derive(Debug, Serialize)]
pub struct PrimerSurvivor {
    /// Exactly five decimal digits, including leading zeros.
    pub primer: String,
    /// First 98 digits for exact comparison with the pinned upstream program.
    pub expanded_key: String,
    /// Number of distinct digits among the 97 message positions.
    pub distinct_digits: usize,
}

/// Exhaustive coverage and checkable rejection certificates for the fixed domain.
#[derive(Debug, Serialize)]
pub struct PrimerReport {
    /// Output schema version.
    pub schema_version: u32,
    /// Validated evidence identifier.
    pub evidence_id: String,
    /// Number of enumerated primers (99,999, excluding 00000).
    pub examined: usize,
    /// Primers that pass only the simple two-edge checks.
    pub simple_survivors: usize,
    /// Complete symbolic relation catalog, with simple checks first.
    pub constraints: PrimerConstraints,
    /// Index matches the relation index; each list contains its first failures.
    pub rejected_by_relation: Vec<Vec<u32>>,
    /// Surviving primers in increasing numeric order.
    pub survivors: Vec<PrimerSurvivor>,
}

/// Exhaust the nonzero five-digit base-10 domain using aligned frozen K4 cribs.
///
/// No search over alphabets or plaintext is performed. All rejected primers are
/// partitioned by their first contradictory relation, retaining an exact witness.
/// # Errors
/// Returns [`CipherError`] if constraint construction or key allocation fails.
pub fn filter_decimal_primers(evidence: &Evidence) -> Result<PrimerReport, CipherError> {
    let cribs: Vec<_> = evidence
        .known_letters()
        .map(|(position, letter)| Crib {
            position,
            letter: char::from(letter),
        })
        .collect();
    let constraints = PrimerConstraints::new(evidence.ciphertext(), &cribs)?;
    let mut report = PrimerReport {
        schema_version: 1,
        evidence_id: evidence.id().to_owned(),
        examined: 0,
        simple_survivors: 0,
        rejected_by_relation: vec![Vec::new(); constraints.relations.len()],
        constraints,
        survivors: Vec::new(),
    };
    for number in 1..100_000 {
        let primer = format!("{number:05}");
        let digits = primer.bytes().map(|digit| digit - b'0').collect();
        let key = Recurrence::new(10, digits)?.generate(98)?;
        report.examined += 1;
        let violation = report.constraints.first_violation(&key)?;
        if violation.is_none_or(|index| index >= report.constraints.simple_count) {
            report.simple_survivors += 1;
        }
        if let Some(index) = violation {
            report.rejected_by_relation[index].push(number);
        } else {
            report.survivors.push(PrimerSurvivor {
                primer,
                expanded_key: key.iter().map(|&digit| char::from(b'0' + digit)).collect(),
                distinct_digits: key[..97].iter().collect::<BTreeSet<_>>().len(),
            });
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests;
