//! Exact alphabet feasibility for aligned additive equations with known key digits.
//!
//! [`solve`] places connected crib components on two independent 26-position
//! alphabets. Unconstrained letters fill unused positions deterministically.
//! A witness proves compatibility with the cribs, not recovery of an intended key.

pub mod batch;
mod search;

use crate::cipher::{
    CipherError,
    constraints::{Crib, validated},
    parameter, validate_text,
};
use serde::Serialize;
use std::collections::VecDeque;

/// A letter's index relative to its connected component's root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Coordinate {
    /// Uppercase ASCII letter.
    pub letter: char,
    /// Relative index modulo 26, before adding the component offset.
    pub index: u8,
}

/// Crib-connected coordinates; the lowest plaintext letter has relative index zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Component {
    /// Plaintext coordinates in alphabetic letter order.
    pub plaintext: Vec<Coordinate>,
    /// Ciphertext coordinates in alphabetic letter order.
    pub ciphertext: Vec<Coordinate>,
}

/// An exact decision or an explicitly incomplete bounded search.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Decision {
    /// Two complete permutations satisfy every supplied crib equation.
    Feasible {
        /// Letters in index order: the character at index i has coordinate i.
        plaintext_alphabet: String,
        /// Ciphertext letters in index order, independently permuted.
        ciphertext_alphabet: String,
        /// Offsets in report component order; the first is zero by symmetry.
        offsets: Vec<u8>,
    },
    /// A local contradiction or exhaustive offset search proves infeasibility.
    Infeasible {
        /// Whether the contradiction is local to a component or requires packing.
        reason: &'static str,
    },
    /// The attempt cap was reached before deciding; not an exclusion.
    BudgetExhausted,
}

/// Search accounting, explicit components and the resulting decision.
#[derive(Debug, Serialize)]
pub struct FeasibilityReport {
    /// Components ordered by decreasing total letters, then lowest plain letter.
    pub components: Vec<Component>,
    /// Number of offset placements examined, including immediately colliding ones.
    pub attempted_offsets: u32,
    /// Complete witness, exact contradiction or unresolved budget limit.
    pub decision: Decision,
}

/// Solve `c(C_i) - p(P_i) = key[i] (mod 26)` with independently bijective p and c.
///
/// All crib-connected coordinates are derived first. A common rotation of both
/// alphabets preserves the equations, so the first component's offset is fixed
/// to zero without excluding solutions. Remaining offsets range over 0–25.
/// Unconstrained letters impose no additional constraints and fill free slots.
///
/// # Errors
/// Rejects invalid text/cribs, insufficient key digits, digits outside 0–25, and
/// attempt limits outside 1–10,000,000. Contradictory valid equations are reported
/// as [`Decision::Infeasible`], while budget exhaustion is a separate decision.
///
/// # Examples
/// ```
/// use kryptos_research::{cipher::constraints::Crib, feasibility::{solve, Decision}};
/// let report = solve("B", &[Crib { position: 0, letter: 'A' }], &[1], 100)?;
/// assert!(matches!(report.decision, Decision::Feasible { .. }));
/// # Ok::<(), kryptos_research::cipher::CipherError>(())
/// ```
pub fn solve(
    ciphertext: &str,
    cribs: &[Crib],
    key: &[u8],
    attempt_limit: u32,
) -> Result<FeasibilityReport, CipherError> {
    validate_text(ciphertext)?;
    let known = validated(cribs, ciphertext.len())?;
    if key.len() < ciphertext.len() || key.iter().any(|&digit| digit >= 26) {
        return Err(parameter(
            "numeric key",
            "requires enough digits, all in 0..26",
        ));
    }
    if !(1..=10_000_000).contains(&attempt_limit) {
        return Err(parameter("attempt limit", "must be in 1..=10000000"));
    }
    let mut graph = vec![Vec::new(); 52];
    for (position, letter) in known {
        let plain = letter as usize - usize::from(b'A');
        let cipher = usize::from(ciphertext.as_bytes()[position] - b'A') + 26;
        graph[plain].push((cipher, key[position]));
        graph[cipher].push((plain, (26 - key[position]) % 26));
    }
    let Some(mut components) = components(&graph) else {
        return Ok(FeasibilityReport {
            components: Vec::new(),
            attempted_offsets: 0,
            decision: Decision::Infeasible {
                reason: "inconsistent cycle or within-component alphabet collision",
            },
        });
    };
    components.sort_by_key(|c| {
        (
            std::cmp::Reverse(c.plaintext.len() + c.ciphertext.len()),
            c.plaintext[0].letter,
        )
    });
    let (decision, attempted_offsets) = search::place(&components, attempt_limit)?;
    Ok(FeasibilityReport {
        components,
        attempted_offsets,
        decision,
    })
}

fn components(graph: &[Vec<(usize, u8)>]) -> Option<Vec<Component>> {
    let mut assigned = [None; 52];
    let mut result = Vec::new();
    for root in 0..26 {
        if graph[root].is_empty() || assigned[root].is_some() {
            continue;
        }
        assigned[root] = Some(0);
        let mut queue = VecDeque::from([(root, 0_u8)]);
        let mut nodes = Vec::new();
        while let Some((node, index)) = queue.pop_front() {
            nodes.push((node, index));
            for &(next, shift) in &graph[node] {
                let expected = (index + shift) % 26;
                if let Some(previous) = assigned[next] {
                    if previous != expected {
                        return None;
                    }
                } else {
                    assigned[next] = Some(expected);
                    queue.push_back((next, expected));
                }
            }
        }
        nodes.sort_unstable();
        let mut component = Component {
            plaintext: Vec::new(),
            ciphertext: Vec::new(),
        };
        let mut used = [0_u32; 2];
        for (node, index) in nodes {
            let side = node / 26;
            if used[side] & (1 << index) != 0 {
                return None;
            }
            used[side] |= 1 << index;
            // The graph has exactly 52 vertices, so this conversion is bounded.
            let letter = char::from(b'A' + u8::try_from(node % 26).ok()?);
            let target = if side == 0 {
                &mut component.plaintext
            } else {
                &mut component.ciphertext
            };
            target.push(Coordinate { letter, index });
        }
        result.push(component);
    }
    Some(result)
}

#[cfg(test)]
mod tests;
