//! Bounded, exhaustive placement of component translations on two alphabets.

use super::{Component, Coordinate, Decision};
use crate::cipher::{CipherError, parameter};

#[derive(Clone, Copy, Default)]
struct Footprint {
    plain: u32,
    cipher: u32,
}

fn mask(letters: &[Coordinate], offset: u8) -> u32 {
    letters
        .iter()
        .fold(0, |bits, c| bits | (1 << ((c.index + offset) % 26)))
}

enum Outcome {
    Found,
    Exhausted,
    Limit,
}

struct Search {
    choices: Vec<Vec<Footprint>>,
    offsets: Vec<u8>,
    attempted: u32,
    limit: u32,
}

impl Search {
    fn visit(&mut self, depth: usize, used: Footprint) -> Outcome {
        if depth == self.choices.len() {
            return Outcome::Found;
        }
        let end = if depth == 0 { 1 } else { 26 };
        for offset in 0..end {
            if self.attempted == self.limit {
                return Outcome::Limit;
            }
            self.attempted += 1;
            let candidate = self.choices[depth][usize::from(offset)];
            if used.plain & candidate.plain != 0 || used.cipher & candidate.cipher != 0 {
                continue;
            }
            self.offsets.push(offset);
            match self.visit(
                depth + 1,
                Footprint {
                    plain: used.plain | candidate.plain,
                    cipher: used.cipher | candidate.cipher,
                },
            ) {
                Outcome::Found => return Outcome::Found,
                Outcome::Limit => return Outcome::Limit,
                Outcome::Exhausted => {
                    self.offsets.pop();
                }
            }
        }
        Outcome::Exhausted
    }
}

pub(super) fn place(components: &[Component], limit: u32) -> Result<(Decision, u32), CipherError> {
    let choices = components
        .iter()
        .map(|c| {
            (0..26)
                .map(|offset| Footprint {
                    plain: mask(&c.plaintext, offset),
                    cipher: mask(&c.ciphertext, offset),
                })
                .collect()
        })
        .collect();
    let mut search = Search {
        choices,
        offsets: Vec::new(),
        attempted: 0,
        limit,
    };
    let decision = match search.visit(0, Footprint::default()) {
        Outcome::Found => Decision::Feasible {
            plaintext_alphabet: complete(components, &search.offsets, |c| &c.plaintext)?,
            ciphertext_alphabet: complete(components, &search.offsets, |c| &c.ciphertext)?,
            offsets: search.offsets,
        },
        Outcome::Exhausted => Decision::Infeasible {
            reason: "all component offsets exhausted modulo a common alphabet rotation",
        },
        Outcome::Limit => Decision::BudgetExhausted,
    };
    Ok((decision, search.attempted))
}

fn complete(
    components: &[Component],
    offsets: &[u8],
    side: impl Fn(&Component) -> &[Coordinate],
) -> Result<String, CipherError> {
    let mut slots = [None; 26];
    for (component, &offset) in components.iter().zip(offsets) {
        for coordinate in side(component) {
            slots[usize::from((coordinate.index + offset) % 26)] = Some(coordinate.letter);
        }
    }
    let mut unused = ('A'..='Z').filter(|letter| !slots.contains(&Some(*letter)));
    let mut output = String::with_capacity(26);
    for slot in slots {
        let letter = slot
            .or_else(|| unused.next())
            .ok_or_else(|| parameter("alphabet completion", "not enough unused letters"))?;
        output.push(letter);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(indices: &[u8], first_letter: u8) -> Component {
        Component {
            plaintext: indices
                .iter()
                .zip(first_letter..)
                .map(|(&index, letter)| Coordinate {
                    letter: char::from(letter),
                    index,
                })
                .collect(),
            ciphertext: Vec::new(),
        }
    }

    #[test]
    fn exhausted_packing_is_distinct_from_budget_exhaustion() {
        // Each component has 13 distinct coordinates. One fills an even coset;
        // the other contains adjacent coordinates and cannot fill the odd coset.
        let components = [
            component(&(0..26).step_by(2).collect::<Vec<_>>(), b'A'),
            component(&(0..13).collect::<Vec<_>>(), b'N'),
        ];
        let (decision, attempts) = place(&components, 27).unwrap();
        assert!(matches!(decision, Decision::Infeasible { .. }));
        assert_eq!(attempts, 27);
        assert!(matches!(
            place(&components, 26).unwrap().0,
            Decision::BudgetExhausted
        ));
    }

    #[test]
    fn compatible_components_fill_a_complete_bijection() {
        let components = [
            component(&(0..26).step_by(2).collect::<Vec<_>>(), b'A'),
            component(&(0..26).step_by(2).collect::<Vec<_>>(), b'N'),
        ];
        let (decision, _) = place(&components, 100).unwrap();
        if let Decision::Feasible {
            plaintext_alphabet,
            offsets,
            ..
        } = decision
        {
            assert_eq!(offsets, [0, 1]);
            assert_eq!(plaintext_alphabet, "ANBOCPDQERFSGTHUIVJWKXLYMZ");
        } else {
            panic!("expected a witness");
        }
    }
}
