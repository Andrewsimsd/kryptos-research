//! Five fixed statistics from Bean's K4 investigation, under explicit conventions.
//!
//! These descriptive quantities and [`simulate`] compare the aligned evidence
//! with permutations preserving its letter counts. They do not identify a cipher
//! or correct for the historical selection of interesting widths and alphabets.

mod sampling;
pub mod width_scan;
pub use sampling::{Simulation, SimulationRequest, simulate};

use crate::{
    cipher::{CipherError, validate_text},
    evidence::Evidence,
};

/// Statistic identifiers in the order returned by [`StatisticModel::measure`].
pub const NAMES: [&str; 5] = [
    "width21_repeated_types",
    "kryptos_minor_sum",
    "repeated_plain_minor_sum",
    "repeated_plain_below_five",
    "adjacent_equal_pairs",
];

/// Whether an observed value's extreme tail is the upper (true) or lower tail.
pub const UPPER_TAIL: [bool; 5] = [true, false, false, true, true];

/// Fixed-width, standard-alphabet statistics with crib positions derived from evidence.
///
/// The width-21 statistic counts distinct ordered pair types occurring at least
/// twice, not all matching pairs. Minor differences are shortest circular A–Z
/// distances. Repeated-plaintext comparisons include every unordered pair of
/// positions carrying the same crib letter. Adjacent equal pairs overlap.
///
/// # Examples
/// ```
/// use kryptos_research::{evidence::Evidence, statistics::StatisticModel};
/// let evidence = Evidence::from_json(include_str!("../../evidence/k4.json"))?;
/// let model = StatisticModel::new(&evidence);
/// assert_eq!(model.measure(evidence.ciphertext())?, [11, 21, 47, 10, 6]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct StatisticModel {
    original: Vec<u8>,
    selected: Vec<(usize, u8)>,
    pairs: Vec<(usize, usize)>,
}

impl StatisticModel {
    /// Derive position lists from validated evidence; no statistic is tuned.
    #[must_use]
    pub fn new(evidence: &Evidence) -> Self {
        let known: Vec<_> = evidence.known_letters().collect();
        let selected = known
            .iter()
            .filter(|(_, letter)| b"KRYPTOS".contains(letter))
            .map(|&(index, letter)| (index, letter - b'A'))
            .collect();
        let mut pairs = Vec::new();
        for (index, &(first, letter)) in known.iter().enumerate() {
            for &(second, other) in &known[index + 1..] {
                if letter == other {
                    pairs.push((first, second));
                }
            }
        }
        Self {
            original: evidence.ciphertext().bytes().map(|b| b - b'A').collect(),
            selected,
            pairs,
        }
    }

    /// Measure an uppercase 97-letter string at the evidence's fixed positions.
    ///
    /// # Errors
    /// Rejects non-A–Z input and lengths different from the evidence.
    pub fn measure(&self, text: &str) -> Result<[u32; 5], CipherError> {
        validate_text(text)?;
        if text.len() != self.original.len() {
            return Err(CipherError::LengthMismatch {
                expected: self.original.len(),
                actual: text.len(),
            });
        }
        Ok(self.measure_digits(&text.bytes().map(|b| b - b'A').collect::<Vec<_>>()))
    }

    fn measure_digits(&self, text: &[u8]) -> [u32; 5] {
        let mut counts = [0_u8; 676];
        let mut repeats = 0;
        for (&left, &right) in text.iter().zip(text.iter().skip(21)) {
            let count = &mut counts[usize::from(left) * 26 + usize::from(right)];
            *count += 1;
            if *count == 2 {
                repeats += 1;
            }
        }
        let minor_sum = self.selected.iter().map(|&(i, p)| minor(p, text[i])).sum();
        let mut repeated_sum = 0;
        let mut below_five = 0;
        for &(a, b) in &self.pairs {
            let distance = minor(text[a], text[b]);
            repeated_sum += distance;
            below_five += u32::from(distance < 5);
        }
        let doubles = text
            .windows(2)
            .map(|pair| u32::from(pair[0] == pair[1]))
            .sum();
        [repeats, minor_sum, repeated_sum, below_five, doubles]
    }

    fn histogram_sizes(&self) -> [usize; 5] {
        [
            (self.original.len() - 21) / 2 + 1,
            self.selected.len() * 13 + 1,
            self.pairs.len() * 13 + 1,
            self.pairs.len() + 1,
            self.original.len(),
        ]
    }
}

fn minor(a: u8, b: u8) -> u32 {
    let distance = a.abs_diff(b);
    u32::from(distance.min(26 - distance))
}

#[cfg(test)]
mod tests;
