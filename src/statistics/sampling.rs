//! Reproducible permutation sampling and integer histograms, without inference.

use super::StatisticModel;
use crate::cipher::{CipherError, parameter};
use serde::{Deserialize, Serialize};

/// Strict bounded request for the five-statistic permutation experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationRequest {
    /// Supported schema is 1.
    pub schema_version: u32,
    /// Fixed number of permutations, in 1..=10,000,000.
    pub samples: u32,
    /// Explicit `SplitMix64` initial state; zero is valid.
    pub seed: u64,
}

/// Exact integer simulation outputs; uncertainty is computed by the verifier.
#[derive(Debug, Serialize)]
pub struct Simulation {
    /// Versioned, bounded request actually executed.
    pub request: SimulationRequest,
    /// Observed values in [`super::NAMES`] order.
    pub observed: [u32; 5],
    /// Dense histograms: `histograms[statistic][value]` is the sample count.
    pub histograms: Vec<Vec<u32>>,
    /// First sixteen permutations (or all when fewer) for reproducibility checks.
    pub first_permutations: Vec<String>,
    /// Final wrapping `SplitMix64` state.
    pub rng_final_state: u64,
    /// Generator words consumed, including rejected bounded draws.
    pub rng_draws: u64,
}

pub(crate) struct SplitMix64 {
    pub(crate) state: u64,
    pub(crate) draws: u64,
}

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.draws += 1;
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    pub(crate) fn bounded(&mut self, bound: u64) -> u64 {
        // Discard the short initial residue interval: the retained range has
        // exactly a multiple of bound entries, avoiding modulo-selection bias.
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let value = self.next();
            if value >= threshold {
                return value % bound;
            }
        }
    }
}

/// Sample fresh permutations of the evidence's multiset with replacement.
///
/// Each trial resets the original sequence, then applies descending Fisher–Yates
/// with rejection-based bounded `SplitMix64` draws. All five statistics share the
/// same trials. This preserves their dependence for subsequent interpretation.
/// # Errors
/// Rejects unsupported schema versions and sample counts outside 1..=10,000,000.
pub fn simulate(
    model: &StatisticModel,
    request: SimulationRequest,
) -> Result<Simulation, CipherError> {
    if request.schema_version != 1 || !(1..=10_000_000).contains(&request.samples) {
        return Err(parameter(
            "simulation",
            "requires schema 1 and samples in 1..=10000000",
        ));
    }
    let mut rng = SplitMix64 {
        state: request.seed,
        draws: 0,
    };
    let mut histograms: Vec<_> = model
        .histogram_sizes()
        .into_iter()
        .map(|size| vec![0; size])
        .collect();
    let mut text = model.original.clone();
    let mut first_permutations = Vec::new();
    for trial in 0..request.samples {
        text.copy_from_slice(&model.original);
        for index in (1..text.len()).rev() {
            let bound = u64::try_from(index + 1).map_err(|_| parameter("length", "exceeds u64"))?;
            let other = usize::try_from(rng.bounded(bound))
                .map_err(|_| parameter("index", "exceeds usize"))?;
            text.swap(index, other);
        }
        for (histogram, value) in histograms.iter_mut().zip(model.measure_digits(&text)) {
            histogram
                [usize::try_from(value).map_err(|_| parameter("statistic", "exceeds usize"))?] += 1;
        }
        if trial < 16 {
            first_permutations.push(text.iter().map(|&b| char::from(b'A' + b)).collect());
        }
    }
    Ok(Simulation {
        request,
        observed: model.measure_digits(&model.original),
        histograms,
        first_permutations,
        rng_final_state: rng.state,
        rng_draws: rng.draws,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix_zero_seed_matches_fixed_vector() {
        let mut rng = SplitMix64 { state: 0, draws: 0 };
        assert_eq!(
            [rng.next(), rng.next(), rng.next()],
            [
                0xe220_a839_7b1d_cdaf,
                0x6e78_9e6a_a1b9_65f4,
                0x06c4_5d18_8009_454f
            ]
        );
    }

    #[test]
    fn bounded_draws_cover_boundaries_and_rejection_branch() {
        let mut rng = SplitMix64 { state: 0, draws: 0 };
        assert_eq!(rng.bounded(1), 0);
        for _ in 0..100 {
            assert!(rng.bounded((1 << 63) + 1) < (1 << 63) + 1);
        }
        assert!(rng.draws > 101);
    }
}
