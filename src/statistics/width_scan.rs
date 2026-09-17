//! A fixed 1–48 width scan calibrated separately and selected identically on nulls.
//!
//! Each width counts repeated ordered pair types. Separate null calibration
//! supplies width-specific means and population variances. Maximum standardized
//! scores are compared exactly using signed integer cross-products, without
//! floating-point thresholds. This corrects only this declared width selection.

use super::sampling::SplitMix64;
use crate::{
    cipher::{CipherError, parameter, validate_text},
    evidence::Evidence,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Explicit seeds and fixed sample sizes for separate calibration and evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    /// Supported schema is 1; widths are always 1 through 48 inclusive.
    pub schema_version: u32,
    /// Calibration permutations, in 2..=1,000,000.
    pub calibration_samples: u32,
    /// Evaluation permutations, in 1..=1,000,000.
    pub samples: u32,
    /// Initial calibration generator state.
    pub calibration_seed: u64,
    /// Different initial evaluation generator state.
    pub seed: u64,
}

impl ScanRequest {
    fn validate(&self) -> Result<(), CipherError> {
        if self.schema_version != 1
            || !(2..=1_000_000).contains(&self.calibration_samples)
            || !(1..=1_000_000).contains(&self.samples)
            || self.seed == self.calibration_seed
        {
            return Err(parameter(
                "width scan",
                "requires schema 1, calibration samples 2..=1000000, samples 1..=1000000 and different seeds",
            ));
        }
        Ok(())
    }
}

/// Reproducible sampling output for one stage, with dense width/count histograms.
#[derive(Debug, Serialize)]
pub struct ScanStage {
    /// `histograms[width-1][count]` records every trial's statistic.
    pub histograms: Vec<Vec<u32>>,
    /// First sixteen sampled texts, or all if fewer.
    pub first_permutations: Vec<String>,
    /// Generator state after all trials.
    pub rng_final_state: u64,
    /// Number of words drawn, including bounded rejections.
    pub rng_draws: u64,
}

/// Complete integer output for calibration and maximum-statistic evaluation.
#[derive(Debug, Serialize)]
pub struct ScanReport {
    /// Request actually executed.
    pub request: ScanRequest,
    /// K4 repeated-type counts at widths 1–48.
    pub observed: Vec<u32>,
    /// Smallest width attaining the maximum standardized observed score.
    pub selected_width: usize,
    /// Width-specific sums of counts over calibration trials.
    pub calibration_sums: Vec<u64>,
    /// Width-specific sums of squared counts over calibration trials.
    pub calibration_sum_squares: Vec<u64>,
    /// `N * sum_squares - sums²`; strictly positive for every width.
    pub variance_numerators: Vec<u64>,
    /// Complete calibration histograms and generator traces.
    pub calibration: ScanStage,
    /// Complete evaluation histograms and generator traces.
    pub evaluation: ScanStage,
    /// Each trial appears once at `[winning_width-1][winning_raw_count]`.
    /// Ties select the smallest width. This preserves the maximum distribution.
    pub maxima_histograms: Vec<Vec<u32>>,
    /// Number of evaluation maxima at least the observed maximum.
    pub global_exceedances: u32,
}

/// Count distinct ordered pair types occurring twice or more at widths 1–48.
///
/// Every pair `(text[i], text[i+width])` with an in-range endpoint is included;
/// there is no row wrapping or padding. A type repeated three times counts once.
///
/// # Examples
/// ```
/// use kryptos_research::statistics::width_scan::measure_widths;
/// assert_eq!(measure_widths(&"A".repeat(97))?, vec![1; 48]);
/// # Ok::<(), kryptos_research::cipher::CipherError>(())
/// ```
/// # Errors
/// Rejects text other than exactly 97 uppercase ASCII letters.
pub fn measure_widths(text: &str) -> Result<Vec<u32>, CipherError> {
    validate_text(text)?;
    if text.len() != 97 {
        return Err(CipherError::LengthMismatch {
            expected: 97,
            actual: text.len(),
        });
    }
    Ok(count_widths(
        &text.bytes().map(|b| b - b'A').collect::<Vec<_>>(),
    ))
}

fn count_widths(text: &[u8]) -> Vec<u32> {
    (1..=48)
        .map(|width| {
            let mut bins = [0_u8; 676];
            let mut repeated = 0;
            for (&a, &b) in text.iter().zip(text.iter().skip(width)) {
                let count = &mut bins[usize::from(a) * 26 + usize::from(b)];
                *count += 1;
                if *count == 2 {
                    repeated += 1;
                }
            }
            repeated
        })
        .collect()
}

fn empty_histograms() -> Vec<Vec<u32>> {
    (1..=48)
        .map(|width| vec![0; (97 - width) / 2 + 1])
        .collect()
}

#[derive(Clone, Copy)]
struct Score {
    numerator: i128,
    variance: i128,
}

impl Score {
    fn compare(self, other: Self) -> Ordering {
        match self.numerator.signum().cmp(&other.numerator.signum()) {
            Ordering::Equal => {
                // Counts <=48 and calibration N<=1e6 bound these products below
                // 6e30, well within i128. Variance denominators are positive.
                let order = (self.numerator * self.numerator * other.variance)
                    .cmp(&(other.numerator * other.numerator * self.variance));
                if self.numerator < 0 {
                    order.reverse()
                } else {
                    order
                }
            }
            different => different,
        }
    }
}

fn moments(histograms: &[Vec<u32>]) -> (Vec<u64>, Vec<u64>) {
    histograms
        .iter()
        .map(|histogram| {
            histogram
                .iter()
                .zip(0_u64..)
                .fold((0, 0), |(sum, squares), (&count, value)| {
                    (
                        sum + value * u64::from(count),
                        squares + value * value * u64::from(count),
                    )
                })
        })
        .unzip()
}

fn score_table(
    samples: u32,
    sums: &[u64],
    squares: &[u64],
) -> Result<(Vec<Vec<Score>>, Vec<u64>), CipherError> {
    let mut variances = Vec::new();
    let mut table = Vec::new();
    for ((bins, &sum), &square) in empty_histograms().iter().zip(sums).zip(squares) {
        let variance = u64::from(samples) * square - sum * sum;
        if variance == 0 {
            return Err(parameter(
                "calibration",
                "zero variance at a width; register a larger calibration sample",
            ));
        }
        variances.push(variance);
        table.push(
            (0_u32..)
                .take(bins.len())
                .map(|value| Score {
                    numerator: i128::from(samples) * i128::from(value) - i128::from(sum),
                    variance: i128::from(variance),
                })
                .collect(),
        );
    }
    Ok((table, variances))
}

fn winner(values: &[u32], table: &[Vec<Score>]) -> usize {
    let mut selected = 0;
    for width in 1..values.len() {
        // Count bounds are at most 48, so conversion is exact on supported targets.
        if table[width][values[width] as usize].compare(table[selected][values[selected] as usize])
            == Ordering::Greater
        {
            selected = width;
        }
    }
    selected
}

fn sample_stage(
    original: &[u8],
    samples: u32,
    seed: u64,
    mut visit: impl FnMut(&[u32]),
) -> Result<ScanStage, CipherError> {
    let mut rng = SplitMix64 {
        state: seed,
        draws: 0,
    };
    let mut report = ScanStage {
        histograms: empty_histograms(),
        first_permutations: Vec::new(),
        rng_final_state: 0,
        rng_draws: 0,
    };
    let mut text = original.to_vec();
    for trial in 0..samples {
        text.copy_from_slice(original);
        for index in (1..97).rev() {
            let other =
                usize::try_from(rng.bounded(
                    u64::try_from(index + 1).map_err(|_| parameter("width", "exceeds u64"))?,
                ))
                .map_err(|_| parameter("index", "exceeds usize"))?;
            text.swap(index, other);
        }
        let values = count_widths(&text);
        for (histogram, &value) in report.histograms.iter_mut().zip(&values) {
            histogram[value as usize] += 1;
        }
        visit(&values);
        if trial < 16 {
            report
                .first_permutations
                .push(text.iter().map(|&b| char::from(b'A' + b)).collect());
        }
    }
    report.rng_final_state = rng.state;
    report.rng_draws = rng.draws;
    Ok(report)
}

/// Calibrate each width on a separate sample, then repeat maximum selection on
/// every evaluation permutation. The same frozen calibration applies to K4 and
/// all evaluation texts. No normal approximation is used for tail decisions.
/// # Errors
/// Rejects invalid request bounds, equal seeds or a zero calibration variance.
pub fn scan(evidence: &Evidence, request: ScanRequest) -> Result<ScanReport, CipherError> {
    request.validate()?;
    let original: Vec<_> = evidence.ciphertext().bytes().map(|b| b - b'A').collect();
    let calibration = sample_stage(
        &original,
        request.calibration_samples,
        request.calibration_seed,
        |_| {},
    )?;
    let (sums, squares) = moments(&calibration.histograms);
    let (table, variances) = score_table(request.calibration_samples, &sums, &squares)?;
    let observed = count_widths(&original);
    let selected = winner(&observed, &table);
    let threshold = table[selected][observed[selected] as usize];
    let mut maxima = empty_histograms();
    let mut exceedances = 0;
    let evaluation = sample_stage(&original, request.samples, request.seed, |values| {
        let width = winner(values, &table);
        maxima[width][values[width] as usize] += 1;
        if table[width][values[width] as usize].compare(threshold) != Ordering::Less {
            exceedances += 1;
        }
    })?;
    Ok(ScanReport {
        request,
        observed,
        selected_width: selected + 1,
        calibration_sums: sums,
        calibration_sum_squares: squares,
        variance_numerators: variances,
        calibration,
        evaluation,
        maxima_histograms: maxima,
        global_exceedances: exceedances,
    })
}

#[cfg(test)]
mod tests;
