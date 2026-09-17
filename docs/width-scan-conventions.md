# Milestone 5: calibrated maximum over widths 1–48

Before inspecting the scan, fix the range to every integer width 1 through 48
and the upper-tail repeated ordered pair-type statistic from milestone 4. At
width w, all 97-w ordered pairs (C[i], C[i+w]) are used, without wrapping or
padding. A type appearing at least twice counts once. Available pair counts
vary from 96 to 49; raw counts are not compared directly across widths.

Draw 10,000 calibration permutations of the observed multiset using seed
1261726001. At each width record S=sum(X), Q=sum(X²) and V=N*Q-S². Freeze this
calibration before evaluating the observed scan or evaluation null. The score
at count x is Z=(N*x-S)/sqrt(V), equivalent to standardizing by the width's
calibration mean and population standard deviation. Zero V is an error, not a
zero score. This calibration accounts for both pair opportunities and the
width-dependent null spread. No normal-distribution tail approximation is used.

Select the largest Z across all 48 widths, breaking exact ties toward the
smallest width. Repeat this full selection on every evaluation permutation,
always using the same frozen calibration. Compare null maxima to K4's maximum,
including ties. Selection and thresholds use exact signed integer comparisons:
first compare signs, then cross-multiplied squares, reversing order for negative
scores. Floats are only for display, never decisions.

Null texts are fresh permutations with replacement of the same K4 multiset.
Reuse the precisely specified SplitMix64/Fisher–Yates generator from
`statistics-conventions.md`. Calibration and evaluation use different seeds.
Start with a fixed 10,000 evaluation trials, seed 1261726002. If the global tail
has fewer than 100 exceedances, register 100,000 new evaluation trials at seed
1261726003 before drawing them. Keep the calibration unchanged and do not pool
pilot evaluations. No other seed, width, statistic, calibration size or stopping
rule is tuned after seeing the scan. Any extension needs a new specification.

Preserve calibration/evaluation histograms at every width, calibration moments,
observed counts, generator traces, and a histogram of (winning width, winning
raw count) sufficient to reconstruct every null maximum. Report the global
inclusive tail count r, (r+1)/(B+1), and a marginal approximate 95% Wilson interval
for r/B. Also show per-width local tails and the number of null maxima at least
that width's observed score. Adjusted counts cannot be smaller than local ones.
Do not multiply marginal probabilities or combine pilot and precision samples.

Inference is conditional on the fixed, independent calibration. Wilson bounds
describe evaluation Monte Carlo error, not calibration uncertainty or historical
cipher uncertainty. Discreteness, width dependence and non-normal tails remain
present in the maximum null distribution and need not be modeled analytically.

This is a single maximum test under the complete permutation null, not a claim
of strong familywise control under arbitrary partial alternatives. The scan
correction covers only these 48 widths and this one registered statistic. It
does not erase the historical selection of K4 anomalies, alternative alphabets,
or crib subsets, and does not identify a cipher. Uniform-string nulls, synthetic
cipher calibration and all broader Phase 3 work remain separate.

Rust and Python must agree on every integer report field. Python derives score
ranks once using arbitrary-precision comparisons; Rust compares scores directly
at each selection. Both implementations are by the same coordinator, not a
fresh-context A7 review.

Method context: maximum-statistic permutation correction is described by
[Alberton et al., Multiple testing correction over contrasts for brain imaging](https://pmc.ncbi.nlm.nih.gov/articles/PMC8191638/).
This experiment's separate calibration and exact score comparison are explicitly
defined above; it does not claim their application-specific assumptions apply.
