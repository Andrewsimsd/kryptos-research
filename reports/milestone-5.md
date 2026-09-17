# Milestone 5 — selection-aware width scan

Completed 2026-09-17. The width-scan handoff from [milestone 4](milestone-4.md)
is complete. **Width 21 remains the strongest of widths 1–48.** After applying
the same maximum-selection procedure to every null text, **441 of 100,000**
evaluation permutations match or exceed K4's maximum. The adjusted estimate is
**0.004419956**, with a marginal approximate Monte Carlo 95% Wilson interval
**[0.004017920, 0.004840154]**, conditional on the fixed calibration.

Rust and Python agree on every integer field of the complete report. This
corrects the declared width scan under the multiset-permutation null; it does
not identify K4's cipher or correct all historical searches for patterns.

## Registered experiment and selection rule

[WIDTHS-0001](../experiments/WIDTHS-0001.json) registered widths 1–48, the upper
repeated-ordered-type count, seeds, calibration, tie rule, precision trigger
and limits before inspecting the scan. The statistic at width w counts distinct
ordered types `(C[i], C[i+w])` occurring at least twice. There is no padding or
wrapping. A type occurring three times counts once.

There are **97−w available pairs**, ranging from 96 at width 1 to 49 at width 48.
To account for the differing opportunities and spreads, a separate 10,000-text
calibration estimates a mean and population standard deviation at each width.
For a raw count x, with calibration sample size N, sum S and squared sum Q:

```text
V = N*Q - S*S
Z = (N*x - S) / sqrt(V)
```

The score is undefined when V=0; the implementation returns an explicit error.
No normal-distribution approximation supplies tail probabilities. Instead,
select the maximum Z over all 48 widths, with exact ties assigned to the
smallest width. Use the same frozen calibration and full selection procedure
on K4 and every evaluation permutation. The observed threshold and null maxima
are compared inclusively.

Maximum-statistic permutation correction provides the methodological context;
see [Alberton et al.](https://pmc.ncbi.nlm.nih.gov/articles/PMC8191638/).
Our separate calibration and exact comparison conventions are specified in
[the frozen design](../docs/width-scan-conventions.md). This is a single maximum
test under the complete permutation null, not a claim of strong familywise
control under arbitrary partial alternatives.

All comparisons use signed integer arithmetic. Equal signs are compared using
cross-multiplied squared numerators and positive variance denominators; negative
scores reverse the ordering. Floating-point values appear only in the human
summary. Rust's bounded domain keeps intermediate products below 6×10³⁰,
within i128. Python uses arbitrary-precision integers to form an equivalent
rank table. This avoids near-tie disagreements from square roots.

## Pilot and precision run

Both stages sample fresh permutations with replacement of K4's observed
97-letter multiset. The previously tested SplitMix64 generator and unbiased
bounded Fisher–Yates shuffle are reused. This conditions on K4's counts; it is
not a uniform A–Z-string null or a sample from possible cipher mechanisms.

| Stage | Calibration size / seed | Evaluation size / seed | Global tail count |
| --- | --- | --- | ---: |
| Pilot | 10,000 / 1261726001 | 10,000 / 1261726002 | 39 |
| Precision | Same calibration | 100,000 / 1261726003 | 441 |

The pilot's 39 exceedances triggered the registered rule of fewer than 100.
[WIDTHS-0002](../experiments/WIDTHS-0002.json) then fixed the larger evaluation
sample before drawing it. Pilot evaluations were not pooled. The calibration,
statistic, width range and tie rule were unchanged; no seed shopping or within-run
stopping occurred. Calibration output is identical between runs, not additional
independent calibration data. In total there are 10,000 calibration
trials and two separate evaluation samples of 10,000 and 100,000 draws; rerunning
the calibration for verification does not increase its statistical sample size.

The top five observed standardized scores are shown below. All other widths
are preserved in the machine-readable report; this display does not define
an additional selection procedure.

| Width | Available pairs | Observed repeated types | Calibration mean / SD | Z | Local tail estimate | Maximum-adjusted estimate |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| 21 | 76 | 11 | 3.4915 / 1.667372 | 4.503196 | 0.0001300 | **0.0044200** |
| 10 | 87 | 9 | 4.5233 / 1.885009 | 2.374896 | 0.0247098 | 0.5265747 |
| 1 | 96 | 10 | 5.5124 / 2.051937 | 2.187007 | 0.0307597 | 0.6574134 |
| 7 | 90 | 9 | 4.8775 / 1.909579 | 2.158852 | 0.0358896 | 0.6834132 |
| 14 | 83 | 7 | 4.1469 / 1.801699 | 1.583561 | 0.0997890 | 0.9606204 |

Every estimate is `(r+1)/(B+1)`. Width 21's local count is only 12 of 100,000;
its local estimate has much more Monte Carlo uncertainty than the earlier
million-sample fixed-width experiment. The precision decision here targets the
**global** tail. No extra simulation was added to make a local estimate agree
with milestone 4. An adjusted count is at least its corresponding local count
at every width, as required by maximum selection.

The main practical change from the fixed-width analysis is the scale of the
tail: treating width 21 alone yields a much smaller number than allowing any
of the 48 registered widths to win. Even this correction covers only the chosen
statistic and range. It does not account for other alphabets, crib subsets,
unpublished investigations, or choosing this statistic because K4 looked unusual.
No cipher family is ruled out by this result.

Wilson intervals quantify evaluation sampling uncertainty conditional on the
fixed, separately generated calibration. They do not quantify calibration
uncertainty, are not simultaneous intervals for all widths, and do not measure
the probability that a cipher hypothesis is correct.

## Implementation and preserved outputs

[`statistics::width_scan`](../src/statistics/width_scan.rs) separates measurement,
calibration moments, exact score comparison and sampling. Each evaluation text
contributes to every width's histogram and exactly one cell of a joint histogram
of winning width and raw count. This retains the full null maximum distribution,
including ties, without saving every permutation.

[`verify_width_scan.py`](../verification/verify_width_scan.py) independently counts
ordered pairs using Python counters, derives score ranks, regenerates every
calibration and evaluation draw, and checks the entire Rust report. It reuses
the previously tested Python RNG. Both new implementations were written by the
same coordinator; this is not the plan's fresh-context A7 review. The pinned
upstream C program does not implement this calibrated scan. Width 21 is regression
checked against the already verified fixed-statistic implementation.

The [successful precision run](../results/WIDTHS-0002/run-001/completion.json)
took **28.347 seconds** including build, simulation and verification. The release
Rust scan took about **0.365 seconds** and Python verification **26.557 seconds**.
Maximum child RSS was **263,028 KiB**, including compilation, not simultaneous
total memory. This is run accounting, not a controlled throughput benchmark.
The cap was 600 seconds and 110,000 calibration-plus-evaluation permutations,
each measured at 48 widths and independently regenerated for verification.

Artifacts:

- [Pilot verification](../results/WIDTHS-0001/run-001/verification.json).
- [Precision manifest](../results/WIDTHS-0002/run-001/manifest.json).
- [Complete histograms, calibration and generator traces](../results/WIDTHS-0002/run-001/scan.json).
- [All 48 local/adjusted tails and uncertainty](../results/WIDTHS-0002/run-001/verification.json).
- [Validation record](milestone-5-validation.json).

The full scan report SHA-256 is
`b0898237fd2167cda9bce7cdf1316a1f9fdf2c85a00d063b918480ff7d1de1bd`.
Evidence and earlier frozen fixtures remain unchanged. Every run also requires
byte-identical baseline diagnosis and milestone-4 fixed-statistic pilot output.
The new fixture is pinned by the width-scan manifests; older checksum lists
were not rewritten. Existing output directories are refused.

## Validation and next work package

All required checks pass:

- Formatting and Clippy with pedantic warnings denied.
- **104 Rust unit/integration tests and eight doctests**.
- Separate doctest run and documentation generation with warnings denied.
- Rust 1.85 offline compatibility check.
- **73 Python tests**.

Coverage includes invalid text, sample limits and seeds, zero variance, repeated
types versus occurrences, lag boundaries, sign-aware ordering, exact scaled
ties, differing calibration means, multiset preservation, complete histogram
totals, adjusted-versus-local ordering, CLI failures and corrupted reports. The
CLI must reproduce the complete preserved pilot byte-for-byte. No dependencies,
unsafe code or warning suppressions were added.

The next bounded work package is **global alphabet feasibility for the 39
Gromark primer survivors** from milestone 3: register the same model, solve the
component offsets subject to both alphabets' all-different constraints, and
produce checked alphabet witnesses or exact unsatisfiability results for each
primer. This closes an existing necessary-versus-sufficient gap before any
heuristic language search. Compatible alphabets alone would still not establish
intended plaintext or historical use.

The broader Phase 3 battery, uniform-string null, held-out synthetic cipher
calibration, source-access gaps and fresh-context review remain open. The fixed
statistic and width-scan milestones do not silently complete those gates.
