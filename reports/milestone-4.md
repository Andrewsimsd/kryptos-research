# Milestone 4 — fixed-statistic permutation reproduction

Completed 2026-09-17. The fixed-statistic reproduction queued in
[milestone 3](milestone-3.md) is complete. Rust and Python agree on all five
observed values, every null histogram bin, initial permutation traces and final
generator state for one million permutations. The pinned upstream C measurement
functions also agree on the observed text and 10,000 sampled texts.

This is a bounded statistical reproduction. It neither recovers plaintext nor
identifies K4's cipher, and does not complete the broader Phase 3 calibration.

## Registered design and precision decision

[STATS-0001](../experiments/STATS-0001.json) registered the five statistic
definitions, inclusive tails, standard A–Z alphabet, width 21, null, generator,
seed 1261724721 and 10,000-sample pilot before simulation. The pilot had tail
counts **1, 1, 49, 34, 1,383**. The registered precision trigger was any count
below 100, so [STATS-0002](../experiments/STATS-0002.json) then fixed one million
new samples at seed 1261724722. The pilot is not pooled into the final estimates.
No statistic, tail, seed or stopping point was changed after precision sampling.

Each null text is a fresh Fisher–Yates permutation of K4's observed 97-letter
multiset, with replacement across trials. Plaintext cribs stay fixed. This
conditions on the monogram counts and asks about position-dependent structure.
It is not a uniform A–Z-string null or a distribution over cipher mechanisms.
All five measurements share the same permutations, preserving their dependence.

The deterministic SplitMix64 generator and rejection-based bounded draws are
specified in [frozen conventions](../docs/statistics-conventions.md). Integer
histograms avoid rounded comparisons. The quoted estimate is $(r+1)/(N+1)$,
where $r$ is the inclusive tail count among $N$ permutations. The marginal
approximate 95% Wilson interval describes Monte Carlo uncertainty for the raw
binomial proportion $r/N$. The interval calculation follows
[NIST's Wilson description](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm).

## Precision results

N = **1,000,000** for every row. Comparisons include ties. Distance sums use the
shorter circular A–Z distance, with maximum 13.

| Statistic and tail | Observed | Null mean | Tail count r | Estimate | Marginal Wilson 95% interval |
| --- | ---: | ---: | ---: | ---: | --- |
| Width-21 repeated ordered types ≥ observed | 11 | 3.489807 | 156 | 0.000157000 | [0.000133367, 0.000182473] |
| KRYPTOS-letter crib distance sum ≤ observed | 21 | 61.046604 | 180 | 0.000181000 | [0.000155557, 0.000208283] |
| Repeated-plaintext pair distance sum ≤ observed | 47 | 84.638479 | 4,234 | 0.00423500 | [0.00410863, 0.00436318] |
| Repeated-plaintext distances < 5, count ≥ observed | 10 | 4.470743 | 3,309 | 0.00331000 | [0.00319833, 0.00342348] |
| Adjacent equal pairs ≥ observed | 6 | 3.463390 | 132,097 | 0.132098 | [0.131435, 0.132762] |

The KRYPTOS-letter statistic has ten comparisons; repeated-plaintext statistics
have thirteen unordered position pairs. Their observed means are 2.1 and 47/13,
respectively. The width statistic counts distinct types occurring at least twice,
not the number of pairwise collisions. Adjacent equal pairs include overlaps;
K4 has six, starting at zero-based positions 18, 25, 32, 42, 46 and 67.

The first four published approximate rates, 1/6,750, 1/5,520, 1/240 and 1/310,
fall inside the corresponding intervals. See
[Bean's paper](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
and [the pinned source](https://github.com/RichardBean/k4testing/blob/6a5e3cb200d5ab72a62bb7f5124b4fdf163faf8c/k4-testy.c).
For adjacent doubles, our estimated reciprocal is about 7.57. The upstream
program prints integer division `co/pcount`, so its “1 in 7” label is a truncated
reciprocal, not an exact probability of 1/7. We retain raw counts and do not force
agreement with a rounded label.

The Bonferroni-adjusted estimates for these five fixed tests are, in order,
**0.0007850, 0.0009050, 0.0211750, 0.0165500 and 0.6604893**. The full precision
values, null standard deviations and observed-minus-null means are saved in
[verification.json](../results/STATS-0002/run-002/verification.json).
These marginal probabilities are not multiplied together.

These statistics were originally selected after observing K4. Registering this
reproduction does not undo that history. The five-test correction does not
account for other widths, alphabets, crib subsets or unpublished investigations.
The Wilson intervals are marginal, not simultaneous. The results support
reproducing the reported positional anomalies under this null; they do not
establish a global significance level or justify eliminating a cipher family.

## Implementation and reproducibility

[`src/statistics/`](../src/statistics/mod.rs) separates crib-derived measurement
from bounded sampling. It derives selected crib positions and repeated-letter
pairs from the evidence rather than copying the C program's index list. Its
public measurement API validates text and length; the CLI requires an explicit
sample count and seed. There are no new Rust dependencies or unsafe code.

[`verify_statistics.py`](../verification/verify_statistics.py) independently
uses grouped crib positions and counted ordered pairs, regenerates every null
text and compares the entire integer report. It also computes the uncertainty
and correction. The unchanged upstream source is included by a small GPL-3.0
[adapter](../third_party/bean-statistics-harness.c) which calls only the five
measurement functions. Its time-seeded simulation entry point is never run.
The adapter executes separately and is not linked into the Rust library.

The two new implementations are by the **same coordinator**, not a fresh-context
A7 reviewer. The pre-existing C implementation provides an additional check of
the statistic definitions. Neither the code comparison nor simulation
authenticates the original clues or establishes historical cipher attribution.

The [successful precision run](../results/STATS-0002/run-002/completion.json)
completed in **33.098 seconds**, including **0.516 seconds** for the release Rust
simulation and **32.327 seconds** for Python regeneration and C comparisons.
Maximum child RSS was **34,644 KiB**, including build and verification; this is
not simultaneous total memory or a controlled benchmark. The total run cap was
600 seconds. The run records tool versions, commands, source hashes, artifact
hashes and exit statuses. The original baseline diagnosis is byte-for-byte
unchanged.

Artifacts:

- [Pilot verification](../results/STATS-0001/run-001/verification.json).
- [Precision manifest](../results/STATS-0002/run-002/manifest.json).
- [Integer histograms and generator traces](../results/STATS-0002/run-002/statistics.json).
- [Saved C inputs](../results/STATS-0002/run-002/upstream-input.txt) and
  [outputs](../results/STATS-0002/run-002/upstream-output.txt).
- [Inference and cross-check record](../results/STATS-0002/run-002/verification.json).

Precision report SHA-256:
`6d4203ace9951a98192aaf65ae4a5bac3b907c5f7e663989f15944f43a7de04a`.
The first precision execution was interrupted during verification when its
execution session ended. Its partial artifacts and an explicit
[interruption record](../results/STATS-0002/run-001/completion.json) are preserved.
The successful run repeats the identical specification and seed; it does not
add independent samples. The interrupted run's termination time, exit status
and resource usage are unknown and have not been fabricated.

## Validation and next milestone

All required checks pass; see [the validation record](milestone-4-validation.json):

- Formatting and Clippy with pedantic warnings denied.
- **95 Rust unit/integration tests and seven doctests**.
- Separate doctest run and documentation generation with warnings denied.
- Rust 1.85 offline compatibility check.
- **68 Python tests**.

Tests cover circular wrap and antipodes, repeated types versus overlapping
pairs, malformed text and requests, sample bounds, generator vectors and
rejection sampling, multiset preservation, histogram totals, inclusive tails,
zero-exceedance behavior, Wilson boundaries, correction clipping and tampered
reports. CLI behavior and all previous milestones remain covered. Original
evidence and cipher-fixture hashes are unchanged; the new example is pinned by
the statistical experiment rather than added to the old frozen checksum list.

The next milestone is a **selection-aware width scan**, with a registered range
such as 1–48 and the entire maximum-selection procedure repeated on null texts.
Its statistic must account explicitly for the differing available pair counts
at different lags. Do not interpret the fixed-width result here as already
corrected for that scan. The broader diagnostic battery, uniform-string null,
synthetic cipher calibration, global alphabet feasibility for the 39 primers,
and fresh-context review remain separate open gates.

The declared width-scan handoff was subsequently completed in
[milestone 5](milestone-5.md). Its maximum-statistic correction covers widths
1–48 with separate calibration and 100,000 precision evaluation permutations.
