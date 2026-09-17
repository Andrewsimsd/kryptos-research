# Milestone 4: fixed-statistic permutation reproduction

Reproduce the five quantities in pinned `k4-testy.c`, without its time-derived
seed, separate streams, rounded reciprocal output or ten-million-trial default.
The original file is unchanged; a separately licensed C adapter calls its five
measurement functions on saved texts. There is no width scan in this milestone.

The statistic order, alphabet and one-sided tails are fixed before simulation:

1. Count distinct ordered types `(C[i], C[i+21])` appearing at least twice for
   i=0..75. Upper tail, ties included; a triple counts as one repeated type.
2. Sum circular A–Z distances between plaintext and ciphertext at crib positions
   whose plaintext is in KRYPTOS. Lower tail, ties included. Ten comparisons.
3. Sum circular A–Z distances between ciphertext letters for every unordered
   pair of crib positions bearing the same plaintext letter. Lower tail,
   ties included. Thirteen comparisons; letters occurring three times give
   three pairs. Use sums rather than rounded means.
4. Count those thirteen distances strictly below five. Upper tail, ties included.
5. Count adjacent equal letters at i,i+1 for i=0..95, including overlapping
   pairs. Upper tail, ties included; this is not a count of distinct types.

The null consists of uniformly shuffled copies of the observed 97-letter
multiset, sampled with replacement. Plaintext anchors remain fixed. This asks
about positional structure conditional on the counts. It is not the uniform
A–Z-string null or a distribution over cipher families. All five statistics are
evaluated on each shared sample, preserving their dependence.

Generation: SplitMix64 state starts at the manifest's unsigned 64-bit seed.
Each word increments state by 0x9e3779b97f4a7c15, then applies xor-shift 30,
multiply 0xbf58476d1ce4e5b9, xor-shift 27, multiply 0x94d049bb133111eb,
and xor-shift 31, with 64-bit wrapping arithmetic. For bound b, reject words
below `2^64 mod b`, then return word mod b. Each trial resets the original text
and shuffles positions i=96 down to 1, swapping with a draw in 0..i inclusive.
This removes bounded-integer modulo bias; the generator is deterministic,
noncryptographic pseudorandomness, not physical randomness.

Begin with 10,000 permutations. If any tail has fewer than 100 exceedances,
register a separate 1,000,000-sample precision run with a different seed, without
changing statistics or tails. Do not pool pilot samples into the precision run.
The latter's N is fixed before its draws; no within-run stopping or seed shopping.
Further precision requires a new experiment and justification.

Preserve every statistic's dense integer histogram, observed threshold, inclusive
tail count r, sample size N, null mean and standard deviation, observed-minus-null
mean, estimate `(r+1)/(N+1)`, and marginal approximate 95% Wilson score interval
for r/N with z=1.959963984540054. Zero exceedances yield a positive estimate and
upper bound. Report `min(1, 5*(r+1)/(N+1))` as the Bonferroni-adjusted value for
this fixed five-test battery. Do not multiply the five marginal probabilities.
Wilson intervals express Monte Carlo uncertainty under the sampling model,
not uncertainty about which cipher was used; they are not simultaneous bounds.

These tests were selected historically after observing K4. Registration here
prevents additional tuning in this reproduction but does not undo historical
selection. The five-test correction does not cover other widths, alphabets,
crib subsets or unpublished investigations. No global significance or rejection
of a cipher family is justified. A later width scan must run its entire selection
procedure on null texts. Synthetic cipher calibration remains separate work.

Rust and Python regenerate every sample and require identical integer outputs,
prefix permutations and final generator state. The C adapter checks the observed
text and first min(N,10000) permutations. Its unchanged numeric conventions must
agree with Python on each of those texts. A mismatch fails the run, regardless
of closeness to published approximate rates. Both new implementations are by
the same coordinator, not fresh-context A7 review.

Sources: [Bean paper, sections 2.1 and 2.4](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109),
[pinned code](https://github.com/RichardBean/k4testing/blob/6a5e3cb200d5ab72a62bb7f5124b4fdf163faf8c/k4-testy.c),
[NIST Wilson interval description](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm).
