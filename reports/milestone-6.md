# Milestone 6 — complete alphabet feasibility

Completed 2026-09-17. The handoff from
[milestone 5](milestone-5.md) is complete: every one of the 39 registered
five-digit decimal primer survivors has been tested against the global
all-different constraints on both independently unknown alphabets.

| Decision | Primers |
| --- | ---: |
| Feasible with checked complete alphabets | **39** |
| Exactly infeasible | 0 |
| Unresolved by the search budget | 0 |

The result closes the necessary-versus-sufficient gap left by the milestone-3
graph filter. It also shows that complete alphabet feasibility under this broad
model does **not** narrow the 39-primer list. The generated alphabets are
compatibility witnesses. They are not proposed historical keys, and decoding
the 73 uncribbed positions with them does not recover an intended plaintext.

## Registered question and exact model

[FEASIBILITY-0001](../experiments/FEASIBILITY-0001.json) was registered before
the preserved run. Its input list is byte-bound to the final
[PRIMERS-0001 report](../results/PRIMERS-0001/run-002/primers.json). No primer,
recurrence, base, offset, crib position, alphabet convention, or plaintext score
was added after observing the result.

For each primer, the recurrence is

```text
k[i] = (k[i-5] + k[i-4]) mod 10
```

including the five primer digits at positions 0–4 and producing 97 digits. At
each of the 24 frozen crib positions, the solver requires

```text
c(C_i) - p(P_i) = k[i] mod 26
```

where `p` and `c` independently map A–Z bijectively onto 0–25. They are not
restricted to A–Z order, the KRYPTOS alphabet, ACA keyword construction, a word
list, or matching orders. The complete scope and canonical choices are frozen
in [the feasibility conventions](../docs/feasibility-conventions.md).

## Exact search and completeness

[`feasibility::solve`](../src/feasibility/mod.rs) rebuilds the bipartite crib
graph for one expanded key. Within each connected component it fixes the
alphabetically lowest plaintext letter at relative coordinate zero and derives
all remaining coordinates. An inconsistent cycle or two distinct letters on
one alphabet side at the same coordinate is an immediate contradiction.

Every locally consistent component retains one additive offset in 0–25. The
solver orders larger components first and places their plaintext and ciphertext
footprints into separate 26-bit occupancy masks. A placement is pruned only
when it causes a real collision on one of the two alphabets. Fixing the first
component at offset zero removes the common rotation of both alphabets; it does
not remove distinct solutions. Therefore, if every normalized offset branch is
exhausted, the result is an exact infeasibility proof for this model.

The search distinguishes three outcomes:

- `feasible`, with two complete 26-letter permutations, component offsets, and
  all 24 directly evaluated equations;
- `infeasible`, only after every normalized offset branch is exhausted;
- `budget_exhausted`, which remains unresolved and is never reported as proof.

Unconstrained letters are placed alphabetically into unused slots after a
solution is found. Any partial injection extends to a permutation, so this
deterministic completion adds no condition to feasibility.

All 39 instances contain five components. Rust found a first witness in **18–52
candidate offset attempts** per primer, **1,504 attempts** total. The registered
cap was 10,000,000 attempts per primer, so no result approached it.

## Independent verification

[`verify_feasibility.py`](../verification/verify_feasibility.py) independently:

- checks that the supplied list exactly matches all 39 registered survivors;
- expands every 97-digit recurrence again;
- derives components with its own graph traversal;
- searches component placements with set intersections and a smallest-domain
  choice rather than Rust's fixed component order;
- validates that both reported alphabet strings are permutations;
- checks every reported component coordinate and offset; and
- evaluates every one of the **936 crib equations** directly.

The Python search resolved every primer as feasible in six recursive states.
It need not reproduce Rust's chosen witness; agreement is on existence, and the
reported Rust witness is checked independently. Tamper tests alter alphabets,
keys, equations, components, primer lists, and budgets. Separate tests exercise
local contradictions, global infeasibility, successful packing, and the
difference between infeasibility and budget exhaustion.

Both implementations were written by the same project coordinator. Their
different algorithms and complete witness checks reduce shared-error risk, but
this remains short of the research plan's fresh-context A7 review.

## Preserved run

The [completed run](../results/FEASIBILITY-0001/run-001/completion.json) took
approximately **0.198 seconds** with the existing build cache, including an
offline release build, Rust solution, Python verification, baseline regression,
and primer-report regression. Maximum child RSS was **30,564 KiB**; this is an
OS child-process maximum and not a controlled memory benchmark.

Preserved artifacts include:

- [run manifest](../results/FEASIBILITY-0001/run-001/manifest.json), including
  tool versions and all implementation hashes;
- [full witness report](../results/FEASIBILITY-0001/run-001/feasibility.json),
  containing components, alphabets, offsets, keys, and equations;
- [independent verification](../results/FEASIBILITY-0001/run-001/verification.json),
  containing both decisions and search accounting for every primer; and
- [completion record](../results/FEASIBILITY-0001/run-001/completion.json),
  including command, timing, memory, and artifact hashes.

The full witness report SHA-256 is
`b08b50937dbd77972bdad40c7fda0957df7c49b4d9884421b0e793ac55f211b5`.
The reproduced baseline and primer reports remain byte-identical to their
registered hashes. No random generator, external solver, corpus, or network
access is involved.

## Validation

The full validation record is preserved in
[milestone-6-validation.json](milestone-6-validation.json). All required checks
pass:

- formatting and Clippy with pedantic warnings denied;
- **117 Rust unit/integration tests and nine doctests**;
- a separate doctest run and documentation generation with warnings denied;
- the declared Rust 1.85 offline compatibility check; and
- **81 Python tests** across every verifier.

No dependency, unsafe block, or warning suppression was added. New tests cover
local and global infeasibility, independent components, wrapping coordinates,
planted alphabet pairs, input and budget bounds, complete batch output, direct
CLI failure behavior, altered witnesses, false proofs, and incomplete searches.

## Interpretation and remaining work

Milestone 3 showed that 39 primers pass conditions internal to each graph
component. This milestone shows that the components can also coexist in both
complete alphabets for every primer. The result is positive evidence about
mathematical consistency and negative evidence about the discriminatory power
of this unconstrained model: arbitrary independent alphabets leave too much
freedom to select a smaller primer set.

The result does not:

- enumerate every compatible alphabet pair;
- show that either witness alphabet has a keyword construction;
- decode or authenticate the unknown plaintext;
- establish the standard ACA Gromark procedure;
- calibrate a language search on planted examples; or
- establish that Sanborn used this recurrence family.

The next bounded recurrence work package should constrain the two alphabets to
registered, historically or structurally motivated constructions—beginning
with A–Z, KRYPTOS-deduplicated, reversed, and documented tableau variants—and
test the complete 39-primer set without language-score tuning. Any later keyword
search needs a frozen dictionary, exact construction rules, planted-cipher
recovery benchmarks, and a complete null selection procedure.

The broader statistical battery, additional null ensembles, unresolved source
access, and fresh independent review remain open plan gates.

The immediate structured-alphabet handoff is now complete in
[milestone 7](milestone-7.md). All 16,224 combinations of the four registered
forward/reversed A-Z and KRYPTOS orders, ordered plaintext/ciphertext pairs, and
relative rotations are exactly incompatible with at least one crib equation.
