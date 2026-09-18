# Milestone 8 — calibrated keyword alphabets

Completed 2026-09-18 and corrected by an explicit unblinded amendment. The bounded handoff from
[milestone 7](milestone-7.md) is complete: none of the 39 registered decimal
primers satisfies all 24 aligned K4 crib equations when both alphabets are
chosen from the registered KRYPTOS, PALIMPSEST and ABSCISSA constructions at
any relative rotation.

| Outcome | Models |
| --- | ---: |
| Exactly rejected | **146,016** |
| Compatible survivors | **0** |
| Total physical domain | **146,016** |

This is an exact exclusion for the frozen finite family. It does not exclude
other keywords, dictionaries, tableau conventions, key offsets, recurrences,
transpositions or compound mechanisms, and it does not recover plaintext.

`KEYWORD-ALPHABETS-0001/run-001` first observed the zero-survivor result, but a
review found that its purported full-message reencryption gate simply invoked
the forward transform a second time. It neither decrypted ciphertext nor
compared recovered plaintext, and its operation cap omitted the missing work.
That immutable run and registration are retained as **superseded historical
records**. The final evidence is the `KEYWORD-ALPHABETS-0002` amendment. Because
the K4 result was already known, this correction is unblinded and makes no
claim of restored preregistration blindness.

## Frozen domain

[KEYWORD-ALPHABETS-0002](../experiments/KEYWORD-ALPHABETS-0002.json) binds the
evidence, 39-primer report, milestone-6 feasibility report, milestone-7 result,
request and [amended model conventions](../docs/keyword-alphabet-conventions-v2.md) by
SHA-256. The recurrence and equation remain:

```text
k[i] = (k[i-5] + k[i-4]) mod 10
c(C_i) - p(P_i) = k[i] mod 26
```

The three candidate words have explicit provenance and roles. `KRYPTOS` is the
sculpture tableau keyword. `PALIMPSEST` and `ABSCISSA` are K1 and K2 indicator
words repurposed as declared K4 hypotheses; their reuse is not evidence about
K4. `ENIGMA` is retained only as the published ACA construction control.

Each candidate word supplies an ordinary deduplicated keyword-fill alphabet
and an ACA Gromark transposed alphabet. Both forward and reversed orientations
produce 12 literal orders that are also distinct up to rotation. Every ordered
plaintext/ciphertext pair and all 26 relative ciphertext rotations are tested
for each primer. A proven common-rotation symmetry fixes plaintext rotation to
zero. Thus 39 × 12 × 12 × 26 = **146,016** physical models are retained, even
when different physical models share a crib signature.

The planner's preregistration probe inspected domain structure but did not
compare this expanded family with K4. It found 123,552 signatures: 101,088
singleton buckets and 22,464 doubletons. Therefore 69.2308% of physical models
are uniquely identified by a complete 24-letter signature. The disclosed
collision joins the 54258 KRYPTOS keyword-fill reversed pair at rotation 16
with the 56852 KRYPTOS keyword-fill forward pair at rotation zero.

## Calibration gate

The `keyword-calibrate` command runs before, and separately from, K4. It first
regenerates the exhaustive signature census. It then creates 144 deterministic
97-letter planted cases, one for every ordered base-order pair, using the
registered xorshift32 stream and assignment rules. Random letters at the 24
crib positions are replaced by the frozen known plaintext before encryption.
Recovery receives the ciphertext and those 24 positions only. It locates the
true candidate ID in the returned set, decodes that ID, reconstructs its model,
decrypts all 97 positions through a separate inverse path, compares the
recovered plaintext, and reencrypts that recovered text. It does not retain the
model object used to construct the planted ciphertext.

| Calibration result | Cases |
| --- | ---: |
| True physical candidate retained | **144 / 144** |
| Full 97-letter plaintext recovery | **144 / 144** |
| Recovered-plaintext reencryption | **144 / 144** |
| Singleton physical recovery | **98 / 144** |

Unique recovery is descriptive rather than a gate because the registered
domain contains genuine signature collisions. K4 evaluation rejects a missing,
failed or byte-different calibration report and regenerates the full report
before inspecting K4.

The amended evaluator reports every primary operation. Its exact total is
7,050,672: 3,504,384 signature equations, 13,968 planted encryption positions,
13,968 planted decryption positions, 13,968 planted reencryption positions, and
3,504,384 K4 equations. The runner rejects missing counters, an incorrect sum,
or a total above the registered cap.

## K4 result and certificates

The gated evaluator checked all 24 equations for every model, for exactly
**3,504,384** K4 equation evaluations. Its complete score histogram is:

| Matching cribs out of 24 | Models |
| ---: | ---: |
| 0 | 59,424 |
| 1 | 51,878 |
| 2 | 24,223 |
| 3 | 8,017 |
| 4 | 2,039 |
| 5 | 364 |
| 6 | 64 |
| 7 | 7 |

No model matches more than seven cribs. The seven tied best models span seven
primers and several construction pairs. This score audits complete coverage;
it was not used to tune or extend the frozen family.

[`keyword_alphabets`](../src/keyword_alphabets/mod.rs) validates the exact
primer and provenance-bound keyword domain, derives both constructors, indexes
every physical model, performs calibration, and emits a compact complete K4
certificate. Parallel arrays preserve the match count and first mismatching
crib ordinal for every canonical index. A survivor would additionally retain
both full alphabets, the 97-digit key, and all 24 equation traces.

[`verify_keyword_alphabets.py`](../verification/verify_keyword_alphabets.py)
does not call Rust. It independently derives keyword orders, recurrence keys,
signature buckets, planted messages, recovery sets, reencryption checks,
canonical indices, compact K4 arrays, histogram and survivor traces. Tamper
tests alter request provenance, numeric types, calibration recovery sets,
certificate cells, histograms, index encoding and survivor equations.

## Preserved run and interpretation

The immutable amended [production run](../results/KEYWORD-ALPHABETS-0002/run-001/completion.json)
includes an offline release build, current-binary foundations regression,
calibration, K4 evaluation, independent verification, and byte-identical
baseline, primer, feasibility and milestone-7 regressions. The foundations
stage reproduces the five preserved known-answer traces and all 600 seeded
synthetic message pairs byte-for-byte.

The main artifacts are:

- the [run manifest](../results/KEYWORD-ALPHABETS-0002/run-001/manifest.json),
  including tool versions and implementation hashes;
- the [calibration report](../results/KEYWORD-ALPHABETS-0002/run-001/calibration.json),
  SHA-256 `44a40b9b4feba3be311daa36719dd0097d88a4c58760a773526509715e5b4580`;
- the [complete K4 certificate](../results/KEYWORD-ALPHABETS-0002/run-001/keyword-alphabets.json),
  SHA-256 `a79d83e3ce787bf6e048244e0aa4f23815f7ea24e7bf4c000a6ce2676a9bcc56`;
  and
- the [independent verification](../results/KEYWORD-ALPHABETS-0002/run-001/verification.json).

No corpus, dictionary, language score, network service, external solver or
external spend was used. The independently derived Python verifier was written
inside the same coordinated project, so this is a strong implementation
cross-check rather than the plan's external fresh-context A7 review.

The complete [validation record](milestone-8-validation.json) preserves the
required formatting, Clippy, test, documentation and minimum-toolchain checks.
All 141 Rust unit and integration tests, 9 doctests and 99 Python tests pass.

The result narrows one historically motivated recurrence branch. It says that
these three words, these two alphabet constructors, reversal, and relative
rotation cannot jointly explain the known K4 letters with any registered
primer. It does not rank untested words or constructions. The next bounded
branch should freeze a distinct documented tableau construction or structured
key schedule and calibrate recovery before K4 evaluation.
