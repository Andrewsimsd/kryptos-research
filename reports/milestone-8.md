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
records**. `KEYWORD-ALPHABETS-0002` corrected the inverse path, but its
coordinator accounting omitted the evaluator's internal second calibration.
The final evidence is `KEYWORD-ALPHABETS-0003`, which also places independent
calibration verification before K4. Because the K4 result was already known,
these corrections are unblinded and make no claim of restored preregistration
blindness.

## Frozen domain

[KEYWORD-ALPHABETS-0003](../experiments/KEYWORD-ALPHABETS-0003.json) binds the
evidence, 39-primer report, milestone-6 feasibility report, milestone-7 result,
request and [final model conventions](../docs/keyword-alphabet-conventions-v3.md) by
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
Recovery receives the ciphertext and those 24 positions only. The test then
uses the known planted candidate ID to locate it in the returned set, decodes
that ID, reconstructs its model,
decrypts all 97 positions through a separate inverse path, compares the
recovered plaintext, and reencrypts that recovered text. It does not retain the
model object used to construct the planted ciphertext.

| Calibration result | Cases |
| --- | ---: |
| True physical candidate retained | **144 / 144** |
| Known-true-model 97-letter round trip | **144 / 144** |
| Recovered-plaintext reencryption | **144 / 144** |
| Singleton physical recovery | **98 / 144** |

Unique recovery is descriptive rather than a gate because the registered
domain contains genuine signature collisions. The other 46 cases are transform
and retention tests, not blind key recovery. Python independently regenerates
the calibration before K4 begins; the evaluator then rejects a missing, failed,
or byte-different report and regenerates it internally.

One calibration performs 3,546,288 primary operations: 3,504,384 signature
equations and three 13,968-position planted transforms. The coordinator produces
one calibration, and the evaluator independently regenerates another before
performing 3,504,384 K4 equations. The actual execution total is therefore
**10,596,960**. The earlier 7,050,672 figure described one logical calibration
plus K4 and omitted the evaluator's second calibration pass. These are the
primary Rust operations governed by the registered operation cap.
Python performs 3,546,288 operations before search and 7,050,672 afterward, so
the [combined keyword workload](milestone-8-workload-clarification.md) is
**21,193,920**. Builds, JSON work, and regression stages remain outside this
scientific unit and inside the wall-time cap.

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

The immutable final [production run](../results/KEYWORD-ALPHABETS-0003/run-002/completion.json)
includes an offline release build, current-binary foundations regression,
calibration, K4 evaluation, independent verification, and byte-identical
baseline, primer, feasibility and milestone-7 regressions. The foundations
stage reproduces the five preserved known-answer traces and all 600 seeded
synthetic message pairs byte-for-byte.

The main artifacts are:

- the [run manifest](../results/KEYWORD-ALPHABETS-0003/run-002/manifest.json),
  including tool versions and implementation hashes;
- the [calibration report](../results/KEYWORD-ALPHABETS-0003/run-002/calibration.json);
- the [pre-search independent gate](../results/KEYWORD-ALPHABETS-0003/run-002/calibration-verification.json);
- the [complete K4 certificate](../results/KEYWORD-ALPHABETS-0003/run-002/keyword-alphabets.json);
  and
- the [independent verification](../results/KEYWORD-ALPHABETS-0003/run-002/verification.json).

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
