# Milestone 7 — registered structured alphabets

Completed 2026-09-17. The bounded handoff from
[milestone 6](milestone-6.md) is complete: none of the 39 registered decimal
primers satisfies all 24 aligned crib equations when both alphabets are limited
to A-Z or the KRYPTOS-deduplicated order, independently forward or reversed,
at any relative rotation.

| Outcome | Models |
| --- | ---: |
| Exactly rejected | **16,224** |
| Compatible survivors | **0** |
| Total canonical domain | **16,224** |

This is an exact exclusion for the registered family. It does not exclude other
keyword alphabets, tableau conventions, recurrences, offsets, transpositions or
compound mechanisms, and it does not recover plaintext.

## Registered domain

[STRUCTURED-ALPHABETS-0001](../experiments/STRUCTURED-ALPHABETS-0001.json)
binds the exact primer report, preceding feasibility report, request, evidence,
and [model conventions](../docs/structured-alphabet-conventions.md) by SHA-256.
For each primer, the same offset-zero decimal recurrence is used:

```text
k[i] = (k[i-5] + k[i-4]) mod 10
c(C_i) - p(P_i) = k[i] mod 26
```

The four registered orders are standard A-Z, reversed A-Z, the deduplicated
`KRYPTOSABCDEFGHIJLMNQUVWXZ` order, and its reversal. The evaluator covers all
16 ordered plaintext/ciphertext pairs and all 26 left rotations of the
ciphertext alphabet. Plaintext rotation is fixed at zero because rotating both
alphabets by the same amount preserves every index difference. The resulting
domain has 39 × 4 × 4 × 26 = 16,224 distinct models.

Every model evaluates all 24 equations, even after a mismatch. This produces
exactly **389,376** equation evaluations and the complete score histogram:

| Matching cribs out of 24 | Models |
| ---: | ---: |
| 0 | 6,683 |
| 1 | 5,694 |
| 2 | 2,627 |
| 3 | 935 |
| 4 | 214 |
| 5 | 59 |
| 6 | 12 |

No model matches more than six cribs. The 12 best models are spread over five
primers and several construction pairs and rotations; the score was retained
to audit coverage, not used to extend or tune the family.

The registration discloses an exploratory read-only Python probe that had
examined only relative rotation zero. It found zero survivors, a best score of
6/24, and histogram `0:264, 1:225, 2:87, 3:38, 4:6, 5:3, 6:1`. Rotations 1–25
had not been inspected. The observation was frozen before the production run
and did not change its domain.

## Certificates and independent verification

[`structured_alphabets`](../src/structured_alphabets/mod.rs) contains the pure
equation evaluator; its strict [batch layer](../src/structured_alphabets/batch.rs)
validates complete Cartesian coverage and produces stable candidate IDs. Each
rejected model records its primer, both construction IDs, relative rotation,
total match count, and earliest true mismatch with letters, indices, key digit,
observed residue and required residue. A survivor schema also exists and would
retain the complete alphabets, expanded key and all 24 equations.

[`verify_structured_alphabets.py`](../verification/verify_structured_alphabets.py)
does not call Rust. It independently reconstructs all recurrence streams,
alphabet index maps, rotations, equations and canonical identities. It checks
all rejection certificates, the full histogram, exact model coverage, and any
survivor trace. Tamper tests modify identities, primers, rotations, indices,
keys, match counts, positions, histogram cells, coverage and every request
domain. Each mutation is rejected.

Both implementations were produced within the same coordinated project. This
is an independent algorithmic cross-check, not the research plan's fresh-context
A7 verification.

## Preserved run

The final [completed run](../results/STRUCTURED-ALPHABETS-0001/run-002/completion.json)
took approximately **2.40 seconds**, including an offline release build,
evaluation, independent verification and three upstream regressions. Its
reported child-process high-water mark was **300,612 KiB**; this includes the
release build and is not a controlled memory benchmark.

The main preserved artifacts are:

- the [run manifest](../results/STRUCTURED-ALPHABETS-0001/run-002/manifest.json),
  including tool versions and implementation hashes;
- all [16,224 decisions](../results/STRUCTURED-ALPHABETS-0001/run-002/structured-alphabets.json),
  SHA-256 `301428c028c3e8d44a071b5df9bc5f142f8ce1abb1c40aaa03f0952520109ea0`;
- the [independent verification](../results/STRUCTURED-ALPHABETS-0001/run-002/verification.json);
  and
- byte-identical baseline, primer, and milestone-6 feasibility regressions in
  the same immutable run directory.

No random generator, corpus, language model, dictionary, network service or
external solver was used. The run used no external spend.

The preserved `run-001` remains immutable. `run-002` records the final reviewed
implementation, including strict rejection of JSON booleans in every numeric
field, modulo-26 boundary tests for arbitrary byte-valued keys, and planted
full-batch survivor tests through both implementations. Its K4 decision artifact
is byte-identical to `run-001`.

## Validation and interpretation

The complete validation record is preserved in
[milestone-7-validation.json](milestone-7-validation.json). Formatting, Clippy
pedantic, all Rust tests, doctests, rustdoc warnings, the Rust 1.85 offline check,
and every Python verifier test pass.

Milestone 6 showed that arbitrary independent alphabet permutations are broad
enough to accommodate every surviving primer. This milestone shows that the
four simplest historically motivated explicit orders are too restrictive:
none accommodates even the 24 known letters under this exact recurrence.
Together those results locate the remaining uncertainty between a very broad
free-alphabet family and this small fixed family; they do not establish that an
intermediate keyword family was used.

That bounded handoff is completed by [milestone 8](milestone-8.md): its keyword
sources, construction rules and offsets were frozen, its complete physical
domain passed planted calibration, and all 146,016 registered K4 models were
then rejected.

The next bounded branch should preregister a distinct documented tableau rule
or structured key schedule and calibrate it on planted examples before K4.
The broader statistical battery, other null ensembles, unresolved source
access and fresh external A7 review remain open.
