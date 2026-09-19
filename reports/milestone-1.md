# Milestone 1 — frozen evidence and exact baseline diagnosis

Completed 17 September 2026 UTC (16 September America/New_York).

The first milestone is a reproducible baseline for research: source-linked data,
an initial evidence audit, and independently checked exact exclusions. **No K4
plaintext, complete key, or historical encryption procedure was recovered.**
This completes the bounded milestone announced for this session, not every task
in Phase 0 or the full Phase 1 cipher machinery gate.

## Deliverables and acceptance

| Deliverable | Accepted evidence |
| --- | --- |
| Frozen ciphertext and anchors | [K4-v1](../evidence/k4.json): 97 uppercase letters, 4/31/31/31 physical fragments, 24 distinct fixed plaintext positions, explicit zero-based half-open ranges |
| Provenance | [42 source records](../evidence/sources.jsonl), [44 statements](../evidence/statements.jsonl), complete internal source/claim references; repeated URLs do not count as independent confirmation |
| Research audit | [Current status](current-status.md), [prior-work matrix](prior-work.md), [reference collection](../evidence/reference-material.json) with separate inscribed/corrected K2 and unresolved physical/Morse observations |
| Rust harness | Strict evidence validation; JSON diagnostics with assumptions, contradiction witnesses, letter counts and all 24 anchored-position traces |
| Independent computations | [Python reference](../verification/verify_baseline.py) derives all results using pairwise constraints and verifies every Rust certificate; [review scope](independent-verification.md) |
| Registered experiment | [K4-D-0001](../experiments/K4-D-0001.json), [run-001 completion](../results/K4-D-0001/run-001/completion.json), [append-only registry](../experiments/registry.jsonl) |

The exact manifest SHA-256 is
`d43c5020ce4f11dd58ae406346860267dbdc16f06c9203103ae0a18c40eb79bf`.
The other evidence files are frozen in [SHA256SUMS](../evidence/SHA256SUMS)
and in the experiment specification. Changes invalidate dependent runs until
explicitly registered and rerun. Source hashes are null when an original document
was not locally preserved; the evidence-file hashes do not claim otherwise.

## Results and precise scope

1. **Pure transposition rejected:** the three anchored E's at human positions
   22, 31 and 65 exceed the ciphertext's two E's. This assumes a permutation of
   exactly these 97 symbols with no substitution, addition, omission or padding.
2. **Fixed monoalphabetic maps rejected:** E maps to multiple ciphertext letters;
   Q also decrypts to distinct anchored plaintext letters. These are direct,
   aligned single-letter maps, not changing or compound mechanisms.
3. **Ordinary A–Z repeating additive Vigenère:** all 97 periods were evaluated
   for $C_i\equiv P_i+K_{i\bmod t}\pmod{26}$, where $i$ is a zero-based
   position, $t$ the period, and letters and key symbols are standard A–Z
   indices. Periods 1–26 and 30–52 fail: **49 exact
   rejections**. Periods 27–29 and 53–97 survive: **48 necessary-condition
   survivors**, not recovered keys. Reports include unconstrained slot counts.
4. **IC reproduced:** $336/9312\approx0.03608247422680412$, from the 97-letter
   ciphertext's repeated-letter count over its ordered distinct-position
   count. No p-value or cipher
   classification is inferred from this descriptive statistic.
5. **Direct no-self-encryption rejected:** human positions **33 and 74** are
   `S → S` and `K → K`. The plan mentions 74; the harness additionally records
   33. The compact Rust certificate uses the earliest witness; Python enumerates
   both. This does not reject such a restriction on a cipher's internal stage.

The run evaluated four nonperiodic family checks plus 97 periods; no plaintext
candidate search or published primer attack ran. Build, diagnosis, and reference
verification finished in approximately **0.212 seconds** with the existing build
cache. Recorded maximum child RSS was **35,716 KiB** on Linux; this includes build
and verification and is not a simultaneous total or a search throughput benchmark.
All three subprocess stages exited 0. No random seed or significance simulation
is applicable to this exact consistency experiment.

## Validation and limits

All required checks passed: formatting, Clippy with pedantic warnings denied,
28 Rust unit/integration tests, two doctests, explicit documentation tests,
documentation generation with warnings denied, and 35 Python tests. The code
also passed an offline Rust 1.85 build check. Frozen evidence checksums and saved
artifact hashes were checked, and reusing an existing run directory was rejected
without changing its artifacts or the registry.

Tests cover malformed/empty inputs, range boundaries and overflow-sized ranges,
non-ASCII/punctuation, duplicate and overlapping data, all 676 letter pairs,
388 planted period/phase combinations, CLI failures, and forged certificates.
They calibrate exact consistency checks, not a general cryptanalytic recovery
algorithm. No benchmark or audit/deny/nextest configuration exists yet.

Two published transcripts agree, but their historical transcription lineage is
not established as independent. New photographic transcription, original 2020
clue correspondence, current item-level archive access, and the live steward's
verification instructions remain open evidence tasks. The initial source audit
found no authenticated public full plaintext in accessible material; inaccessible
documents remain leads. The full K1–K3 fixture suite and Phase 1 cipher library
have not passed their gates. No external submission, contact or payment occurred.

## Next three work packages

1. **Complete Phase 1 fixture reconstruction:** implement explicit alphabet and
   permutation conventions, independently reproduce K1/K2 (including both K2
   variants), K3's exact permutation, and the ACA Gromark known-answer fixture.
   Gate: independent known answers, inverse/illegal-key tests and position traces.
2. **Reproduce the published primer baseline:** register a separate experiment
   for Bean's pinned code and independently derive its exact constraints.
   Gate: explain the reported 39 survivors and the gap between necessary primer
   filters and a complete alphabet/key solution. Do not count it as new K4 coverage.
3. **Calibrate bounded follow-up attacks and statistics:** after primitive gates,
   register standard/keyed-alphabet and recurrence domains, fresh synthetic
   recovery cases, and width-selection-aware null experiments. Advance only
   domains with measured recovery ability; preserve exact/heuristic distinctions.

Continue source-access follow-ups alongside these packages. Broader searching is
not justified merely by the surviving periods or a fluent proposed plaintext.
