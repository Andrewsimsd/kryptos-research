# Keyword-alphabet conventions, amendment 2

This document registers `KEYWORD-ALPHABETS-0002`. It preserves the complete
candidate domain in [the original conventions](keyword-alphabet-conventions.md)
and amends its calibration gate and operation accounting.

`KEYWORD-ALPHABETS-0001/run-001` had already observed the K4 result before this
amendment was designed. That run is retained as a superseded historical record:
its purported reencryption gate invoked the same forward transformation twice,
so it never recovered plaintext through an inverse path, and its operation cap
omitted planted decryption and final reencryption. The amendment is therefore
an unblinded correction and regression, not a preregistered first look at K4.

## Preserved model domain

The candidate domain is unchanged: the same exact 39 primers; KRYPTOS,
PALIMPSEST and ABSCISSA with the same provenance; keyword-fill and ACA Gromark
transposed constructors; forward and reversed orders; every ordered pair of
the 12 base orders; and all 26 relative ciphertext rotations. The same 24
aligned crib equations and offset-zero decimal recurrence are used. There are
146,016 physical models and 3,504,384 K4 equation evaluations.

ENIGMA remains a construction known-answer control and is not a K4 candidate.
Physical candidate identities remain distinct across signature collisions.

## Corrected full-message calibration

The signature census and 144 deterministic planted cases are unchanged. For
each case the evaluator:

1. constructs the planted ciphertext with the true physical model;
2. obtains a set of candidate IDs from the ciphertext at only the 24 frozen
   known-plaintext positions;
3. confirms the true physical ID is retained, then locates that ID in the
   recovered set;
4. decodes the ID and reconstructs its primer, alphabets and rotation rather
   than retaining the model object used for construction;
5. decrypts all 97 ciphertext positions through a separately implemented
   inverse path and compares the result with the planted plaintext; and
6. reencrypts the recovered plaintext and compares all 97 output positions
   with the planted ciphertext.

Set-valued true-model retention, exact plaintext recovery and final
reencryption are separate reported gates. All 144 cases must pass all three.
Unique signature recovery remains descriptive and is not required.

The Python verifier independently reconstructs candidate IDs, performs its own
inverse transformation, checks the recovered plaintext, reencrypts it, and
regenerates the complete Rust report. Wrong-model and altered-ciphertext tests
must fail plaintext recovery even though an internally reversible wrong model
can reencrypt its own decrypted text.

## Exact operation accounting

The registered primary-operation unit counts one evaluated crib equation or
one transformed planted-message position. The exact cap is **7,050,672**:

| Operation | Count |
| --- | ---: |
| Signature-census equations | 3,504,384 |
| Planted encryption positions | 13,968 |
| Planted decryption positions | 13,968 |
| Planted reencryption positions | 13,968 |
| K4 crib equations | 3,504,384 |
| **Total** | **7,050,672** |

Both implementations emit these counters. The coordinator sums them, rejects
any missing or changed unit, and fails if the sum differs from or exceeds the
registered cap.

## Foundations regression

The amendment executes the current Rust binary against the five published
known-answer pairs and the deterministic 600-message-pair synthetic suite from
`FOUNDATIONS-0001/run-002`. The generated full fixture traces and verification
summary must be byte-identical to that preserved run. The experiment
registration binds the source fixture, preserved reference outputs, seed,
case count, and all per-family generated request and output digests.

## Interpretation

The original K4 result was known before this correction, so the amended run
cannot restore prospective blindness. Its purpose is to determine whether the
result survives a meaningful recovery gate, an independent inverse
implementation, exact accounting and current-code foundations regression. A
zero-survivor result still excludes only the unchanged finite family.
