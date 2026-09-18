# Keyword-alphabet conventions

This document freezes `KEYWORD-ALPHABETS-0001` before its production K4 run.
It extends Milestone 7 with a finite, provenance-bound keyword family. It does
not search a dictionary or infer unknown plaintext.

## Candidate keywords and provenance

Only three words are K4 candidates:

| ID | Word | Frozen source | Experimental role |
| --- | --- | --- | --- |
| `kryptos` | `KRYPTOS` | S210 | Keyword printed in the sculpture tableau |
| `palimpsest` | `PALIMPSEST` | S203 | K1 indicator word, repurposed as a K4 alphabet hypothesis |
| `abscissa` | `ABSCISSA` | S203 | K2 indicator word, repurposed as a K4 alphabet hypothesis |

The last two roles are hypotheses, not evidence that those words were reused
for K4. `ENIGMA` remains only the existing ACA construction known-answer test
and is not evaluated as a K4 candidate.

## Constructors and orientations

Each keyword produces two forward orders:

1. `keyword_fill`: deduplicate in first-occurrence order, then append unused
   A-Z letters.
2. `aca_gromark_transposed`: deduplicate to `D`; form the keyword-fill alphabet;
   write it rowwise at width `len(D)`; read ragged columns in alphabetical order
   of the letters in `D`.

Each order is evaluated forward and completely reversed. The resulting 12
orders must be distinct both literally and up to rotation. The request is
rejected otherwise.

## Candidate domain and indexing

The recurrence and crib equation remain:

```text
k[i] = (k[i-5] + k[i-4]) mod 10
c(C_i) - p(P_i) = k[i] mod 26
```

The exact domain is 39 registered primers × 12 plaintext base orders × 12
ciphertext base orders × 26 relative ciphertext left rotations = **146,016**
physical candidates. Plaintext rotation is zero by the proven common-rotation
symmetry. Key offset is zero. All 24 aligned cribs are checked.

The canonical index is:

```text
((((primer_index * 12) + plaintext_base_index) * 12
  + ciphertext_base_index) * 26) + ciphertext_rotation
```

All component indices are zero-based and follow request/derived-order sequence.
The K4 report preserves one match count and one nullable first-mismatch crib
ordinal at every canonical index. Physical identities remain separate even when
two candidates have the same 24-letter signature. Full traces are preserved
for every survivor.

## Calibration gate

K4 evaluation requires a separately emitted calibration report and regenerates
it exactly before search. Calibration has two parts:

1. Enumerate the 24 predicted ciphertext letters for all 146,016 candidates and
   retain complete signature buckets, including physical collisions.
2. Generate 144 deterministic 97-letter planted plaintexts, one for every
   ordered base-order pair. Use xorshift32 shifts 13,17,5 with seed 1263222081
   and `next_u32 mod 26` letter selection. Case `n` uses primer `n mod 39`,
   rotation `n mod 26`, plaintext base `n / 12`, and ciphertext base `n mod 12`.
   Random letters at the 24 crib positions are overwritten with the frozen
   known plaintext before encrypting all 97 letters.

Recovery receives the planted ciphertext and the 24 known plaintext positions
only. It looks up the observed crib signature and must retain the exact physical
true candidate. The separately retained planted plaintext is used only to check
full 97-letter reencryption. Unique recovery is reported separately and is not
a gate. K4 evaluation is blocked unless all 144 true candidates are retained,
all 144 full reencryption checks pass, and Rust exactly regenerates the supplied
calibration report.

## Registration disclosure and limits

Before implementation, the planner performed a read-only structural design
probe. It reported 123,552 signatures, 101,088 singleton buckets, 22,464
doubleton buckets, and 101,088 / 146,016 = 69.2308% physically unique
candidates. An example collision was a 54258 KRYPTOS keyword-fill reversed pair
at rotation 16 with a 56852 KRYPTOS keyword-fill forward pair at rotation zero.
The planner did not evaluate the expanded domain against K4.

The frozen operation cap is **7,022,736**: 3,504,384 signature equations,
13,968 planted full-message encryption positions, and 3,504,384 K4 crib
equations. There is no language score, dictionary, plaintext inference,
transposition, alternate recurrence, alternate offset, constructor expansion,
or tuning after the K4 result. A zero-survivor result excludes only this exact
family. A survivor would establish crib compatibility only.
