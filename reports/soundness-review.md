# Project soundness review

Review date: 18 September 2026.

## Conclusion

The preserved evidence and completed fixed/keyword-alphabet exclusions are
internally consistent: none of the 16,224 milestone-7 or 146,016 milestone-8
models survives all 24 known letters. Other completed necessary-condition tests
have survivors, including all 39 arbitrary-alphabet feasibility instances. The
preliminary integrity pass found no corruption in 190 artifact hashes across
the 15 completion records that existed before the corrective production run.
It also independently recomputed
the milestone-8 K4 match arrays with a direct rotation-residue method: all
146,016 match counts and first-mismatch positions agreed, the best score was
7/24 for seven models, and there were no survivors. This is another
same-coordinator cross-check, not external authentication.

Two milestone-8 claims required correction:

1. The runner produced a calibration and the evaluator regenerated it. The
   earlier 7,050,672 count represented one calibration plus K4, but actual
   primary Rust execution performed two calibrations plus K4: **10,596,960**
   registered equation/position operations. Python verification performs the
   same amount again, for **21,193,920** combined keyword operations.
2. All 144 planted cases retained and round-tripped the known true model, while
   only 98 produced a singleton candidate set. The transform check is sound,
   but the ambiguous cases are not blind model recovery.

`KEYWORD-ALPHABETS-0003` preserves the model and result, corrects both labels,
adds the omitted accounting, and requires an independent Python calibration
gate before K4 evaluation. Earlier registrations and artifacts remain immutable
historical records.

## What was checked

- Frozen evidence shape, crib coordinates, source references, and registered
  input hashes.
- Rust/Python agreement, known-answer fixtures, complete-domain counters,
  compact rejection certificates, and runner fail-closed behavior.
- Primer, width-scan, arbitrary-alphabet feasibility, and keyword-domain
  counting arguments at their principal boundaries.
- Every preserved completion artifact hash, every manifest's registered input
  hash, and every completion hash in the append-only registry.
- README claims against reports and machine-readable outputs.

The repeatable command is:

```bash
python3 verification/audit_repository.py
```

The live command is the source of current counts as new immutable runs are
added. The final commands and observed counts for this review are recorded in
[the validation record](soundness-review-validation.json). The preliminary
190/15 figures above intentionally describe the state when the defect was found.

The audit intentionally does not compare a historical manifest's implementation
hashes with today's checkout. Those hashes record the code used then; current
code is expected to evolve. It also cannot authenticate inaccessible source
documents or prove that an untested cipher family is impossible.

## Claim boundaries that remain important

- “Exhaustive” always applies to a stated finite family. It never means every
  possible encryption method.
- The 39 arbitrary-alphabet feasibility witnesses show that the known letters
  do not contradict that flexible model. They are not candidate solutions.
- The width-21 result is adjusted for choosing among widths 1–48 under its
  registered permutation null. It does not correct for every pattern anyone
  may have inspected historically.
- Rust and Python were developed in one project. A serious positive candidate
  still needs a clean-room implementation and independent provenance review.
- Current public status can change. The evidence audit has explicit access
  gaps and must be refreshed before making current-status claims.

## Engineering assessment

The Rust core is typed, documented, panic-averse in production paths, and has
strong unit, integration, doctest, and independent-verifier coverage. The
experiment runners preserve inputs and refuse overwrite. The large
`keyword_alphabets` module is cohesive around one bounded experiment; splitting
it now would add churn without changing the scientific result. Future attacks
should be separate modules and registrations rather than extending it into a
general search engine.

The main remaining risk is research breadth, not a known arithmetic defect.
Many historically plausible families have not been tested. The numbered
[future milestones](../docs/future-milestones.md) turn that open-ended space
into bounded, falsifiable work packages.
