# Independent baseline verification

For later work, see [milestone 2](milestone-2.md) and [milestone 3](milestone-3.md).
Their Rust/Python comparisons were separately implemented by the same
coordinator; they do not claim a fresh-context A7 review. Milestone 3 additionally
compares the untouched upstream C program and checks every primer rejection.

[Milestone 4](milestone-4.md) separately implements the fixed-statistic simulation
in Rust and Python, regenerates all one million precision samples, and checks
the original C measurement functions on 10,001 inputs. This is also work by the
same coordinator, with the same fresh-context-review limitation.

[Milestone 5](milestone-5.md) regenerates the width-scan calibration and every
evaluation permutation, checking all 48 histograms and the joint distribution
of selected maxima. Python uses precomputed exact score ranks; Rust compares
signed integer scores directly. The same-coordinator limitation still applies.

[Milestone 6](milestone-6.md) independently reconstructs every primer key and
crib graph, searches global component placements with a different ordering, and
checks both complete alphabet permutations plus all 936 reported equations.
Rust and Python resolve all 39 primers as feasible. This is still a
same-coordinator cross-check rather than the plan's fresh-context A7 review.

[Milestone 7](milestone-7.md) independently re-enumerates the exact 39 × 4 × 4
× 26 structured-alphabet domain in Python, reconstructing all recurrence keys,
index maps, rotations and 389,376 equations. It validates every first-mismatch
certificate and aggregate histogram. Rust and Python agree that all 16,224
models are rejected. The same-coordinator limitation continues to apply.

[Milestone 8](milestone-8.md) independently reconstructs both keyword-alphabet
constructors, all 12 rotation classes, every signature bucket, the xorshift32
planted corpus, all 144 recovery sets and all 3,504,384 K4 equations. In the
amended `KEYWORD-ALPHABETS-0002` run, both implementations decode recovered
candidate IDs, independently decrypt all 97 positions, compare plaintext, and
reencrypt it. The current Rust binary also reproduces the preserved five
known-answer traces and 600 synthetic foundations cases byte-for-byte. Rust and
Python agree that all 146,016 models are rejected after all amended gates pass.
This remains a same-coordinator cross-check rather than external A7.

The saved [Rust diagnosis](../results/K4-D-0001/run-001/diagnosis.json) passes the
[Python reference verifier](../verification/verify_baseline.py), including all
97 periods, complete anchor traces, aggregate counts, IC and every rejection
witness. The [reference output](../results/K4-D-0001/run-001/verification.json)
contains its separately derived conflicts and survivors. This acceptance is for
the scoped baseline calculations only, not a candidate decryption or the full
Phase 1 machinery gate.

The reference core was written by an agent launched in a fresh context with an
explicit instruction not to read `src/`. It received the model equations and JSON
interface, not Rust source or expected result values. Its derivation computes
conflicting pairs directly; Rust records the first required shift for each key
residue. Python checks that a supplied witness is mathematically valid rather
than requiring Rust's choice of the first witness.

That agent's session was interrupted before final integration. The coordinator
completed the Python manifest/ledger readers and CLI, changed the evidence-ID
field name to match the agreed schema, and ran the cross-check. The independent
arithmetic and witness-checking core was retained. Therefore this is an
independent implementation cross-check with coordinator integration, **not an
unqualified claim of a completed fresh-context A7 final review**. Future positive
candidates still require that separate review and a new implementation.

The Python tests include a manually specified three-letter example, the
ATTACKATDAWN/LEMON Vigenère known answer, modular wraparound, empty constraints,
single-letter IC behavior, invalid inputs and deliberately false certificates.
They detect altered counts, omitted periods, invented survivors, wrong mapping
directions, mismatched positions and compatible equations falsely presented as
contradictions. Evidence/ledger tests check disagreements, reference integrity,
duplicate IDs and altered local snapshot hashes. The coordinator tests protect
frozen inputs and prohibit overwriting an artifact.

The cross-check establishes:

- Multiplicity and aligned mapping contradictions are genuine under their
  stated assumptions.
- All periods 1–97 have been checked for the declared additive model; none are
  silently skipped. A surviving period is not a recovered key.
- Both aligned fixed points, human positions 33 and 74, are present.
- IC is the exact integer ratio 336/9312, with its decimal display matching.
- Source/claim references resolve, and each frozen evidence hash matches.

It cannot authenticate the original clues, prove transcript lineage independence,
establish historical cipher attribution, verify inaccessible documents, or
transfer these exclusions to different alphabets or compound mechanisms.
