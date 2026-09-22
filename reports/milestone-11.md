# Milestone 11 — classical polyalphabetic schedules

The complete registered census leaves **173 of 2,192 canonical schedule
templates** compatible with K4's 24 known letters: 12 repeating/interrupted,
152 progressive, and 9 autokey. Every survivor has an exact 97-letter witness,
but the witness fills unconstrained seed letters with `A`; none is a claimed
plaintext or a ranked candidate.

## Scope and canonical domain

This milestone tests standard A–Z on aligned positions only. The
[versioned conventions](../docs/classical-schedule-conventions-v2.md) freeze periods and seed
lengths 1–32, all three classical equations, progressive increments,
plaintext/ciphertext feedback, and at most two resets from positions 4, 35,
and 66.

The raw domain contains 65,856 parameter tuples. Vigenère and variant Beaufort
free streams are equivalent by key negation; phase renames seed coordinates;
progressive origin is absorbed into the seed; and increment zero is a repeating
schedule. Deduplicating 224 period/reset descriptions gives 200 coordinate maps
on 97 positions.

| Family | Canonical templates |
| --- | ---: |
| Repeating/interrupted: 200 maps × 2 equation classes | 400 |
| Progressive: 32 periods × 25 nonzero increments × 2 classes | 1,600 |
| Autokey: 32 lengths × 2 feedback types × 3 equations | 192 |
| **Total** | **2,192** |

The solver derives required seed residues instead of enumerating $26^t$ keys.
Contradictory residues reject a template. A survivor with $f$ untouched seed
coordinates records multiplicity $26^f$. Plaintext autokey uses affine
expressions so constraints propagate through unknown-letter gaps.

```mermaid
flowchart LR
    C[24 aligned known letters] --> R[Derive modular seed constraints]
    R --> X{Contradiction?}
    X -->|yes| E[Reject template]
    X -->|no| S[Keep fixed and free coordinates]
    S --> W[Build zero-filled witness]
    W --> V[Reencrypt all 97 positions]
```

## Blind calibration

[CLASSICAL-SCHEDULES-0005](../experiments/CLASSICAL-SCHEDULES-0005.json) used a
fresh committed 256-bit seed. Its controller generated 120 positives, balanced
40/40/40 across coordinate-map, progressive, and autokey families, plus 40
tamper negatives. The public input held only ciphertext and 24 cribs; private
truth stayed outside the run directory until the Rust attacker exited.

The cohort covers periods 1/32, phases 0/$t-1$, origins 0/25, increments 1/25
and the increment-zero alias, both free-stream signs, every autokey equation and
feedback type, and all seven reset subsets. The independent Python
implementation regenerated all cases, enumerated exact survivor sets and order,
and reencrypted every witness.

| Gate | Result |
| --- | ---: |
| Planted positive retained | **120/120** |
| Tamper excludes planted template | **40/40** |
| Independent exact survivor agreement | **160/160** |
| Unknown cases | **0** |
| Canonical template checks | **350,720** |

The accepted [verification](../results/CLASSICAL-SCHEDULES-0005/run-001/verification.json)
records the gates. No top-one metric applies because this attack returns exact
compatibility classes and has no language ranker.

Earlier generations remain preserved as audit history. CLASSICAL-SCHEDULES-0001
used a noncanonical variant-Beaufort ID, and 0002 used a tamper that a free seed
coordinate could absorb. CLASSICAL-SCHEDULES-0003 and its dependent K4-0001
are superseded because the controller did not prove raw-model reencryption, the
operation cap described a different unit, and K4 provenance validation was
incomplete. CLASSICAL-SCHEDULES-0004 and K4-0002 corrected those defects but
were then superseded: autokey truth records carried an ignored `phase`, phase
coverage was not family-specific, and the K4 verifier accepted mutations to
registered manifest and result metadata. Run 0005 removes the inapplicable
field, reports phase endpoints separately for repeating and progressive
families, uses a fresh commitment, and checks the complete output contract.

## K4 result and limits

After the gate passed, the registered
[K4 run](../results/CLASSICAL-SCHEDULES-K4-0003/run-001/completion.json) checked
all 2,192 templates. Independent
[verification](../results/CLASSICAL-SCHEDULES-K4-0003/run-001/verification.json)
confirmed all **173** survivors in order and reencrypted every witness, with no
timeouts or unknowns. The verifier also binds every registered manifest field,
the calibration paths and hashes, all aggregate census metadata, the per-case
template count, and the exact survivor objects.

The result rejects only the 2,019 templates contradicted under this aligned,
standard-alphabet domain. The survivors are underdetermined compatibility
classes for later scoring or cross-clue work. They say nothing about routes,
alternative alphabets, or historical plausibility, and template counts are not
counts of all represented concrete key streams.

```bash
cargo run --release --locked -- classical-schedules fixtures/classical-schedules-request.json
python3 verification/verify_classical_k4_v3.py \
  results/CLASSICAL-SCHEDULES-K4-0003/run-001
```
