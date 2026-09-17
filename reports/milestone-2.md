# Milestone 2 — executable cipher foundations and known answers

Completed 17 September 2026 UTC. This completes the **fixture reconstruction**
work package in the [milestone-1 handoff](milestone-1.md): explicit alphabets and
permutations, both K2 variants, K3's complete position mapping, and the ACA
Gromark example. K4 has not been solved, and no K4 keys were searched.

## Reproduced fixtures

| Fixture | Letters | Explicit model | Result |
| --- | ---: | --- | --- |
| K1 | 63 | KRYPTOS alphabet for plaintext, ciphertext and key; additive PALIMPSEST, offset 0 | Exact encryption and decryption; IQLUSION retained |
| K2, inscribed | 369 | Same alphabet convention; additive ABSCISSA, offset 0 | Exact encryption and decryption; UNDERGRUUND and historical IDBYROWS retained |
| K2, corrected | 370 | Insert ciphertext S at zero-based index 361, then use the same model | Exact encryption and decryption; corrected ending XLAYERTWO |
| K3 | 336 | Decrypt by bottom-to-top column reading at widths 24 then 8; encrypt using inverse stages in reverse order | Every character and all 336 source indices match; DESPARATLY and terminal Q retained |
| ACA Gromark | 35 | ENIGMA column-derived mixed alphabet, primer 23452, base-10 recurrence | Exact message pair, alphabet, numeric stream and final used check digit 6 |

The plaintexts are separately transcribed from [Gillogly's published account](https://www.elonka.com/kryptos/mirrors/cypherpunks/1999/0930.html)
and the [K2 correction](https://www.elonka.com/kryptos/CorrectedK2Announcement.html).
The [ACA specification](https://www.cryptogram.org/downloads/aca.info/ciphers/Gromark.pdf)
provides the Gromark answer. [Bean's lecture, slides 14–17](https://richardbean.id.au/presentations/2019-04-02%20kryptos-math3302.pdf)
provides K3 reconstruction context and references creator worksheets. Those
worksheets could not be retrieved here. The implemented route is a fully
specified compatible reconstruction, not a new historical-attribution finding.

The [fixture manifest](../fixtures/known-answers.json) SHA-256 is
`89acd3d2690dcd9aac49f86758ac6ed28d539befec0cb5419eaefee273245613`.
Source/statement additions live in `fixtures/`, so all four milestone-1 evidence
files retain their original bytes and hashes. The complete reconstruction
rules are in [cipher conventions](../docs/cipher-conventions.md).

## Reusable implementation

The Rust library now supplies:

- Validated standard/keyed alphabets, forward/inverse indices, rotation and reversal.
- Repeating Vigenère, Beaufort and variant Beaufort with separate plaintext,
  ciphertext and key alphabets, explicit key offsets and numeric position traces.
- Validated pull permutations, inversion, composition, ragged columnar reading,
  bottom-to-top routes and ordered multi-stage pipelines.
- The actual ACA Gromark alphabet constructor and a separate recurrence generator
  supporting bases 2–26 and primer lengths 2–32.
- Explicit candidate normalization, exact crib mismatch witnesses, constraint
  transport through permutations and deliberately scoped canonical identifiers.

`transform REQUESTS.json` is a generic CLI adapter. There are no K1/K2/K3 model
branches and no expected plaintext lookup tables in runtime logic. Known answers
exist in fixtures and tests. Encryption/decryption order and every alphabet are
required in each request; unknown fields and illegal parameters fail explicitly.
The [example request](../fixtures/example-request.json) demonstrates K1 decryption.

## Reproducible verification

[FOUNDATIONS-0001](../experiments/FOUNDATIONS-0001.json) declares the models,
fixtures, compiler, hashes, seed, generator and 180-second budget.
[Run 002](../results/FOUNDATIONS-0001/run-002/completion.json) completed all stages
with exit status 0, in approximately **0.970 seconds** with the existing build
cache. OS maximum child RSS was **249,552 KiB**, including build and verification;
this is not a simultaneous memory total or a cipher throughput benchmark.

It checked **five published message pairs plus 600 seeded synthetic pairs**:
100 each for Vigenère, Beaufort, variant Beaufort, Gromark, ragged columnar and
compound substitution/transposition. The 1,210 directional transforms cover
lengths 0, 1, 2, 7, 25, 26, 27, 96, 97, 98 and 127, changing alphabets, keys,
offsets, primer digits, column orders, directions and composition order.

The [Python reference](../verification/verify_ciphers.py) uses direct equations
and grid-cell operations and checks every output character, trace field and
canonical identifier. [Known-fixture traces](../results/FOUNDATIONS-0001/run-002/fixture-traces.json)
are saved in full. The [verification summary](../results/FOUNDATIONS-0001/run-002/verification.json)
records hashes for deterministically regenerable synthetic requests and outputs.
The xorshift32 implementation, seed 1261723442 and draw order are pinned.
Modulo selection is sufficient for implementation tests; no statistical-null
claim is made. The existing K4 diagnosis output is byte-for-byte identical to
milestone 1 and passes its original reference verifier.

These are separate implementations by the **same coordinator**. This reduces
shared implementation risk, but does not constitute the plan's fresh-context
A7 final review. No key-recovery rates or successful attack calibration are
claimed: each synthetic transform is given its key.

## Validation

All required checks passed:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
- `cargo test --all-features`: **72 unit/integration tests and five doctests**
- `cargo test --doc`: five doctests
- `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps`
- `cargo +1.85.0 check --locked --offline`
- Python unittest discovery: **46 tests**

Coverage includes illegal symbols/keys/alphabets, empty and one-letter messages,
all letter pairs under each sign convention, ragged boundaries, maximum offsets,
unallocatable lengths, inverse and composition direction, conflicting cribs,
published full-text answers, and intentionally corrupted traces. No dependencies
or unsafe code were added. The baseline runner now hashes nested Rust modules
as well as files directly under `src/`.

## Remaining gates and next milestone

The broad Phase 1 list still includes autokey, progressive/interrupted schedules,
the full explicitly named Quagmire family, and small modular-matrix models. Those
are not implied by this milestone's fixture success. Fresh-context verification
and genuine synthetic **key recovery** calibration remain gates for subsequent
searches using their respective models.

The next milestone is the second work package already queued: register and
reproduce Bean's pinned five-digit base-10 Gromark primer filtering, independently
derive its constraints, and explain the reported 39 survivors. A primer passing
necessary conditions is not a complete valid alphabet pair or a recovered key.
Broader K4 search domains should wait for the corresponding calibrated machinery.

This handoff was subsequently completed in [milestone 3](milestone-3.md): all
three implementations reproduce the same 39 primers, with checked rejection
certificates and explicit remaining alphabet-feasibility limits.
