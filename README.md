# kryptos-research

Reproducible evidence and bounded cryptanalysis for Kryptos K4, following the
[research plan](docs/kryptos-k4-agent-plan.md). This project has **not solved K4**.

**Milestone 5 is complete:** widths **1–48** were scanned with separate null
calibration and the full maximum-selection procedure repeated on every null
text. Width 21 remains strongest; the scan-adjusted estimate is **0.00442**
(441 exceedances in 100,000 evaluation permutations). Rust and Python agree on
all integer outputs. See [milestone 5](reports/milestone-5.md) for uncertainty
and scope. Earlier work includes [fixed statistics](reports/milestone-4.md),
[39 primer survivors](reports/milestone-3.md),
[cipher fixtures](reports/milestone-2.md), and [frozen evidence](reports/milestone-1.md).

## Build and run

Requires Rust 1.85 or newer and Python 3.10 or newer. The recorded experiment
uses Rust 1.95.0 and Python 3.14.4 on Linux; the runner enforces the recorded
`rustc --version` string. The code also passes `cargo +1.85.0 check`.

```bash
cargo build --locked
cargo run --locked -- --help
cargo run --locked -- validate
cargo run --locked -- diagnose > /tmp/k4-diagnosis.json
python3 verification/verify_baseline.py --report /tmp/k4-diagnosis.json --ledger evidence/sources.jsonl
cargo run --locked -- transform fixtures/example-request.json
```

Commands default to `evidence/k4.json`, relative to the current directory.
Pass another file as `validate PATH`, `diagnose PATH` or `primers PATH`. All string data must
already be uppercase ASCII; the parser rejects punctuation, spaces, malformed
ranges, overlapping anchors, inconsistent transcriptions, and unknown fields.
Exit status is 0 on success and 1 on error; errors go to stderr. `diagnose`
writes JSON to stdout and performs no file writes or network requests.

`transform REQUESTS.json` requires an explicit request file. It encrypts or
decrypts declared pipelines and emits computed text, canonical model identifiers
and every stage's position trace. It has no K1/K2/K3 shortcuts or plaintext
lookups. [The example request](fixtures/example-request.json) decrypts K1.
See [cipher conventions](docs/cipher-conventions.md) for equations, ragged-cell
rules, composition direction and the distinction between key and letter moduli.

Serde and serde_json provide typed JSON parsing and machine-readable output;
their versions and transitive dependencies are pinned in `Cargo.lock`. Python
uses only its standard library. After the initial dependency download, add
`--offline` to Cargo commands for offline operation.

## Reproduce the registered experiment

From the project directory, with the recorded Rust toolchain selected:

```bash
sha256sum --check evidence/SHA256SUMS
python3 experiments/run_baseline.py results/K4-D-0001/run-002
```

Choose a **new** output directory each time. The recorded first run is
[run-001](results/K4-D-0001/run-001/completion.json). The runner verifies every
frozen evidence hash, builds offline with the lockfile, runs Rust diagnosis,
and checks every result and witness with the Python reference implementation.
It records input/binary/output hashes, tool versions, commands, exit statuses,
actual counters, elapsed time and OS child-process peak memory. The 180-second
cap covers build, diagnosis, and verification. No random sampling is used.

The runner refuses existing directories and appends started/completed/failed
events to [the registry](experiments/registry.jsonl). Run this coordinator
sequentially; concurrent registry writers are outside this milestone's scope.
Failed runs remain on disk. Changing any frozen evidence file requires a new
experiment specification and rerunning its dependent results. A version label
alone is not evidence identity; the SHA-256 hashes bind the bytes.

The Rust `validate` command checks manifest structure and internal consistency.
The Python `--ledger` option additionally checks source/claim references and
any declared local source hashes. The registered runner enforces the frozen
evidence-file hashes. None of these operations authenticates an external author.

## Reproduce the cipher-fixture milestone

```bash
sha256sum --check fixtures/SHA256SUMS
python3 experiments/run_foundations.py results/FOUNDATIONS-0001/run-003
python3 verification/verify_ciphers.py --report results/FOUNDATIONS-0001/run-002/fixture-traces.json
```

Use a new output directory. The [registered run](results/FOUNDATIONS-0001/run-002/completion.json)
checks all five published fixtures in both directions, then 100 seeded message
pairs in each of six groups: Vigenère, Beaufort, variant Beaufort, Gromark,
ragged columnar and compound substitution/transposition. Synthetic lengths span
0–127, including 97; alphabets, keys, offsets and column orders vary. Both output
and every trace value must match the separate Python implementation. The runner
also requires the original K4 diagnosis JSON to remain byte-for-byte unchanged.

The experiment pins the xorshift32 algorithm, seed, domains, fixture hashes and
compiler. Known-fixture traces are preserved in full; synthetic batches are
reproducible from the pinned generator and have request/output hashes. No corpus
or network is used. These are implementation checks, not attacks or key-recovery
benchmarks. The Python reference was written by the same coordinator and does
not replace the plan's future fresh-context A7 review.

## Reproduce the primer milestone

```bash
python3 experiments/run_primers.py results/PRIMERS-0001/run-003
python3 verification/verify_primers.py --report results/PRIMERS-0001/run-002/primers.json --upstream results/PRIMERS-0001/run-002/upstream.txt
```

The [registered experiment](experiments/PRIMERS-0001.json) pins the source,
conventions and compiler versions, with a 180-second total budget. In addition
to Rust and Python, its upstream comparison requires `cc` supporting GNU C89;
the recorded compiler is GCC 15.2.0 on Linux. No SageMath or new Rust dependency
is needed. The GPL-3.0 upstream source is preserved separately under
[`third_party/`](third_party/README.md) and is never linked into the Rust code.

The [completed run](results/PRIMERS-0001/run-002/completion.json) compares full
survivor lists, all 98 printed key digits and distinct-digit counts over the
97 message positions. Rust derives constraints from crib equations; Python
checks numeric graph consistency and every rejection certificate. Both were
written by the same coordinator, not a fresh-context reviewer.

`cargo run --locked -- primers > /tmp/k4-primers.json` runs just the Rust filter
and writes JSON to stdout, including all rejected primers grouped by their first
contradiction. [Primer conventions](docs/primer-conventions.md) specify the exact
nonzero five-digit domain and the two independently unknown alphabets. Surviving
primers still require global alphabet feasibility and plaintext recovery work.

## Reproduce the statistical milestone

```bash
python3 experiments/run_statistics.py experiments/STATS-0001.json results/STATS-0001/run-002
python3 experiments/run_statistics.py experiments/STATS-0002.json results/STATS-0002/run-003
```

Choose new output directories. The [pilot](results/STATS-0001/run-001/completion.json)
uses 10,000 permutations; the [precision run](results/STATS-0002/run-002/completion.json)
uses 1,000,000 with a new seed. Its sample size was registered after the pilot
showed sparse tail counts, before drawing any precision samples. Pilot samples
are not pooled. The initial precision run was interrupted during verification;
its partial artifacts and interruption record remain preserved.

The runner builds Rust in release mode offline, compiles a separate GNU C99
comparison adapter, and checks source/evidence hashes before and after execution.
It requires the pinned Rust and C compiler versions and allows 600 seconds for
build, simulation and complete Python regeneration. Python uses the standard
library. The original C simulation's time-derived RNG is never invoked.

```bash
cargo run --release --locked -- statistics fixtures/statistics-example.json > /tmp/k4-statistics.json
```

This last command runs only Rust's 10,000-sample example, emitting observed
values, dense histograms, initial permutation traces and generator state. It
requires an explicit JSON request and reads `evidence/k4.json` from the project
directory. Requests specify schema 1, a sample count in 1–10,000,000, and a
64-bit seed. [Frozen conventions](docs/statistics-conventions.md) define the
five inclusive tails, SplitMix64 generator, unbiased bounded shuffles, null,
Wilson intervals and Bonferroni correction. The null preserves K4's letter counts.
The correction covers these five tests only; historical width/alphabet selection
and cipher-family calibration remain open work.

## Reproduce the width-scan milestone

```bash
python3 experiments/run_width_scan.py experiments/WIDTHS-0001.json results/WIDTHS-0001/run-002
python3 experiments/run_width_scan.py experiments/WIDTHS-0002.json results/WIDTHS-0002/run-002
```

Use new output directories. The pilot uses 10,000 calibration permutations and
10,000 evaluation permutations with different seeds. The precision experiment
reuses the identical calibration and draws 100,000 new evaluation samples;
pilot evaluations are not pooled. Both stages measure all 48 widths. The
[completed precision run](results/WIDTHS-0002/run-001/completion.json) regenerates
all calibration and evaluation samples in Python and preserves every histogram.
Its 600-second cap includes release build, simulation, verification and regression
checks against the baseline diagnosis and milestone-4 fixed-statistic output.
Only Rust and Python are required; no additional dependency or C build is needed.

```bash
cargo run --release --locked -- width-scan fixtures/width-scan-example.json > /tmp/k4-width-scan.json
python3 verification/verify_width_scan.py --request fixtures/width-scan-example.json --report /tmp/k4-width-scan.json
```

`width-scan` requires an explicit request and reads `evidence/k4.json`. Requests
use schema 1, calibration sample counts 2–1,000,000, evaluation counts
1–1,000,000, and different unsigned 64-bit seeds. A zero calibration variance
is an error. [Frozen conventions](docs/width-scan-conventions.md) define the
standardization, exact integer score ordering, tie rule, full null selection,
and interpretation conditional on calibration. The correction covers these 48
widths and this statistic, not other alphabets, statistics or historical searches.

## What the diagnostics establish

For the final aligned 97-letter baseline:

- Pure transposition fails: the anchors require three E's, while the ciphertext
  contains two. This says nothing against a transposition stage in a compound cipher.
- Fixed monoalphabetic encryption and decryption maps fail the aligned anchors.
- A direct mechanism forbidding all self-encryption fails at human positions
  33 (`S → S`) and 74 (`K → K`).
- Standard A–Z additive repeating Vigenère has 49 rejected periods among 1–97.
  Only 27–29 and 53–97 survive the necessary consistency test. These are not
  recovered keys or candidates; other alphabets and sign conventions are untested.
- The ciphertext IC is `336 / 9312 = 0.03608247422680412`. This is descriptive,
  not a statistical verdict about its cipher family.

Every rejection includes assumptions and a small, checkable contradiction
witness. Surviving periods include constrained and unconstrained slot counts.
All 24 anchored positions have plaintext/ciphertext/key-residue traces.

## Evidence and scope

[The manifest](evidence/k4.json) records zero-based, half-open anchor ranges and
preserves physical line fragments separately. The preceding question mark is
excluded. Two published transcripts agree; their historical copying lineage is
not proven independent of one another. Photographs have not been freshly
transcribed in this milestone.

[Current status](reports/current-status.md) records what could be read on
17 September 2026 UTC and which documents remain inaccessible. The live steward
checker was not verified. No external submission, message, or payment was made.
[Prior work](reports/prior-work.md) distinguishes inspected code, author-reported
results, and research that has actually been reproduced here. K1–K3 ciphertext,
the keyed tableau, separate K2 variants, and qualified physical/Morse references
are collected in the original [reference material](evidence/reference-material.json).
That file remains frozen; the separately versioned
[known-answer fixtures](fixtures/known-answers.json) now supply tested K1–K3 and
Gromark encryption/decryption pairs. K3's exact 336-position permutation and
Gromark's mixed alphabet, numeric stream and check digit are explicitly checked.

## Validation

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic
cargo test --all-features
cargo test --doc
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
python3 -m unittest discover -s verification -v
```

Tests include malformed evidence, boundary/overlap checks, every letter pair,
planted key schedules and phases, CLI failures, and deliberately corrupted
certificates. They require no network. The Rust API documentation is generated
under `target/doc/kryptos_research/`. See
[independent verification](reports/independent-verification.md) for how the
implementations were separated and the limits of this review.

The Rust CLI is portable in design and uses `PathBuf`; Linux is the validated
platform. Python hash verification in the runner is portable; the optional
`sha256sum` command is a Linux utility. Peak-memory units are explicitly recorded
per OS, or unavailable where Python lacks `resource`. Cross-compilation and
Windows/macOS execution have not been validated. No audit/deny/nextest policy
or performance benchmark suite is configured yet.

## Layout and contribution

| Directory | Contents |
| --- | --- |
| `evidence/` | Versioned data, sources, statements, reference material and hashes |
| `src/` | Rust ciphers, evidence, primer constraints, fixed statistics, width scans and CLI |
| `verification/` | Independent Python derivation, certificate checking and tests |
| `fixtures/` | Versioned known answers, source addendum, hashes and example request |
| `experiments/` | Registered specification, bounded runner and append-only registry |
| `results/` | Preserved individual run artifacts |
| `reports/` | Findings, limitations and next milestones |
| `docs/` | Research plan and frozen model conventions |
| `third_party/` | Pinned GPL-3.0 comparison source and license |

Follow [AGENTS.md](AGENTS.md): keep model assumptions explicit, preserve failed
results, update documentation, and pass the validation commands above. The
project code is [MIT licensed](LICENSE); the vendored comparison source retains
its [GPL-3.0 license](third_party/bean-k4testing/LICENSE). Linked source material retains its
authors' rights; no license over those works is implied.
