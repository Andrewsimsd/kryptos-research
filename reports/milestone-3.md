# Milestone 3 — reproduce the decimal Gromark primer constraints

Completed 2026-09-17. The next work package from the
[milestone-2 handoff](milestone-2.md) is complete: the unmodified pinned Bean
program, generic Rust constraints, and a separate Python numeric graph check
agree on the full survivor set and expanded keys.

| Stage | Primers remaining | Newly rejected |
| --- | ---: | ---: |
| Nonzero five-digit decimal domain | 99,999 | — |
| Two-edge crib conditions | 1,040 | 98,959 |
| Cycle and within-component alphabet conditions | **39** | 1,001 |

These reproduce the counts reported in §3 of
[Bean's paper](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109)
and the output of the
[pinned source](https://github.com/RichardBean/k4testing/blob/6a5e3cb200d5ab72a62bb7f5124b4fdf163faf8c/gt.c).
The prior evidence ledger identifies these as S200/C200 and S201/C201; its
original attributed claims remain frozen. This report records the new local
reproduction rather than rewriting the old audit.

**No full K4 plaintext or alphabet key has been recovered.** A surviving primer
passes necessary conditions for the declared model; it is not an authenticated
solution or proof of historical use.

## Exact model and coverage

[PRIMERS-0001](../experiments/PRIMERS-0001.json) was written before enumeration.
It declares all `00001`–`99999` primers, including leading zeros, and excludes
`00000` to match upstream. The included-primer recurrence is
$$
k_i=(k_{i-5}+k_{i-4})\bmod10,\qquad
c(C_i)-p(P_i)\equiv k_i\pmod{26}.
$$

Here $i$ is a zero-based position, $k_i$ is a decimal digit (the five primer
digits start the stream), $P_i$ and $C_i$ are aligned letters, and $p$ and $c$
are independently unknown plaintext/ciphertext alphabet indices 0–25. The
key offset is zero, and all 24 frozen cribs are used.

The original program prints 98 digits but counts distinct digits in the first
97. Both conventions are reproduced exactly; the last printed digit is not an
extra ciphertext character. No alternate recurrence, base, length, transposition,
crib placement, plaintext score, or keyword list was tried. No corpus or random
sampling was used. [Frozen conventions](../docs/primer-conventions.md) give the
complete scope and the conditions for reporting a discrepancy.

The upstream files are preserved byte-for-byte, with their GPL-3.0 license,
under [`third_party/`](../third_party/README.md). They run as a separate process,
not as linked Rust code. GNU C89 accepts the historical function declaration;
the original source and compiler diagnostics remain unchanged and recorded.

## Derivation and rejection certificates

[`src/primers.rs`](../src/primers.rs) builds a bipartite graph whose vertices
are plaintext and ciphertext letters. Each crib is an edge labeled by its key
position. A spanning forest expresses each alphabet coordinate relative to an
unknown component offset. Closing an edge requires a zero cycle sum; distinct
letters on the same side of a component require different coordinates.

There are 35 canonical signed relations: 23 simple relations followed by 12
additional graph relations, comprising 33 inequalities and two equalities.
This need not match the paper's literal formula count: the generic pair pass
includes the redundant comparison of positions 65 and 72 as well as 27 and 72,
and the forest chooses a different set of longer expressions. There is no
hard-coded K4 inequality list in the Rust implementation. The complete primer
classifications agree despite the different derivation.

For example, R maps to P at both positions 27 and 65, requiring
$k_{27}=k_{65}$. The S/T-to-R/S cycle requires
$k_{23}-k_{28}-k_{32}+k_{33}\equiv0\pmod{26}$; these subscripts are the
report's zero-based positions.
The saved report partitions **all 99,960 rejected primers** by their first
violated signed relation. Summing the corresponding signed crib equations
proves each relation; substituting the rejected primer proves its contradiction.
Leading zeros are restored by formatting each numeric rejection ID to five digits.

[`verify_primers.py`](../verification/verify_primers.py) independently assigns
numeric coordinates by graph traversal, without using Rust's symbolic relations
to classify primers. It also verifies each relation's algebraic derivation,
every rejection's first failing condition, complete disjoint domain coverage,
all survivor expansions and digit counts, and exact agreement with upstream.

The Python and Rust implementations were written by the **same coordinator**.
Separate algorithms and the pre-existing C reference reduce shared implementation
risk, but are not the plan's fresh-context A7 review.

## Preserved results

[Final run 002](../results/PRIMERS-0001/run-002/completion.json) completed in
approximately **1.194 seconds** with the existing build cache, including the
C compilation, three enumerations/checks, and baseline regression. The Rust
filter stage took about 0.265 seconds including JSON emission. OS maximum child
RSS was **43,372 KiB**; this is not simultaneous total memory or a controlled
throughput benchmark. The declared wall-time limit was 180 seconds.

- [Manifest](../results/PRIMERS-0001/run-002/manifest.json): input/source hashes,
  exact tool versions, model, bounds and assumptions.
- [Full Rust report](../results/PRIMERS-0001/run-002/primers.json): all relations,
  rejection groups and survivor key streams.
- [Upstream output](../results/PRIMERS-0001/run-002/upstream.txt): untouched C output.
- [Verification](../results/PRIMERS-0001/run-002/verification.json): all 39 primers,
  counts, certificate coverage and exact upstream agreement.

The full Rust report SHA-256 is
`57a4a68f33cee527e2d1a125d457bef5ae68d7825ad718d979cf5b9ffebb8ed1`.
Runs 001 and 002 have identical report bytes. Run 001 is retained as a regression
fixture; run 002 hashes the final implementation and added tamper tests. Every
original evidence and cipher-fixture hash remains unchanged, and the baseline
diagnosis still has its original SHA-256
`6f1327c040467fb4dd307c447997f6b46d7ecae23f4fc8eacbe012c742744987`.

The 39 primers, kept individually without an equivalence quotient, are:

```text
10319 12042 16795 16953 20173 20707 22856 26717 30016 30640
30690 30987 36650 38175 38254 38888 40909 44157 52654 54258
56852 58456 60101 60319 62389 66953 70094 70173 70410 70460
72856 80303 84393 84501 84551 88254 94157 98800 98850
```

## Validation and remaining gates

All required checks passed, with details in
[the validation record](milestone-3-validation.json):

- Formatting and Clippy with pedantic warnings denied.
- `cargo test --all-features`: **84 unit/integration tests and six doctests**.
- Separate doctest run and documentation generation with warnings denied.
- `cargo +1.85.0 check --locked --offline`.
- Python unittest discovery: **59 tests**.

Tests cover short/invalid keys, malformed or conflicting cribs, empty/singleton
graphs, modular wrap, cycles, nonadjacent alphabet collisions, component offsets,
48 planted alphabet/key cases per implementation, and altered certificates,
counts, group assignments, missing/duplicate primers and false survivors. The
planted cases test rejection soundness; they are not plaintext recovery rates.
The CLI is checked against the complete preserved report. No Rust dependency or
unsafe code was added. The runner refuses to overwrite existing results.

Global offsets between graph components have not been solved under both
alphabets' all-different constraints. Keyword realizability, complete alphabet
recovery, language scoring, genuine recovery calibration and historical
attribution remain separate tasks. Broad Phase 1 primitives and the fresh-context
review gates listed in milestone 2 also remain open.

The next queued reproduction work is Bean's fixed-width statistical experiments:
freeze the exact statistic and permutation null, record seeds and raw counts,
and report uncertainty before considering any wider-width search. Alternatively,
extending these 39 primers requires a separately registered global alphabet
feasibility experiment; the current result does not justify simply declaring
them feasible complete keys.

The fixed-statistic reproduction was subsequently completed in
[milestone 4](milestone-4.md), with registered seeds, raw counts, uncertainty,
and full Rust/Python agreement. A selection-aware width scan remains next.
