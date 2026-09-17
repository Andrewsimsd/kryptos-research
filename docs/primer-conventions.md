# Milestone 3: decimal Gromark primer reproduction

The registered domain is every five-digit decimal string `00001` through
`99999`, including leading zeros. `00000` is deliberately excluded to match
Bean's enumeration. No other base, length, recurrence, offset, transposition,
alphabet convention or crib placement is searched.

For each primer, include its five digits at positions 0–4, then compute
`k[i] = (k[i-5] + k[i-4]) mod 10`. Generate 98 digits to compare the upstream
output exactly. Only the first 97 correspond to K4; digit 97 is not an extra
ciphertext symbol. Count distinct digits over positions 0–96.

The model is `c(C_i) - p(P_i) = k[i] (mod 26)`, where p and c are independently
unknown permutations of 0–25. All 24 frozen, aligned crib letters are used.
This is broader than standard ACA Gromark's fixed A–Z plaintext alphabet.

First derive two-edge conditions whenever two cribs share a plaintext or
ciphertext letter: identical letter pairs require equal key digits; sharing
only one letter requires unequal digits. Next build the bipartite graph of
plaintext and ciphertext letters. A spanning forest expresses each vertex's
coordinate as a component offset plus a signed sum of key digits. Non-tree
edges require cycle sums to vanish. Distinct vertices on the same side of a
component must have different coordinates. All congruences use modulus 26,
not modulus 10. Symbolic relations are deduplicated up to sign, retaining
the two-edge conditions first.

Each rejected primer is stored under its first violated symbolic relation.
The relation's signed crib equations constitute a checkable exclusion
certificate. Verification checks the algebraic validity of every relation,
complete disjoint domain coverage and the numeric contradiction for every
rejection. A separate Python graph traversal checks the classification of
every primer without consuming the Rust symbolic relations.

Compare the entire Rust/Python survivor sets and expanded keys with the
unmodified pinned upstream C output. Published target counts are 99,999,
1,040 and 39. If stronger automatically derived conditions change the last
count, preserve and explain the discrepancy rather than weakening checks.

Survival establishes only consistency of these necessary conditions. We do
not solve the offsets between components, produce complete alphabet pairs,
recover the unknown plaintext, rank English, or establish historical use.
No equivalence quotient removes primers from the original enumeration.

Tests include planted alphabet assignments and malformed or contradictory
inputs. These verify rejection soundness, not a plaintext recovery attack.
The separate reference implementation is by the same coordinator and is
not the plan's fresh-context independent A7 review.
