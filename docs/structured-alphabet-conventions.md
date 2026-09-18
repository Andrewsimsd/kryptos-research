# Structured-alphabet conventions

This document freezes the exact Milestone 7 model before its registered
production run. The experiment evaluates the 39 sorted survivors in
`results/PRIMERS-0001/run-002/primers.json` and no other primers.

For each primer, the base-10 recurrence includes the five primer digits and
continues as

```text
k[i] = (k[i-5] + k[i-4]) mod 10
```

with key offset zero. At every one of the 24 frozen aligned cribs, the model is

```text
c(C_i) - p(P_i) = k[i] mod 26
```

The finite alphabet family contains four explicit permutations:

1. `az-forward`: `ABCDEFGHIJKLMNOPQRSTUVWXYZ`
2. `az-reversed`: `ZYXWVUTSRQPONMLKJIHGFEDCBA`
3. `kryptos-forward`: `KRYPTOSABCDEFGHIJLMNQUVWXZ`
4. `kryptos-reversed`: `ZXWVUQNMLJIHGFEDCBASOTPYRK`

All 16 ordered plaintext/ciphertext construction pairs are evaluated. The
plaintext alphabet has rotation zero. The ciphertext alphabet is rotated left
by each amount 0 through 25. This evaluates 39 × 4 × 4 × 26 = **16,224**
canonical models and 16,224 × 24 = **389,376** equations.

Fixing plaintext rotation loses no distinct equation system: adding the same
rotation to both alphabet orders subtracts that amount from both indices and
leaves every difference unchanged. A ciphertext rotation therefore represents
the complete relative-rotation domain. `Alphabet::rotated(n)` means a left
rotation, so the original position `n` becomes index zero.

Every equation is evaluated, even after the first mismatch, to produce a full
match-count histogram. A rejection includes the first true mismatch in
ascending message-position order. A survivor includes its expanded key,
complete rotated alphabets, and all 24 equation traces. A survivor establishes
compatibility only; it does not establish an intended key or plaintext.

There is no randomness, language scoring, dictionary, extra alphabet
construction, transposition, key offset, or plaintext inference. The complete
domain is evaluated once. If it has no survivor, only this stated family is
excluded.

Before registration, an exploratory read-only Python probe examined only the
zero-rotation slice. It found no full match, a best score of 6/24, and the
histogram `0:264, 1:225, 2:87, 3:38, 4:6, 5:3, 6:1`. This prior observation is
disclosed to prevent the production experiment from being presented as wholly
unseen. It did not inspect rotations 1–25 and did not change the declared full
domain.
