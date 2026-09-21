# BLIND-0002 corrected blind benchmark contract

This registration supersedes the BLIND-0001 pilot. The pilot's seed was
published in its pre-run specification, so its 100% recovery is **not** valid
blind calibration. Its artifacts remain immutable for audit. The equations,
canonical IDs, cohorts, budgets, ranking, and targets in the
[original contract](blind-benchmark-conventions.md) still apply, except where
the isolation protocol below replaces them.

Before generating cases, the coordinator samples a 256-bit random secret and
freezes the SHA-256 digest of its 32 raw bytes in BLIND-0002.json. The seed is
kept outside the repository until the attack process exits. A SHA-256 counter
stream, with block $H(\mathrm{seed}\parallel\mathrm{counter}_{64\mathrm{be}})$,
supplies successive big-endian 32-bit words. Selection takes each word modulo
the range, with Fisher–Yates case mixing. The seed is then revealed in the
run's private file. The attacker receives only the public JSONL path and its
output path. Private truth is kept outside the attacker-visible run directory
during its execution and moved in only after it exits. This is reproducible
process isolation, not a security boundary against a malicious local process.

An independent verifier must hash-check the revealed seed, regenerate all
300 cases from the frozen corpus and algorithm, compare every byte of public
and private case content, independently enumerate all exact survivors and
their order, and only then score the recovery targets. An altered private
answer, ciphertext, case class, or ordering must fail verification. A timeout
or partial search is unknown, not a negative. The production run does not
access K4 ciphertext; the evidence file supplies only public clue positions
and letters.
