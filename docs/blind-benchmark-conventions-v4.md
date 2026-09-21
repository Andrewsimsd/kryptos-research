# BLIND-0004 final correction

The [original exact family](blind-benchmark-conventions.md) and
[hidden-seed case generator](blind-benchmark-conventions-v2.md) are unchanged.
This registration uses a new, previously unseen 256-bit seed and supersedes
BLIND-0003 as the accepted blind calibration run. BLIND-0003's verifier omitted
an exact implementation-path set check, and its runner checked wall time before
final artifact hashing. Its artifacts remain immutable and independently
checkable under the versioned historical audit below.

Before scoring BLIND-0004, verification requires exact equality of every
scientific manifest field with the frozen registration, the complete expected
set of implementation paths, and matching bytes at each recorded code hash.
It also checks frozen inputs, the seed commitment, full independent case
regeneration, exact survivor enumeration and order, and target metrics. The
runner checks the final wall cap **after artifact hashing** and before writing
completion. A late overrun is a timeout even when the attacker and verifier
subprocesses returned successfully.

Historical BLIND-0002 run 002 remains reproducible through the current
independent equations and seed regeneration. Its original code hash strings
are bound to the immutable manifest through the completion record and
append-only registry, but the exact old source bytes were not archived; do
not claim a source-byte replay for that run. BLIND-0003's changed verifier and
runner sources were archived byte-for-byte under versioned snapshot paths;
their hashes still match its recorded manifest. Neither historical run counts
as the accepted fresh blind gate.

This remains one calibrated reference family. The reusable controller and
verification protocol does not certify any future cipher family without its
own preregistration, cases, negatives, and targets.
