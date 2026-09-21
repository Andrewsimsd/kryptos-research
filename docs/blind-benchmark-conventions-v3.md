# BLIND-0003 final preregistration

This run uses the [BLIND-0002 isolation and regeneration contract](blind-benchmark-conventions-v2.md)
with one fresh, previously unseen 256-bit seed. BLIND-0001 published its seed
before attack. BLIND-0002 run 001 executed the attacker before a private-file
transfer failed; run 002 replayed those exact public cases. Both remain in the
immutable audit trail, but neither is counted as a fresh blind success.

The BLIND-0003 verifier also binds every scientific field in the run manifest
to the checked-in BLIND-0003 registration. It checks all registered input hashes
and recorded implementation hashes before examining outputs. It then checks
the revealed seed commitment, independently regenerates every public and
private case, and independently enumerates every survivor. Altered targets,
cohort sizes, ciphertext, private answers, seed, and code are failures. The
runner checks the wall-time cap after verification and hash checks, so a final
overrun is a timeout rather than a completed run.

The shared controller and verifier form a reusable **protocol**, but the
registered recovery target and case distribution apply only to this small
reference attack. Every future attack family requires a separate registration,
representative positives and negatives, and blind recovery gate before K4.
