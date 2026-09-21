# Milestone 10 blind benchmark contract

This registration covers a **synthetic** exact-recovery reference attack. It
does not test K4 or claim to calibrate a language ranker. Milestone 9's open
physical, World Clock, and Carter inputs are excluded.

## Public case and secret controller

The controller uses a fixed xorshift32 stream to choose messages, keys, models,
and a shuffle of case order. It writes a public JSONL of case ID, ciphertext,
known plaintext positions/letters, and evaluation budget. It writes planted
models and plaintexts to a separate controller-private JSONL. The attacker is
invoked as a separate process with only the public file path and output path;
it never reads controller code or private files. The independent verifier may
read both after the attacker exits. This is process-level blindness, not a
security boundary against a malicious local process.

Random messages are uniformly sampled A–Z outside the 24 published positions.
The separate frozen prose corpus supplies held-out text for a limited
plausible-language diagnostic; its clue positions are replaced with the public
letters. No language score is used for ranking. Out-of-family negatives have
period-three keys. Tamper negatives alter a ciphertext letter at a known
plaintext position after generation. Cases are mixed before attack.

## Reference family and canonicalization

At plaintext index $i$, the route selects ciphertext index $j=i$ (identity)
or $j=n-1-i$ (reverse). With standard A–Z indices, period $t\in\{1,2\}$,
$k_i=q_{i\bmod t}$, and all arithmetic modulo 26, registered equations are

$$c_j=p_i+k_i,\qquad c_j=p_i-k_i,\qquad c_j=k_i-p_i.$$

The first and second equations are the same **constraint family** under
$k\mapsto-k$. Their canonical representative is `add`; Beaufort is `reflect`.
If both period-two key letters agree, reduce to period one. Thus a survivor ID
contains route, canonical equation, primitive period, and canonical key.
Distinct IDs may still produce the same ciphertext for a particular message;
the reported ambiguity retains them, with no truth-dependent deduplication.

The attacker derives each key residue from all public known letters, rejects
inconsistencies, then reencrypts each candidate's decrypted message. Its order
is fixed: identity before reverse, add before reflect, period one before two,
then lexicographic key. This is a deterministic structural ranking, **not** a
claim that the first model is historically likelier. A surviving exact model
can fit 24 letters while giving meaningless text elsewhere.

## Limits, targets, and interpretation

The preregistered production set is 120 random-letter positives, 40 held-out
prose positives, 120 period-three negatives, and 20 tamper negatives. Every
public case has length 97 and the same 24 clue positions. Maximum model checks
are $8$ per case and $2400$ overall; wall cap is 600 seconds. The controller
also tests empty, boundary, duplicate-crib, invalid-letter, and undersized
budget behavior separately. If a limit is reached before complete enumeration,
status is `unknown`, never `rejected`.

Targets: 100% planted canonical-class retention, at least 90% top-one and 99%
top-five recovery among positives, at most 1% out-of-family negatives with any
survivor, and zero unclassified overrun. Positive recovery uses exact canonical
ID, not a truth-selected equivalent. Report ambiguity-set sizes, subgroup
rates, wall time, and negatives separately. A failed target blocks this attack
family from K4 but does not exclude a historical method. Held-out prose merely
checks the exact recovery path on a different message distribution; it does
not calibrate English-language scoring.
