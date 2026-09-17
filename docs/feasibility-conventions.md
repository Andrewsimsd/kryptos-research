# Milestone 6: complete alphabet feasibility for 39 primers

The input primer set is exactly the 39 survivors in
`results/PRIMERS-0001/run-002/primers.json`; its hash and the frozen K4 evidence
are inputs to this experiment. No new primer, base, offset, recurrence or crib
placement is searched. Expand each nonzero five-digit decimal primer including
its digits at positions 0–4, with k[i]=(k[i-5]+k[i-4]) mod 10. Use 97 digits.

Solve c(C_i)-p(P_i)=k[i] modulo 26 for all 24 aligned cribs. Plaintext and
ciphertext alphabets are independently arbitrary bijections onto 0–25; neither
is fixed to A–Z, KRYPTOS, an ACA keyword construction or a word list.

Build a bipartite graph of the letters in the crib equations. In each component,
set its alphabetically lowest plaintext letter to relative coordinate zero and
derive all other coordinates. Inconsistent cycles or repeated coordinates for
distinct letters on the same side prove local infeasibility. Different alphabets
may use the same coordinate. Sort components by decreasing total vertices,
then their lowest plaintext letter.

Each component has one free additive offset in 0–25. A common rotation of BOTH
alphabets preserves all differences and both bijections, so fix the first
component's offset at zero without losing any solutions. Search the others in
component order, offsets 0–25 in ascending order. A placement is legal iff its
plaintext and ciphertext footprints separately avoid already occupied positions.
Stop at the first complete placement. Once all constrained letters are placed,
assign unused letters alphabetically to each alphabet's unused ascending slots.
This deterministic completion imposes no extra restriction: any partial injection
on at most 26 letters extends to a permutation.

Completeness: every satisfying alphabet pair induces the component coordinates
plus some offsets; subtracting the first offset normalizes its common rotation.
Every remaining offset combination is either visited or pruned by an actual
same-alphabet coordinate collision. Exhausting all branches therefore proves
infeasibility for this model. Reaching the attempt cap is a separate unresolved
status, never an impossibility claim. A successful witness consists of two
26-letter strings in coordinate order, offsets and all 24 evaluated equations.

Rust's cap is 10,000,000 candidate offset attempts per primer, including
immediately rejected collisions. Empty problems need zero attempts. The Python
reference independently derives components and searches by the smallest current
legal offset domain using sets; its separate cap is 1,000,000 recursive states
per primer. It need not find the same witness. Both must resolve every listed
primer and agree on feasibility for milestone completion. The overall run cap
is 600 seconds. Search is deterministic and uses no RNG or external solver.

The Python verifier additionally checks exact list coverage, 97-digit recurrence,
component coordinates, both complete alphabet permutations, every offset and
every crib equation directly. No unknown plaintext or language score is used to
guide the search. A witness can decode the remainder arbitrarily; that does not
make it intended plaintext. No full witness plaintext is published as a candidate.

This closes an existence question left by the necessary-condition filter. It
does not enumerate all alphabet pairs, recover keyword constructions, calibrate
an English-language attack, authenticate plaintext or establish historical use.
The two new implementations are by the same coordinator, not fresh-context A7.
