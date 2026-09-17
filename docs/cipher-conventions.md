# Milestone 2 cipher conventions

This milestone implements the primitives needed to reproduce the published
K1/K2/K3 and ACA Gromark fixtures. It is the first work package in the
[milestone-1 handoff](../reports/milestone-1.md). It is not a K4 key search.

## Text and alphabets

Cipher inputs and keys are strings of uppercase ASCII A–Z, with no implicit
normalization. Empty messages are allowed; empty keywords are rejected. A named
candidate-normalization helper accepts ASCII letters and whitespace, uppercases
letters, and removes whitespace; punctuation, digits and non-ASCII are errors.
Fixture transcription from published prose is a separately documented step.

An alphabet is an ordered permutation of all 26 letters. Indices are 0–25.
Keyword construction removes repeated letters in first-occurrence order and
appends unused letters in standard A–Z order. A left rotation by n places maps
new index i to old index `(i+n) mod 26`. Reversal reverses the complete alphabet.

## Polyalphabetic equations

Let a, b and q be the plaintext, ciphertext and key letter-to-index maps.
For keyword W and nonnegative offset o, `k_i = q(W[(i+o) mod len(W)])`.

| Name | Encryption | Decryption |
| --- | --- | --- |
| Vigenère | `c = p + k (mod 26)` | `p = c - k (mod 26)` |
| Beaufort | `c = k - p (mod 26)` | `p = k - c (mod 26)` |
| Variant Beaufort | `c = p - k (mod 26)` | `p = c + k (mod 26)` |

K1 and both K2 variants use Vigenère with **all three** alphabets equal to
`KRYPTOSABCDEFGHIJLMNQUVWXZ`, offset zero, and keys PALIMPSEST/ABSCISSA.
This explicitly fixes the alignment of the reported Quagmire III variation:
the keyword letter is underneath the index-zero plaintext letter K. It does
not imply that every convention called Quagmire III has identical alignment.

The repeating-model canonical identifier retains the exact equation and three
alphabets. It removes repeated complete keyword cycles and incorporates the
offset modulo that primitive period. It proves equivalence only for that
fixed-alphabet representation; it does not merge alphabet rotations or different
equations.

## Permutations and routes

Every permutation is a pull map: `output[j] = input[source_indices[j]]`.
Its indices must contain each integer `0..n` once. `first.then(second)` means
apply first, then second; its map is `first[second[j]]`. Decryption uses the
inverse map. Substitution order is never silently exchanged with permutation.

A columnar route fills input rowwise, left to right, in the declared width.
Columns are read in a declared permutation of `0..width`. Within each column,
read top-to-bottom unless `reverse_rows` is true. A final short row has missing
cells, which are skipped; no padding is inserted. Width must be positive.
An empty message maps to an empty message, even at a nonzero width.

For K3 **decryption**, fill the 336-letter ciphertext at width 24 and read each
column left-to-right, bottom-to-top. Refill that stream at width 8 and apply the
same route. For encryption, apply the inverse width-8 map, then the inverse
width-24 map. Store all 336 final source indices and every stage's position
trace. The separate inscribed question mark is not an extra input character.
The route reproduces the published plaintext exactly; a compatible construction
alone is not an independent historical-attribution finding.

## Gromark

For keyword W, deduplicate W to D, construct the keyword alphabet, and fill it
rowwise at width `len(D)`. Read columns in the alphabetical order of D to obtain
the **ciphertext alphabet**. The plaintext alphabet is standard A–Z. Merely
prefixing the alphabet with W is not the ACA construction.

For the standard five-digit primer, include those digits in the running key:
`k[i+5] = (k[i] + k[i+1]) mod 10`. Encryption is additive using the standard
plaintext and constructed ciphertext indices. The transmitted final check digit
is the key digit used for the final message letter, not the next recurrence digit.
The fixture excludes the transmitted primer and check digit from ciphertext.

The reusable recurrence accepts bases 2–26 and primer lengths 2–32, each digit
strictly below the base. Its equation is `k[i+r] = (k[i]+k[i+1]) mod base`.
These are explicit supported bounds, not an assertion that all variants have
been searched. Recurrence arithmetic and letter arithmetic remain separate.

## Cribs and traces

Cribs specify a final zero-based plaintext position and uppercase letter. A
candidate check reports the first mismatch with expected/actual letters; length
and invalid input errors are distinct from a mismatch. Transport through a pull
permutation maps an output-position constraint to its source input position.
Contradictory repeated constraints are errors, never overwritten.

Each transform returns text and one record per output position: source input
position, input/output letters, and numeric input/key/output values where a
substitution is applied. Multi-stage runs retain each stage's complete trace.
Empty inputs produce empty text and traces. No trace values are supplied from
the expected fixture answer.

## Verification boundary

Known plaintexts are transcribed from published sources and retained with their
irregular spellings; K2's inserted ciphertext S is separately identified.
Both encryption and decryption must match every character. Separate Python
equations and grid operations cross-check Rust output on fixed and seeded
synthetic examples. This is implementation verification, not a recovery-rate
benchmark. A fresh-context A7 candidate review and the broader Phase 1 primitives
remain separate gates before a K4 search campaign.
