# Kryptos K4: research and cryptanalysis plan for AI agents

Prepared 17 September 2026. This is an executable research plan, not a claimed solution. Numerical budgets below are proposed starting limits, not measured throughput or estimates of the probability of solving K4.

Implementation record: [Milestone 1](../reports/milestone-1.md) freezes the initial
evidence and reproduces the scoped baseline exclusions. See that report for
completed gates, unresolved source access, validation and the next work packages;
the remaining phases below are still the research plan.

[Milestone 2](../reports/milestone-2.md) completes the queued fixture reconstruction:
K1, both K2 variants, K3's explicit permutation and ACA Gromark, with reusable
primitives and seeded cross-implementation checks. The report identifies the
remaining Phase 1 and independent-review gates.

[Milestone 3](../reports/milestone-3.md) reproduces the pinned base-10, five-digit
Gromark filtering result: 99,999 → 1,040 → 39, with generic crib-derived
constraints and verified certificates for every rejection. This does not
establish complete alphabet feasibility, a plaintext, or historical attribution.

[Milestone 4](../reports/milestone-4.md) reproduces the five fixed historical
statistics with a 10,000-sample pilot and an independently seeded one-million
permutation run, complete histogram verification, uncertainty and a five-test
correction. This completes the queued fixed-statistic reproduction, not the
entire Phase 3 battery, selection-aware width scan or synthetic cipher calibration.

[Milestone 5](../reports/milestone-5.md) completes the declared width 1–48 scan:
separate width-specific calibration, identical maximum selection on every null,
and complete Rust/Python agreement. Width 21 is selected; the precision run
records 441 global exceedances among 100,000 permutations. Broader historical
selection and cipher-family calibration remain outside this correction.

## 1. Objective and definition of success

Recover the intended 97-letter K4 plaintext and a defensible explanation of the encryption procedure. Treat these as separate achievements:

1. **Plaintext recovery:** establish the exact intended text through authenticated evidence or the current legitimate verification process.
2. **Cryptanalytic recovery:** recover an algorithm, key, and preprocessing procedure that explain the entire ciphertext without supplying the proposed answer as a hidden input.
3. **Historical attribution:** establish that the recovered mechanism is the mechanism Sanborn actually used, rather than another mathematically compatible construction.

An authenticated plaintext would accomplish the first objective without necessarily accomplishing the other two. Conversely, a reversible construction that fits the ciphertext does not establish any of them by itself.

The appropriate strategy is evidence collection, exact constraint propagation, bounded searches over plausible mechanisms, and adversarial verification. Do not begin with agents proposing complete English messages.

## 2. Research findings that change the plan

**The public status changed in 2025–2026.** Researchers Jarett Kobek and Richard Byrne found archival material revealing the plaintext in 2025; this was distinct from recovering the cipher procedure. The solution archive subsequently sold at auction. These developments make an evidence-recovery branch worthwhile alongside independent cryptanalysis. [AP reporting on the archive and auction](https://apnews.com/article/cb8ee8554ca473910cbd0592f8bdb350).

In June 2026, WIRED reported that Paradigm had become the steward and introduced a website for checking submissions. A current-status agent must verify the live process before any proposed submission. Do not confuse Paradigm's separate CTF challenges with K4 or K5. [WIRED, 12 June 2026](https://www.wired.com/story/crypto-guys-bought-the-answer-to-the-cias-mysterious-kryptos-sculpture/); [Paradigm's CTF rules](https://paradigm.xyz/kryptos-ctf/rules).

**Newer clues matter.** At Sanborn's November 2025 presentation, he identified the World Clock in Berlin as the clock referent, connected the solution with his 1986 Egypt trip and the 1989 fall of the Berlin Wall, and described the work in terms of delivering a message. These are contextual clues, not additional fixed plaintext positions. The article itself contains a “79 letters” typo: retain the independently verified length of 97. [Firsthand presentation coverage, Scientific American](https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/).

**Prior research supplies experiments, not a solved cipher.** Richard Bean's 2021 paper investigates statistical anomalies and proposes Gromark-related explanations; its search did not produce a convincing solution. Its conclusions should inform priorities rather than become hard restrictions on all future models. [Paper and publication record](https://ecp.ep.liu.se/index.php/histocrypt/article/view/153).

**AI-generated false solutions are a known failure mode.** Sanborn explicitly describes receiving meaningless AI decrypts in his August 2025 letter. The plan therefore separates proposal agents from deterministic evaluators and independent critics. [Sanborn's open letter](https://www.elonka.com/kryptos/OpenLetterAug2025.html).

No authenticated public full plaintext and independently established encryption procedure were found in the material reviewed for this plan. This is a search finding, not proof that no newer disclosure exists. Some contemporary pages and historical documents could not be fully retrieved; those gaps are recorded below.

## 3. Freeze the evidence before searching

Use this 97-character reference ciphertext, with no whitespace in the machine representation:

```text
OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
```

The physical line lengths are 4, 31, 31, and 31. Preserve the physical rendering separately from the normalized string. The preceding question mark is not part of the baseline 97 letters. Any hypothesis incorporating it must declare a different model and an explicit mapping back to the baseline. [Dunin's transcript](https://www.elonka.com/kryptos/transcript.html); [Gillogly's 1999 firsthand account](https://www.elonka.com/kryptos/mirrors/cypherpunks/1999/0930.html).

The confirmed plaintext anchors are:

| Human positions, inclusive | Python/Rust range, end exclusive | Ciphertext | Plaintext |
|---|---|---|---|
| 22–25 | 21..25 | FLRV | EAST |
| 26–34 | 25..34 | QQPRNGKSS | NORTHEAST |
| 64–69 | 63..69 | NYPVTT | BERLIN |
| 70–74 | 69..74 | MZFPK | CLOCK |

There are 24 fixed plaintext characters and 73 unknown characters. These positions are for the final normalized plaintext; an internal transposition requires transporting the constraints through its permutation. [Dunin's clue chronology](https://www.elonka.com/kryptos/).

Record the following as distinct classes:

| Class | Examples | Permitted use |
|---|---|---|
| Verified data | Ciphertext, anchor positions | Hard constraints after transcription review |
| Attributed statements | Sanborn's dated letters and recorded comments | Priors or specific scoped constraints; preserve exact provenance |
| Reproduced findings | A contradiction certificate or statistical result | Only as strong as its assumptions and validation |
| Context | Clock, Egypt trip, Berlin Wall, installation geometry | Sources for finite hypotheses |
| Speculation | Guessed prose, numerology, unattributed quotes | Experiment proposals only |
| Superseded material | Old K2 ending, outdated clock assumptions | Historical record; never silently promoted |

K1–K3 data must retain their irregular spellings. Maintain separate “as inscribed” and “corrected reconstruction” versions of K2; its corrected ending includes LAYERTWO. [Sanborn's K2 correction](https://www.elonka.com/kryptos/CorrectedK2Announcement.html).

## 4. Agent organization and execution order

Use eight logical roles. They need not all run concurrently. A coordinator may assign several successive roles to one process, but the final verifier must use a fresh context and independent implementation.

| Agent | Owns | Required output | Cannot do |
|---|---|---|---|
| A0 Coordinator | Task queue, budgets, registry, dependency gates | Prioritized experiment queue; daily report | Declare success by consensus |
| A1 Evidence | Sources, dated statements, current status | Source ledger; verified data manifest | Treat a search snippet as full-document evidence |
| A2 Foundations | Cipher primitives, normalization, fixtures | Tested library and reference verifier | Change evidence to improve a result |
| A3 Diagnosis | Statistical analysis and exact exclusions | Reproduction report; scoped exclusion certificates | Turn a p-value into a probability a cipher is correct |
| A4 Algebra and keys | Polyalphabetic, autokey, generated-key models | Model manifests; survivor lists | Fit a free 97-symbol key and call it recovered |
| A5 Structure and context | Transpositions, physical layouts, historical key sources | Finite model families with provenance | Introduce arbitrary cell choices or unconstrained geometry |
| A6 Search and scoring | Optimization, benchmarks, language models | Reproducible search runs; null comparisons | Use fluency as authentication |
| A7 Verification | Fresh implementation and competing explanations | Acceptance or rejection dossier | Depend on the proposer's executable to verify it |

Dependency order:

- A1 establishes the baseline; A2 builds fixtures from it.
- A3 can begin once the baseline is frozen and primitives pass tests.
- A4 and A5 define bounded models; A6 benchmarks each before a large search.
- A7 reviews exclusions as well as positive candidates.
- A0 allocates the next batch based on evidence gained and coverage, not enthusiasm.

Keep plaintext speculation out of A7's initial packet. First provide the ciphertext, algorithm, parameters, external materials, and normalization rules; have A7 generate the plaintext itself.

## 5. Phase 0 — evidence audit and current-status check

**Owner:** A1. **Initial cap:** two agent workdays. **Dependency:** none.

Steps:

1. Read the current steward's announcement, challenge page, and any authenticated solution announcements. Establish whether a complete plaintext or algorithm has since become public.
2. Trace each claimed clue to a dated letter, original interview, recording, or firsthand report. Record who actually made the statement; distinguish Sanborn from Scheidt and both from later interpretation.
3. Review the published archive finding aids and accessible material about the 2025 discovery. If authenticated plaintext is publicly available, preserve it in a separate evidence branch and switch that branch to known-plaintext cryptanalysis.
4. Independently transcribe K4 from two suitable published visual/transcript sources. Store disagreements and resolve them before search. Do not average or silently “correct” characters.
5. Collect K1–K3, the keyed tableau, sculpture layout, entrance Morse inscriptions, and relevant photographs. Keep original coordinates, orientation, and uncertainty.
6. Build a prior-work matrix covering each paper and executable repository: exact model, alphabet conventions, key ranges, preprocessing, crib set, runtime, exhaustive versus heuristic coverage, result, and available reproduction code.
7. Follow citations from the strongest papers and firsthand collections. Review newer claimed solutions only to extract reproducible methods and identify circularity; popularity is not evidence.

Source-ledger fields:

```yaml
source_id: S001
url: exact_document_url
author: named_author_or_unknown
published_at: date_or_unknown
retrieved_at: timestamp
access: full_text_or_partial_or_metadata_only_or_unavailable
source_type: creator_letter_or_original_paper_or_firsthand_report_or_other
claim: narrowly_stated_claim
locator: page_or_section_or_timestamp
status: verified_or_attributed_or_disputed_or_superseded
supports: [claim_ids]
contradicts: [claim_ids]
content_hash: hash_of_locally_preserved_material_if_available
```

**Gate:** a versioned manifest with unambiguous indexing, 24 anchor characters, source links, and unresolved issues. A changed transcription invalidates all dependent experiment results until rerun. A metadata-only or inaccessible document is a lead, not completed research.

**Deliverables:** `evidence/sources.jsonl`, `evidence/k4.json`, `evidence/statements.jsonl`, `reports/prior-work.md`, and `reports/current-status.md`.

## 6. Phase 1 — trustworthy cryptanalytic machinery

**Owners:** A2 and A7. **Initial cap:** three agent workdays.

Use Rust for the high-throughput cipher/search core if convenient; Python is suitable for an independent verifier, analysis, and SMT experiments. Pin toolchain, dependencies, corpora, random-number implementation, and seeds. A faster implementation is useful only after matching the reference implementation.

Required primitives:

- Standard and keyed alphabets, explicit forward/inverse index maps, rotations, reversal, modular addition/subtraction.
- Vigenère, Beaufort, variant Beaufort, and explicitly defined Quagmire variants.
- Plaintext and ciphertext autokey; progressive and interrupted key rules.
- Substitution and permutation composition with explicit direction conventions.
- Ragged columnar, route, and selected two-stage transpositions.
- Gromark-style recurrence generators and bounded generalized variants.
- Modular linear algebra for small matrix models; distinguish arithmetic modulo 26 from arithmetic in a field.
- Exact crib propagation, candidate normalization, and position traces.

Minimum interfaces:

```text
encrypt(plaintext, model, key, external_material) -> ciphertext
 decrypt(ciphertext, model, key, external_material) -> plaintext
 validate_constraints(model, key, evidence) -> pass_or_certificate
 explain_position(index, model, key) -> intermediate_values
 canonicalize(model, key) -> equivalence_class_identifier
```

Tests must include independent known-answer vectors, random round trips, illegal-key rejection, all 26 letters, ragged boundaries, key offsets, and inverse permutations. A round trip alone is insufficient: mutually wrong encrypt/decrypt functions can agree.

Reproduce K1, K2, and K3 with documented methods. K1/K2 keyword fixtures can begin with Gillogly's published keys, but K2 must account for the later correction. K3 must specify the actual position permutation rather than simply labeling it “rotation.” [Gillogly's account](https://www.elonka.com/kryptos/mirrors/cypherpunks/1999/0930.html); [Stein's firsthand report](https://www.elonka.com/kryptos/mirrors/daw/steinarticle.html).

For Gromark, use the ACA's worked example as a known-answer fixture, including its alphabet-construction convention. [ACA specification](https://www.cryptogram.org/downloads/aca.info/ciphers/Gromark.pdf).

**Gate:** primitives pass independent test vectors and the known Kryptos fixtures. Benchmark recovery on fresh synthetic examples before interpreting search failures on K4.

## 7. Phase 2 — exact exclusions before expensive search

**Owner:** A3. **Initial cap:** one agent workday.

The following baseline calculations were executed while preparing this plan. Reproduce them as regression fixtures, then have A7 independently verify the logic.

**A. Pure transposition is incompatible with the anchors.** The ciphertext contains two E's; the fixed plaintext anchors alone require three. A permutation of exactly these 97 letters preserves their multiset. This rejects pure transposition with no substitutions, omissions, or additions. It does not reject a transposition stage inside a compound cipher.

**B. A fixed monoalphabetic substitution is incompatible with the anchors.** The plaintext E appears at positions 22, 31, and 65 and corresponds to F, G, and Y. A fixed function cannot map one input letter to three different outputs. Conversely, ciphertext Q at positions 26 and 27 corresponds to different plaintext letters, ruling out a fixed single-letter decryption map there.

**C. Ordinary A–Z repeating Vigenère has strong period exclusions.** For `C_i = P_i + K_(i mod t) mod 26`, derive every known key value. Reject any period t when two known positions sharing a residue class demand different values. All periods 1–26 fail. Among periods 1–52, only 27, 28, and 29 survive this necessary test. Periods 53–97 also survive it. Survival is not a solution or a complete key recovery.

**D. Index of coincidence is low.** Computed from the normalized ciphertext:

```text
sum(f * (f - 1)) / (97 * 96) = 336 / 9312 = 0.03608247422680412
```

This is descriptive evidence; low IC does not establish a one-time pad or identify a particular cipher.

**E. No-self-encryption restrictions must be scoped.** At position 74, K encrypts to K in the published correspondence. This rejects a direct aligned mechanism that prohibits all fixed points. It does not automatically reject a composite construction whose internal letters differ from the final aligned pair.

Generalize these checks to each alphabet and sign convention rather than transferring conclusions across models. Generate a small contradiction witness for every exact rejection: the assumptions, the positions, and the incompatible equations.

**Gate:** exclusions label the precise family and range. “Impossible under model X” and “search found nothing” must be different result types.

## 8. Phase 3 — reproduce and calibrate statistical diagnosis

**Owner:** A3 with A6. **Initial cap:** three agent workdays plus bounded simulations.

Implement a registered battery: monogram counts, IC, lag coincidences, repeated n-grams and spacing, bigram counts across offsets, runs, and crib-derived differences under declared alphabets. Test lag/width effects across a stated range, such as 1–48, so an interesting width is not treated as if selected in advance.

Reproduce the width-21 investigation and the baseline Gromark constraint results in Bean's work. The accompanying repository documents 39 surviving base-10, length-five primers under its generalized alphabet assumptions. Reproduce the result before extending it; do not confuse it with the stricter standard ACA construction. [Bean's reproducibility repository](https://github.com/RichardBean/k4testing).

Use three null ensembles:

1. Uniform A–Z strings of length 97, for an initial random baseline.
2. Random permutations of K4, preserving its letter counts, for positional-pattern questions.
3. Synthetic 97-character messages encrypted with each candidate family, for model comparison and attack calibration.

For each proposed statistic, record the choice of null and why it answers the question. For adaptive searches, run the complete selection procedure on null data: all widths, alphabet choices, offsets, score tuning, and best-candidate selection. Comparing the selected K4 maximum to a single unselected null statistic is invalid.

Begin with 10,000 null samples. Increase only when the estimate needs finer resolution. Report Monte Carlo counts and uncertainty; `(r+1)/(N+1)` is a useful finite-sample estimate, and zero exceedances must not be reported as probability zero. For a fixed preregistered family use a maximum-statistic procedure or an explicit multiple-testing correction.

If using a cipher classifier, train and evaluate at length 97 with unfamiliar keys, held-out source texts, compound ciphers, and an “unknown” outcome. Its score is a ranking aid, not a verdict. [Nuhn and Knight's original classifier paper](https://aclanthology.org/D14-1185/); [Leierzopf and colleagues' later classification study](https://ecp.ep.liu.se/index.php/histocrypt/article/view/164).

**Gate:** preserve reproducible statistics, effect sizes, null definitions, and simulation seeds. No cipher family is permanently removed because a classifier dislikes it.

## 9. Phase 4 — prioritized cryptanalytic attacks

The ordering below is a proposed engineering allocation. It is not a claim that the first family is the actual K4 mechanism.

### Track A — keyed alphabets and structured key schedules

**Owner:** A4. **Priority:** first wave.

Start with standard A–Z and the deduplicated KRYPTOS alphabet:

```text
KRYPTOSABCDEFGHIJLMNQUVWXZ
```

Add reversed versions and documented tableau conventions as explicit branches. Explore separately keyed plaintext and ciphertext alphabets only after the fixed-alphabet branches.

For a general additive model, let `a` and `b` map letters to positions in plaintext and ciphertext alphabets:

```text
b(C_i) = a(P_i) + k_i (mod 26)
```

For each crib position, derive constraints. If two positions share a key state, their alphabet relationships must be consistent. With fixed alphabets, calculate key residues directly. With unknown alphabets, constrain each map to be a permutation of 0–25.

Experiments:

1. Enumerate periods 1–97 using constraint rejection before key search. Prioritize short periods; count unconstrained key slots and the resulting degrees of freedom.
2. Search a frozen keyword dictionary and independently justified contextual keywords, preserving exact deduplication and indicator conventions.
3. Test plaintext/ciphertext autokey seed lengths 1–32. Propagate crib chains in both directions wherever the model permits.
4. Test progressive-key models with all 26 increments and periods 1–32.
5. Test interrupted keys with at most two resets, initially at independently motivated boundaries. Count every reset as a parameter.
6. Use constraint solving for feasibility and heuristic search for language quality. Save SAT/UNSAT/UNKNOWN distinctly. Only claim an UNSAT exclusion for the exact encoded domain, reviewed for modeling errors.

Use alphabet-rotation or other symmetry breaking only when equivalence has been proven. A convenient restriction that changes the allowed models is not symmetry breaking.

**Promotion criterion:** exact anchors, a specified key mechanism, and benchmark evidence that the attack can recover planted examples. A long key that simply restates a chosen plaintext is not a discovery.

### Track B — recurrence-generated keys

**Owner:** A4 with A6. **Priority:** first wave.

The standard five-digit Gromark recurrence is an appropriate starting fixture. For an explicitly declared generalization of primer length r and base b:

```text
k_(i+r) = (k_i + k_(i+1)) mod b
```

Keep recurrence arithmetic modulo b separate from letter arithmetic modulo 26. State how generated symbols become shifts. Standard Gromark definitions and mixed-alphabet construction are given by the [ACA](https://www.cryptogram.org/downloads/aca.info/ciphers/Gromark.pdf).

Steps:

1. Reproduce the published implementation and survivor counts at a pinned commit.
2. Enumerate primer domains only after estimating `b^r`. Initially consider bases 3–12 and r=2–6; give every pair its own budget and coverage record. Add base 26 with short primers in a separate queue.
3. Filter primers by exact crib constraints before solving alphabet permutations.
4. For each survivor, use modular constraints and all-different conditions to solve or restrict alphabets. Rank by a fixed language model only after satisfying constraints.
5. If justified, extend to a bounded recurrence grammar: two fixed taps, modular addition/subtraction, and a fixed output mapping. Enumerate tap choices and penalize added complexity.
6. Test field-based recurrences separately. Do not apply algorithms requiring a field directly to arithmetic modulo 26 or an arbitrary composite base.
7. Compare attacks on K4 against planted recurrence ciphers and null inputs; a model that produces persuasive text on random input has weak evidential value.

Do not describe already-covered primer spaces as new work. Document exactly what changed: extra constraints, more complete alphabet solving, different recurrence, or new source-supported key material.

### Track C — running keys and documentary sources

**Owners:** A1, A4, A6. **Priority:** first wave, small initial corpus.

For each declared alphabet/sign convention, derive the required running-key characters at all 24 known positions. Search for source passages that match the two key fragments at their exact separation.

Corpus tiers:

1. K1–K3 and the tableau, with physical and corrected forms separated.
2. Exact editions of sources connected with the work, including Howard Carter materials and Sanborn's public explanations.
3. Dated source material related to the confirmed historical context, with a documented reason for inclusion.
4. Broader text collections, only after measuring the expected cost and accidental-match rate.

Freeze Unicode, punctuation, spelling, whitespace, and digit normalization before matching. Allow only named variants; report every source offset, edition, and normalization tried. Search key material in both directions only as declared branches.

When no external text is known, a joint language model for plaintext and running key is exploratory. It cannot authenticate its own fluent pair. Record whether each key symbol came from an independently existing source or was inferred to fit a proposed message.

**Promotion criterion:** a reproducible, independently sourced key extraction with exact matches and successful full decryption. Arbitrary page jumps and per-letter cherry-picking fail.

### Track D — compound substitution and transposition

**Owner:** A5 with A6. **Priority:** second wave, bounded from the start.

Pure transposition is already excluded for the baseline. Test compound models with explicit order:

```text
substitute_then_permute
permute_then_substitute
```

Initial permutation families:

- Physical inscription routes and documented tableau alignments.
- Row/column reading, reversal, and boustrophedon routes with explicit ragged-cell rules.
- Ragged columnar widths 2–32; exhaustive column ordering initially only through width 8.
- Small, evidence-motivated compositions of two routes.
- Circular strides and rotations as a finite baseline; with length 97 there are 96 nonzero invertible strides, each with 97 starts.

Do not add padding merely because 97 is inconvenient. A 98-character question-mark variant needs a 27-symbol or other explicit representation, consistent normalization, and a reason to adopt it.

Transport cribs through each permutation correctly. Use alternating optimization, branch and bound, or beam search where feasible. Check small instances exhaustively to detect errors in the optimizer. Record exactly which permutations were covered.

The width-21 pattern is one hypothesis generator; it is not permission to impose a 21-column model on every experiment.

### Track E — clock, directions, and physical structure

**Owners:** A1 and A5. **Priority:** parallel evidence work, restricted compute.

Treat “BERLINCLOCK” as a contextual instruction whose relevance to the algorithm still needs demonstration. A clock being mentioned in plaintext does not imply its display generates the encryption key.

Steps:

1. Identify primary descriptions and dated images of the Berlin World Clock and relevant sculpture components.
2. Prefer historically appropriate configurations. Modern city labels or restorations cannot automatically be used as 1989 key material.
3. Define finite hypotheses using independently measurable properties: sector order, rotation, city-name ordering, compass directions, or a reading route.
4. Specify starting point, direction, datum, units, and uncertainty before examining output. Distinguish true versus magnetic directions if bearings are used.
5. Derive all 97 transformations from the proposed rule. Prohibit a separate lookup value for each troublesome letter.
6. Test how sensitive the result is to measurement uncertainty and plausible alternative starts. A construction that only works at an arbitrary high-precision coordinate is suspect.
7. Give old set-theory-clock hypotheses low priority unless fresh evidence supports them. The November 2025 clarification changes their historical motivation.

**Promotion criterion:** independent physical/historical evidence determines a compact transformation with predictive value beyond the known anchors.

### Track F — matrix and fractionating models

**Owners:** A4 and A5. **Priority:** bounded residual search.

The matrix-encryption conjecture is published prior work, but the full article was not accessible during this research. Obtain it before representing its actual tested coverage. [Bauer, Link, and Molle, publication DOI](https://www.tandfonline.com/doi/full/10.1080/01611194.2016.1141556).

For small Hill-style models, begin with block sizes 2 and 3 and all block phases. Require an explicit treatment of the incomplete final block. Solve modulo 2 and modulo 13 and combine where appropriate; check invertibility modulo 26. If an affine offset is allowed, encode it as a separate parameter.

For fractionating or digraphic ciphers, audit alphabet size, pair constraints, padding, and the occurrence of all 26 letters before optimization. A length incompatibility rejects only the precise unpadded model. Extensions must specify their mechanism and cost.

Keep this branch small unless a hard constraint or historical clue makes a particular variant attractive.

## 10. Phase 5 — scoring without manufacturing answers

**Owner:** A6. Applies to every heuristic track.

Use a fixed baseline character language model, such as smoothed 4–6-gram log probabilities, trained on documented non-Kryptos text. Use a second model trained on an independent corpus as a robustness check. Tune on synthetic development ciphers, then freeze weights before evaluation.

Hard gates precede ranking:

1. Correct length and alphabet under the declared model.
2. All fixed anchors in the correct final positions.
3. Valid key domain, invertible transformations where required, and no undeclared edits.
4. Deterministic reencryption matching every ciphertext character.

Among passing candidates, record separately:

- Language likelihood, both full-text and on windows excluding fixed anchors.
- Key and model description length.
- Documentary/physical provenance.
- Best-of-search score relative to the identical search procedure on null inputs.
- Stability across random restarts, independent implementations, and scoring corpora.

A possible research ranking is `log P_language(P) - lambda * description_bits(model,key,exceptions)`. Lambda and the coding scheme must be set before K4 comparison. This is an operational ranking, not a posterior probability or proof. Large external dictionaries and candidate-source selection also contribute search freedom.

The key circularity test is simple. Under Vigenère, any proposed P implies `K = C - P mod 26`; encrypting P with that K will exactly recover C. This proves compatibility only. Demand a reason the key should exist independently of that chosen P.

Crib holdouts are useful but limited. Train an experiment on EASTNORTHEAST and evaluate BERLINCLOCK, and vice versa, with the hidden block excluded from objective functions and tuning. Since agents may already know all the clues, call this an ablation unless genuine isolation is maintained. Use fresh synthetic messages for genuinely blind validation.

Agents may propose interpretations after a candidate passes mechanical gates. They may not repair spelling, insert words, or rearrange plaintext to improve the score. Any proposed transcription error creates a separately named model with an explicit exception budget.

## 11. Phase 6 — independent verification and authentication

**Owner:** A7. **Initial cap:** one agent workday per serious candidate.

A candidate dossier must contain:

- Evidence-manifest hash and algorithm specification.
- Full key, key derivation, external inputs, and all normalization rules.
- An executable reference decryptor and encryptor.
- A 97-row trace of inputs, internal states, output letters, and crib checks.
- Search manifest, seeds, evaluated counts, and total model-selection history.
- Synthetic recovery and false-positive results.
- A list of every manual choice, exception, and unresolved historical issue.

Verification procedure:

1. Implement the algorithm from prose in fresh code; derive the plaintext without being handed it as input.
2. Match all ciphertext characters on reencryption and all fixed anchors on decryption.
3. Inspect the implementation for plaintext lookups, hidden constants, arbitrary per-position shifts, and hardcoded repair steps.
4. Assess key provenance and the number of compatible alternative plaintexts. Search for alternative models of similar complexity, including adversarially constructed fluent outputs.
5. Perform model-specific ablations. Do not demand avalanche behavior from a classical cipher; instead test whether claimed components actually constrain its result.
6. Reproduce search results using independent seeds and the frozen scoring rules, when relevant.
7. Check that the method remains well-defined on additional messages generated within its stated domain. This checks the specification; it does not establish historical authenticity.
8. Classify the result as incompatible, underdetermined fit, promising candidate, independently reproduced candidate, authenticated plaintext, or historically authenticated mechanism.
9. For a candidate warranting external confirmation, prepare the exact submission packet and verify the current legitimate verification procedure. This planning request does not authorize agents to send messages, pay fees, or submit claims on the user's behalf.

A plaintext verifier may authenticate the words without authenticating the mechanism. Preserve that distinction in the final report.

## 12. Experiment contract for every worker

No agent begins a search without a manifest. Suggested schema:

```yaml
experiment_id: K4-A-0001
owner: A4
parent_experiment: null
evidence_version: sha256
question: Is this precisely defined family consistent with the anchors?
model:
  family: repeating_additive
  plaintext_alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ
  ciphertext_alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ
  equation: c_i_equals_p_i_plus_k_i_mod_26
  period_range_inclusive: [1, 97]
  preprocessing: none
  key_phase: canonical_zero
  exceptions: []
constraints:
  training_cribs: [EAST, NORTHEAST, BERLIN, CLOCK]
  holdout_cribs: []
search:
  method: exact_crib_consistency
  random_seed: null
  domain_size: 97
  evaluation_cap: 97
  wall_time_cap_seconds: 60
  external_spend_cap: 0
validation:
  reference_implementation: required
  planted_cases: required_for_search_algorithms
  null_pipeline: required_for_statistical_claims
outputs:
  - survivors.json
  - contradictions.jsonl
  - report.md
status: planned
```

Completion reports contain actual counters, elapsed time, memory use, exit status, and a precise statement of what was or was not excluded. `timeout`, `solver_unknown`, and `no_candidate_found` are not synonyms for `unsatisfiable`.

Checkpoint deterministic shards. Canonicalize equivalent keys and transformations before scheduling. Keep an append-only registry; never overwrite a disappointing run with a better one.

The shared project should contain evidence, fixtures, models, experiments, results, and reports in separate directories. A worker owns one experiment output directory; the coordinator controls shared evidence and the registry.

## 13. Proposed compute and scheduling budget

Use a local pilot before requesting large compute. LLMs should write, inspect, and interpret experiments; deterministic processes should evaluate millions of keys.

| Stage | Initial budget | Required return before expansion |
|---|---|---|
| Evidence and harness | First 3–5 working days | Frozen baseline; trusted implementations |
| Exact diagnosis | 1 CPU core-hour per small experiment | Contradictions and survivor counts |
| Heuristic pilot | 10 core-hours per promoted family | Synthetic recovery and throughput |
| First search campaign | 500 total CPU core-hours | Coverage ledger and candidate/null comparison |
| GPU work | None initially | Benchmark demonstrating a useful acceleration |
| New compute purchase | None assumed | Measured cost estimate and explicit user budget |

Suggested allocation of the 500-core-hour campaign: 30% structured polyalphabetic/autokey; 25% generated keys; 20% compound transpositions; 10% documentary running keys; 10% verification/null runs; 5% matrix, fractionating, and other bounded hypotheses. Evidence findings may change the allocation.

If the campaign becomes dominated by false positives, transfer budget from searching to null experiments and model restriction. If no model has adequate synthetic recovery, improve the attack before spending more time on K4.

Calibrate with a starting suite of 100 fresh synthetic cases per major family, matched to length 97 and the intended amount of known plaintext. Report exact-recovery rates by key difficulty and confidence intervals. An operational target might be at least 90% recovery in the deliberately bounded pilot domain; this threshold is a project gate, not a general property of the cipher.

A first ten-working-day cycle:

| Days | Work | Decision |
|---|---|---|
| 1–2 | Evidence/status audit; primitive fixtures | Freeze data or resolve discrepancies |
| 3–4 | Exact exclusions; reproduce published baselines | Approve specific model domains |
| 5–6 | Synthetic benchmarks and scoring calibration | Approve only working attacks |
| 7–9 | Parallel bounded searches; independent verification | Promote candidates or record coverage |
| 10 | Red-team review and planning | Continue, change hypotheses, or stop |

This is a schedule for producing useful research, not a promised solution date.

## 14. Stop rules and reporting discipline

Stop or redesign a branch when:

- An independently verified exact contradiction rejects its defined domain.
- The fixed enumeration is exhausted with no admissible key.
- Synthetic examples cannot be recovered reliably enough to interpret K4 failure.
- Apparent English is equally common after the same search on null data.
- Additional progress requires arbitrary exceptions or a key whose information simply encodes the answer.
- The compute cap is reached without a specific, evidence-based reason to extend it.

Do not say “all Vigenère,” “all transpositions,” or “all running keys were tried” when only particular keys and ranges were searched.

Daily coordinator report, maximum one page:

1. New verified evidence.
2. Models exactly excluded and their assumptions.
3. Search domains actually covered.
4. Surviving candidates and their present validation status.
5. Bugs, source gaps, and reasons earlier results became invalid.
6. Next three experiments and the information each is expected to provide.

A useful campaign can end with no solution and still deliver a verified corpus, reusable solvers, exact exclusions, and defensible coverage. The agents must preserve that outcome rather than invent closure.

## 15. Research map and remaining access gaps

The preparation searched current status, original clues, archival developments, historical solutions, cryptanalytic papers, cipher specifications, and reproducible code. Sources were deduplicated conceptually; syndicated reports and repeated search snippets do not count as independent confirmation. The following is a focused reading queue rather than an assertion that every linked item was fully examined.

| Source | Access during preparation | Value and next action |
|---|---|---|
| [Dunin's Kryptos collection](https://www.elonka.com/kryptos/) | Read | Clue chronology and firsthand visual material; follow links to original evidence |
| [Complete transcript](https://www.elonka.com/kryptos/transcript.html) | Opened | Freeze inscription and tableau separately; independently compare images |
| [Gillogly's 1999 account](https://www.elonka.com/kryptos/mirrors/cypherpunks/1999/0930.html) | Read | K1–K3 keys and early hypotheses; historical K2 needs correction |
| [Stein's report](https://www.elonka.com/kryptos/mirrors/daw/steinarticle.html) | Partially inspected | Primary cryptanalytic account; read fully during baseline reconstruction |
| [K2 correction](https://www.elonka.com/kryptos/CorrectedK2Announcement.html) | Opened | Prevent outdated plaintext from contaminating key-source searches |
| [Dunin's FOIA account](https://www.elonka.com/kryptos/foia.html) | Read | Leads to declassified NSA material; underlying NSA destination failed to open |
| [Bean 2021, full PDF](https://ecp.ep.liu.se/index.php/histocrypt/article/download/153/109) | Substantial technical sections read | Reproduce diagnosis and audit historical assumptions against later clues |
| [Bean's code](https://github.com/RichardBean/k4testing) | README and inventory read | Pin commit and inspect code before execution; contains an executable reproduction route |
| [ACA Gromark specification](https://www.cryptogram.org/downloads/aca.info/ciphers/Gromark.pdf) | Read | Known-answer vector and precise standard definition |
| [Bauer–Link–Molle matrix conjecture](https://www.tandfonline.com/doi/full/10.1080/01611194.2016.1141556) | Metadata located; full article unavailable | Do not assert its tested bounds until obtained |
| [Oranchak's Kryptos repository](https://github.com/doranchak/kryptos) | Repository overview read | Prior experiments, tool links, and literature discovery; code not audited here |
| [Nuhn–Knight classifier paper](https://aclanthology.org/D14-1185/) | Paper read in part | Synthetic data and cipher classification; do not transfer published accuracy to K4 |
| [Leierzopf et al., HistoCrypt 2021](https://ecp.ep.liu.se/index.php/histocrypt/article/view/164) | Abstract and record read | Expanded classifier literature; obtain full experimental details before reuse |
| [Lasry's metaheuristic methodology](https://kobra.uni-kassel.de/items/74307bf4-bf8c-4db7-8c18-4997db1c5465) | Bibliographic record located; full text blocked | Priority methodology reading; proposed search settings here are not quoted from the thesis |
| [Sanborn's August 2025 letter](https://www.elonka.com/kryptos/OpenLetterAug2025.html) | Read | Primary statement on stewardship, AI claims, and continuing riddle |
| [November 2025 presentation coverage](https://www.scientificamerican.com/article/cia-kryptos-puzzle-creator-releases-final-clues/) | Read | Firsthand report of newer clues; linked original letter failed to retrieve |
| [AP archive/auction report](https://apnews.com/article/cb8ee8554ca473910cbd0592f8bdb350) | Search report available | Archive discovery and auction context; corroborate exact provenance in Phase 0 |
| [June 2026 stewardship report](https://www.wired.com/story/crypto-guys-bought-the-answer-to-the-cias-mysterious-kryptos-sculpture/) | Opened; reporting inspected | Updated verification route; do not infer present availability or fees without rechecking |
| [Paradigm Project Kryptos](https://www.paradigm.xyz/2026/06/kryptos) | Indexed announcement found; direct retrieval failed | Recheck live primary source before operational use |
| [Paradigm CTF rules](https://paradigm.xyz/kryptos-ctf/rules) | Indexed rules found | Separate benchmark contest, not evidence of the historical K4 mechanism |
| [Smithsonian Sanborn oral history](https://www.aaa.si.edu/collections/interviews/oral-history-interview-jim-sanborn-15700) | Identified via citations; retrieval failed | Historical statements; do not treat inaccessible content as reviewed |

Do not ingest unauthenticated “solution” websites as ground truth. Archive a claimed method only with its author, timestamp, exact algorithm, and whether the key was fitted after choosing the plaintext.

## 16. Coordinator launch prompt

> Execute this plan as a reproducible research program. Begin with Phase 0 and establish current status before scheduling cryptanalysis. Freeze the ciphertext and fixed anchors. Build and independently test the cipher machinery, reproduce the exact exclusions, then benchmark bounded attacks on fresh synthetic ciphers. Every experiment requires a manifest, budget, output files, and an explicit falsification criterion. Treat research papers as hypotheses and methods whose scope must be reproduced. Keep proposed plaintexts separate from evidence. Require exact full reencryption and independent key provenance for serious candidates. Do not claim success from fluent text, matching anchors, an arbitrary recovered keystream, or agent agreement. Prepare external verification only after an independent dossier passes review; do not submit, spend, or contact anyone without authorization. Preserve all negative results and report uncertainty precisely.
