#!/usr/bin/env python3
"""Independently verify K4 evidence and exact baseline rejection certificates.

This standard-library implementation does not import, invoke, or inspect the Rust
implementation. Passing a necessary condition does not identify a cipher or key.
All positions used internally are zero-based, and intervals are half-open.
"""

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import string
import sys


ALPHABET = string.ascii_uppercase
FAMILIES = (
    "pure_transposition",
    "fixed_monoalphabetic_encryption",
    "fixed_monoalphabetic_decryption",
    "no_self_encryption",
)


class VerificationError(ValueError):
    """Evidence or a purported certificate violates the declared model."""


def require(condition, message):
    """Raise a diagnostic error when a verification condition fails."""
    if not condition:
        raise VerificationError(message)


def is_integer(value):
    """JSON booleans are not valid integer positions or counts."""
    return type(value) is int


def is_letters(value):
    """Recognize nonempty, already normalized ASCII uppercase text."""
    return isinstance(value, str) and bool(value) and all(c in ALPHABET for c in value)


def position_record(ciphertext, known, index):
    """Describe an anchored position and its directly implied Vigenere shift."""
    require(is_integer(index) and index in known, "certificate position is not anchored")
    plain = known[index]
    cipher = ciphertext[index]
    return {
        "index_zero_based": index,
        "position_one_based": index + 1,
        "plaintext": plain,
        "ciphertext": cipher,
        "vigenere_key_value": (ord(cipher) - ord(plain)) % 26,
    }


def derive_baseline(ciphertext, known):
    """Compute exact diagnostics for any normalized text and partial plaintext.

    ``known`` maps distinct zero-based indices to single uppercase letters. The
    index of coincidence is undefined for fewer than two ciphertext symbols.
    """
    require(is_letters(ciphertext), "ciphertext must be nonempty uppercase A-Z")
    require(isinstance(known, dict), "known plaintext must be a position mapping")
    for index, plain in known.items():
        require(is_integer(index) and 0 <= index < len(ciphertext), "invalid known position")
        require(is_letters(plain) and len(plain) == 1, "invalid known plaintext letter")
    counts = Counter(ciphertext)
    plain_counts = Counter(known.values())
    positions = [position_record(ciphertext, known, index) for index in sorted(known)]
    numerator = sum(count * (count - 1) for count in counts.values())
    denominator = len(ciphertext) * (len(ciphertext) - 1)
    deficits = [
        {"letter": letter, "required": count, "available": counts[letter]}
        for letter, count in sorted(plain_counts.items())
        if count > counts[letter]
    ]
    encryption_conflicts = []
    decryption_conflicts = []
    for left_offset, left in enumerate(positions):
        for right in positions[left_offset + 1:]:
            pair = [left["index_zero_based"], right["index_zero_based"]]
            if left["plaintext"] == right["plaintext"] and left["ciphertext"] != right["ciphertext"]:
                encryption_conflicts.append(pair)
            if left["ciphertext"] == right["ciphertext"] and left["plaintext"] != right["plaintext"]:
                decryption_conflicts.append(pair)
    fixed_points = [p["index_zero_based"] for p in positions if p["plaintext"] == p["ciphertext"]]
    periods = []
    for period in range(1, len(ciphertext) + 1):
        # Pairwise equality is deliberately used instead of the Rust
        # implementation's constraint propagation or any search procedure.
        conflicts = [
            [left["index_zero_based"], right["index_zero_based"]]
            for offset, left in enumerate(positions)
            for right in positions[offset + 1:]
            if (left["index_zero_based"] - right["index_zero_based"]) % period == 0
            and left["vigenere_key_value"] != right["vigenere_key_value"]
        ]
        constrained = len({index % period for index in known})
        periods.append({
            "period": period,
            "compatible": not conflicts,
            "constrained_slots": constrained,
            "unconstrained_slots": period - constrained,
            "conflicts": conflicts,
        })
    return {
        "ciphertext_length": len(ciphertext),
        "known_plaintext_count": len(known),
        "letter_counts": {letter: counts[letter] for letter in ALPHABET},
        "ic": {"numerator": numerator, "denominator": denominator,
               "value": numerator / denominator if denominator else None},
        "positions": positions,
        "transposition_deficits": deficits,
        "encryption_conflicts": encryption_conflicts,
        "decryption_conflicts": decryption_conflicts,
        "fixed_points": fixed_points,
        "periods": periods,
        "surviving_periods": [p["period"] for p in periods if p["compatible"]],
    }


def verify_position(record, ciphertext, known):
    """Validate all redundant fields of a supplied position certificate."""
    require(isinstance(record, dict), "position certificate must be an object")
    expected = position_record(ciphertext, known, record.get("index_zero_based"))
    require(record == expected, "position certificate does not match anchored evidence")
    return record["index_zero_based"]


def verify_witness(family, witness, ciphertext, known):
    """Check a family rejection witness without trusting its claimed counts."""
    require(isinstance(witness, dict), "rejection requires a witness object")
    if family == "pure_transposition":
        require(witness.get("kind") == "letter_deficit", "wrong transposition witness kind")
        letter = witness.get("letter")
        require(is_letters(letter) and len(letter) == 1, "invalid deficit letter")
        positions = sorted(index for index, plain in known.items() if plain == letter)
        require(witness.get("positions_zero_based") == positions, "deficit positions do not match anchors")
        require(witness.get("required") == len(positions), "incorrect required multiplicity")
        require(witness.get("available") == ciphertext.count(letter), "incorrect available multiplicity")
        require(len(positions) > ciphertext.count(letter), "letter deficit does not reject transposition")
    elif family in ("fixed_monoalphabetic_encryption", "fixed_monoalphabetic_decryption"):
        direction = family.removeprefix("fixed_monoalphabetic_")
        require(witness.get("kind") == "mapping_conflict", "wrong mapping witness kind")
        require(witness.get("direction") == direction, "wrong mapping direction")
        first = verify_position(witness.get("first"), ciphertext, known)
        second = verify_position(witness.get("second"), ciphertext, known)
        if direction == "encryption":
            valid = known[first] == known[second] and ciphertext[first] != ciphertext[second]
        else:
            valid = ciphertext[first] == ciphertext[second] and known[first] != known[second]
        require(valid, "mapping witness does not demonstrate conflicting images")
    elif family == "no_self_encryption":
        require(witness.get("kind") == "fixed_point", "wrong fixed-point witness kind")
        index = verify_position(witness.get("position"), ciphertext, known)
        require(known[index] == ciphertext[index], "fixed-point witness is not a fixed point")
    else:
        raise VerificationError(f"unknown baseline family: {family}")


def verify_period_witness(period, witness, ciphertext, known):
    """Prove a contradiction between shifts at one repeating-key residue."""
    require(is_integer(period) and period > 0, "period must be a positive integer")
    require(isinstance(witness, dict) and witness.get("kind") == "period_conflict", "wrong period witness kind")
    first = verify_position(witness.get("first"), ciphertext, known)
    second = verify_position(witness.get("second"), ciphertext, known)
    require(first % period == second % period == witness.get("residue"), "period witness indices do not share the claimed residue")
    left_shift = (ord(ciphertext[first]) - ord(known[first])) % 26
    right_shift = (ord(ciphertext[second]) - ord(known[second])) % 26
    require(left_shift != right_shift, "period witness shifts do not conflict")


def verify_report(report, evidence, known, derived):
    """Cross-check the full Rust baseline report, accepting any valid witness."""
    require(isinstance(report, dict), "report must be an object")
    require(report.get("schema_version") == 1, "unsupported report schema")
    require(report.get("evidence_id") == evidence["evidence_id"], "report evidence ID differs")
    for name in ("ciphertext_length", "known_plaintext_count", "letter_counts", "positions"):
        require(report.get(name) == derived[name], f"report {name} differs from independent result")
    claimed_ic = report.get("ic")
    require(isinstance(claimed_ic, dict), "missing IC object")
    for name in ("numerator", "denominator"):
        require(claimed_ic.get(name) == derived["ic"][name], f"incorrect IC {name}")
    value = claimed_ic.get("value")
    require(type(value) in (int, float) and math.isfinite(value)
            and math.isclose(value, derived["ic"]["value"], rel_tol=0, abs_tol=1e-15), "incorrect IC value")
    checks = report.get("checks")
    require(isinstance(checks, list) and len(checks) == len(FAMILIES), "report must contain four family checks")
    require({check.get("family") for check in checks if isinstance(check, dict)} == set(FAMILIES), "missing or repeated baseline families")
    contradictions = dict(zip(FAMILIES, (
        derived["transposition_deficits"], derived["encryption_conflicts"],
        derived["decryption_conflicts"], derived["fixed_points"],
    )))
    for check in checks:
        family = check["family"]
        assumptions = check.get("assumptions")
        require(isinstance(assumptions, list) and assumptions
                and all(isinstance(item, str) and item.strip() for item in assumptions), "check must declare assumptions")
        rejected = bool(contradictions[family])
        status = "rejected" if rejected else "necessary_condition_passed"
        require(check.get("status") == status, f"incorrect {family} status")
        if rejected:
            verify_witness(family, check.get("witness"), evidence["ciphertext"], known)
        else:
            require(check.get("witness") is None, "passing check must not have a rejection witness")
    vigenere = report.get("vigenere")
    require(isinstance(vigenere, dict), "missing Vigenere report")
    require(vigenere.get("alphabet") == ALPHABET, "Vigenere alphabet differs")
    require(vigenere.get("equation") == "c_i = p_i + k_(i mod t) (mod 26)", "Vigenere equation differs")
    require(vigenere.get("surviving_periods") == derived["surviving_periods"], "incorrect surviving periods")
    periods = vigenere.get("periods")
    require(isinstance(periods, list) and len(periods) == len(derived["periods"]), "incomplete period coverage")
    for claimed, expected in zip(periods, derived["periods"]):
        require(isinstance(claimed, dict), "period result must be an object")
        for name in ("period", "constrained_slots", "unconstrained_slots"):
            require(claimed.get(name) == expected[name], f"incorrect period {name}")
        status = "necessary_condition_passed" if expected["compatible"] else "rejected"
        require(claimed.get("status") == status, "incorrect period status")
        if expected["compatible"]:
            require(claimed.get("witness") is None, "passing period must not have a witness")
        else:
            verify_period_witness(expected["period"], claimed.get("witness"), evidence["ciphertext"], known)


def validate_evidence(evidence):
    """Validate the versioned 97-letter manifest and return its known positions."""
    require(isinstance(evidence, dict), "evidence must be an object")
    require(type(evidence.get("schema_version")) is int and evidence["schema_version"] == 1,
            "unsupported evidence schema")
    require(isinstance(evidence.get("evidence_id"), str) and evidence["evidence_id"].strip(),
            "evidence ID is missing")
    require(evidence.get("alphabet") == ALPHABET, "evidence alphabet differs")
    require(evidence.get("indexing") == "zero_based_half_open", "evidence indexing differs")
    require(evidence.get("normalization") == "uppercase_ascii_no_whitespace_no_question_mark",
            "evidence normalization differs")
    cipher = evidence.get("ciphertext")
    require(is_letters(cipher) and len(cipher) == 97, "baseline must have 97 uppercase letters")
    lines = evidence.get("physical_lines")
    require(isinstance(lines, list) and all(is_letters(line) for line in lines), "invalid physical lines")
    require(list(map(len, lines)) == [4, 31, 31, 31] and "".join(lines) == cipher,
            "physical lines disagree with baseline")
    sources = evidence.get("source_ids")
    require(isinstance(sources, list) and all(isinstance(s, str) and s.strip() for s in sources),
            "invalid source references")
    require(len(set(sources)) == len(sources) and len(sources) >= 2, "sources must be distinct")
    transcriptions = evidence.get("transcriptions")
    require(isinstance(transcriptions, list) and len(transcriptions) >= 2, "two transcriptions required")
    seen_sources = set()
    for item in transcriptions:
        require(isinstance(item, dict), "transcription must be an object")
        source = item.get("source_id")
        require(source in sources and source not in seen_sources, "invalid transcription source")
        seen_sources.add(source)
        require(item.get("physical_lines") == lines and item.get("ciphertext") == cipher,
                "transcription disagrees with baseline")
    anchors = evidence.get("anchors")
    require(isinstance(anchors, list), "anchors must be a list")
    known, seen_ids = {}, set()
    for anchor in anchors:
        require(isinstance(anchor, dict), "anchor must be an object")
        identifier = anchor.get("id")
        require(isinstance(identifier, str) and identifier.strip() and identifier not in seen_ids,
                "anchor IDs must be distinct and nonempty")
        seen_ids.add(identifier)
        start, end = anchor.get("start"), anchor.get("end")
        require(is_integer(start) and is_integer(end) and 0 <= start < end <= len(cipher), "invalid anchor range")
        plain = anchor.get("plaintext")
        require(is_letters(plain) and len(plain) == end - start, "invalid anchor plaintext")
        require(anchor.get("ciphertext") == cipher[start:end], "anchor ciphertext differs")
        refs = anchor.get("source_ids")
        require(isinstance(refs, list) and refs and all(ref in sources for ref in refs), "invalid anchor source")
        for index, letter in enumerate(plain, start):
            require(index not in known, "overlapping anchors")
            known[index] = letter
    require(type(evidence.get("known_plaintext_count")) is int
            and evidence["known_plaintext_count"] == len(known) == 24, "expected 24 anchored letters")
    issues = evidence.get("unresolved_issues")
    require(isinstance(issues, list) and all(isinstance(s, str) and s.strip() for s in issues),
            "invalid unresolved issues")
    return known


def read_json(path):
    """Load UTF-8 JSON while rejecting duplicate keys and non-finite numbers."""
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON field: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise VerificationError(f"invalid JSON numeric constant: {value}")

    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def source_references(value):
    """Collect source ID references from nested evidence/reference records."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "source_ids":
                require(isinstance(item, list) and all(isinstance(s, str) for s in item),
                        "source_ids must be a list of strings")
                yield from item
            elif key == "source_id" or key.endswith("_source_id"):
                require(isinstance(item, str), "source_id must be a string")
                yield item
            else:
                yield from source_references(item)
    elif isinstance(value, list):
        for item in value:
            yield from source_references(item)


def verify_ledger(path, evidence, root):
    """Check source/claim references and any explicitly preserved local hashes.

    Null hashes mean no source document was preserved. A local hash authenticates
    stored bytes against the ledger, not the external author's assertions.
    """
    required = {"source_id", "url", "author", "published_at", "retrieved_at", "access",
                "source_type", "claim", "locator", "status", "supports", "contradicts", "content_hash"}
    sources = {}
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        require(bool(line.strip()), f"empty source ledger line {number}")
        record = json.loads(line)
        require(isinstance(record, dict) and required <= record.keys(), f"missing fields at source line {number}")
        identifier = record["source_id"]
        require(isinstance(identifier, str) and identifier not in sources, "duplicate or invalid source ID")
        require(record["access"] in {"full_text", "partial", "metadata_only", "unavailable"}, "invalid access class")
        require(record["status"] in {"verified", "attributed", "disputed", "superseded"}, "invalid source status")
        for field in ("supports", "contradicts"):
            require(isinstance(record[field], list) and all(isinstance(s, str) for s in record[field]), "invalid claim references")
        if record["content_hash"] is not None:
            local_path = record.get("local_path")
            require(isinstance(local_path, str), "hashed source needs a local_path")
            local_path = (root / local_path).resolve()
            require(local_path.is_relative_to(root.resolve()), "source path escapes project")
            require(hashlib.sha256(local_path.read_bytes()).hexdigest() == record["content_hash"], "source hash differs")
        sources[identifier] = record
    statements_path = root / "evidence/statements.jsonl"
    statements = [json.loads(line) for line in statements_path.read_text(encoding="utf-8").splitlines()]
    claim_ids = [item["claim_id"] for item in statements]
    require(len(set(claim_ids)) == len(claim_ids), "duplicate statement ID")
    reference = read_json(root / "evidence/reference-material.json")
    for identifier in source_references([evidence, statements, reference]):
        require(identifier in sources, f"unresolved source ID: {identifier}")
    for record in sources.values():
        for identifier in record["supports"] + record["contradicts"]:
            require(identifier in claim_ids, f"unresolved claim ID: {identifier}")
    return {"sources": len(sources), "statements": len(statements)}


def main(argv=None):
    """Run the independent derivation and optionally verify a Rust report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", nargs="?", default="evidence/k4.json")
    parser.add_argument("--report", help="Rust diagnosis JSON to check")
    parser.add_argument("--ledger", help="source JSONL to audit alongside project statements/reference material")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        evidence = read_json(args.evidence)
        known = validate_evidence(evidence)
        derived = derive_baseline(evidence["ciphertext"], known)
        if args.report:
            verify_report(read_json(args.report), evidence, known, derived)
        ledger = verify_ledger(args.ledger, evidence, args.root) if args.ledger else None
        result = {"status": "verified", "evidence_sha256": hashlib.sha256(Path(args.evidence).read_bytes()).hexdigest(),
                  "rust_report_checked": args.report is not None, "ledger": ledger, "derived": derived}
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
