#!/usr/bin/env python3
"""Independently enumerate and verify the structured-alphabet experiment."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from verify_baseline import read_json, validate_evidence
from verify_primers import expand

ROOT = Path(__file__).resolve().parents[1]
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CONSTRUCTIONS = [
    {"id": "az-forward", "order": AZ},
    {"id": "az-reversed", "order": AZ[::-1]},
    {"id": "kryptos-forward", "order": "KRYPTOSABCDEFGHIJLMNQUVWXZ"},
    {"id": "kryptos-reversed", "order": "KRYPTOSABCDEFGHIJLMNQUVWXZ"[::-1]},
]


def require_int(value, name, minimum=None, maximum=None):
    """Require a JSON integer while rejecting Python's bool subclass."""
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} is below its allowed range")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} is above its allowed range")
    return value


def validate_equation(equation, name):
    """Validate the strict serialized equation schema and all numeric types."""
    if not isinstance(equation, dict) or set(equation) != {
        "position", "plaintext", "ciphertext", "plaintext_index",
        "ciphertext_index", "key", "observed_residue", "required_residue",
    }:
        raise ValueError(f"invalid {name} schema")
    require_int(equation["position"], f"{name} position", 0, 96)
    require_int(equation["plaintext_index"], f"{name} plaintext index", 0, 25)
    require_int(equation["ciphertext_index"], f"{name} ciphertext index", 0, 25)
    require_int(equation["key"], f"{name} key", 0, 255)
    require_int(equation["observed_residue"], f"{name} observed residue", 0, 25)
    require_int(equation["required_residue"], f"{name} required residue", 0, 25)
    if (
        not isinstance(equation["plaintext"], str)
        or len(equation["plaintext"]) != 1
        or equation["plaintext"] not in AZ
        or not isinstance(equation["ciphertext"], str)
        or len(equation["ciphertext"]) != 1
        or equation["ciphertext"] not in AZ
    ):
        raise ValueError(f"invalid {name} letters")


def validate_identity_fields(record):
    """Reject type-confused candidate identity fields before value comparison."""
    for field in ("id", "primer", "plaintext_construction", "ciphertext_construction"):
        if not isinstance(record.get(field), str):
            raise ValueError(f"candidate {field} must be a string")
    require_int(record.get("ciphertext_rotation"), "candidate rotation", 0, 25)


def rotate_left(text, amount):
    """Rotate a string left by an explicit amount."""
    amount %= len(text)
    return text[amount:] + text[:amount]


def equation_trace(plain_order, cipher_order, ciphertext, known, key):
    """Evaluate all known positions using independently built index maps."""
    plain_indices = {letter: index for index, letter in enumerate(plain_order)}
    cipher_indices = {letter: index for index, letter in enumerate(cipher_order)}
    result = []
    for position, plaintext in sorted(known.items()):
        cipher = ciphertext[position]
        plain_index = plain_indices[plaintext]
        cipher_index = cipher_indices[cipher]
        result.append({
            "position": position,
            "plaintext": plaintext,
            "ciphertext": cipher,
            "plaintext_index": plain_index,
            "ciphertext_index": cipher_index,
            "key": key[position],
            "observed_residue": (cipher_index - plain_index) % 26,
            "required_residue": key[position],
        })
    return result


def validate_request(request, primer_report):
    """Require the exact preregistered finite domain."""
    expected_primers = [record["primer"] for record in primer_report["survivors"]]
    ids = [construction["id"] for construction in CONSTRUCTIONS]
    expected_pairs = [
        {"plaintext": plain, "ciphertext": cipher}
        for plain in ids
        for cipher in ids
    ]
    if set(request) != {
        "schema_version", "primers", "constructions", "alphabet_pairs",
        "ciphertext_rotations", "key_offset",
    }:
        raise ValueError("invalid request schema")
    if (
        type(request["schema_version"]) is not int
        or request["schema_version"] != 1
        or request["primers"] != expected_primers
        or request["constructions"] != CONSTRUCTIONS
        or request["alphabet_pairs"] != expected_pairs
        or not isinstance(request["ciphertext_rotations"], list)
        or any(type(rotation) is not int for rotation in request["ciphertext_rotations"])
        or request["ciphertext_rotations"] != list(range(26))
        or type(request["key_offset"]) is not int
        or request["key_offset"] != 0
    ):
        raise ValueError("request differs from the registered structured-alphabet domain")


def candidate_identity(primer, pair, rotation):
    """Build the canonical identity shared only as serialized data."""
    return {
        "id": f"{primer}:{pair['plaintext']}:{pair['ciphertext']}:{rotation:02}",
        "primer": primer,
        "plaintext_construction": pair["plaintext"],
        "ciphertext_construction": pair["ciphertext"],
        "ciphertext_rotation": rotation,
    }


def verify(report, request, evidence, primer_report):
    """Re-enumerate all models and validate decisions, traces and aggregates."""
    validate_request(request, primer_report)
    known = validate_evidence(evidence)
    if set(report) != {
        "schema_version", "evidence_id", "models_evaluated",
        "equation_evaluations", "match_histogram", "rejections", "survivors",
    }:
        raise ValueError("invalid report schema")
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or report["evidence_id"] != evidence["evidence_id"]
        or type(report["models_evaluated"]) is not int
        or report["models_evaluated"] != 16_224
        or type(report["equation_evaluations"]) is not int
        or report["equation_evaluations"] != 389_376
        or not isinstance(report["rejections"], list)
        or not isinstance(report["survivors"], list)
    ):
        raise ValueError("report metadata or evaluation coverage differs")
    if not isinstance(report["match_histogram"], dict):
        raise ValueError("match histogram must be an object")
    for score, count in report["match_histogram"].items():
        if not isinstance(score, str) or not score.isdigit() or str(int(score)) != score:
            raise ValueError("match histogram keys must be canonical integer strings")
        require_int(count, f"match histogram count {score}", 0)

    records = {}
    for decision, items in (("rejected", report["rejections"]), ("survived", report["survivors"])):
        for record in items:
            identifier = record.get("id") if isinstance(record, dict) else None
            if not isinstance(identifier, str) or identifier in records:
                raise ValueError("missing or duplicate canonical candidate identifier")
            validate_identity_fields(record)
            records[identifier] = (decision, record)
    if len(records) != 16_224:
        raise ValueError("candidate decisions do not cover the complete domain")

    orders = {entry["id"]: entry["order"] for entry in CONSTRUCTIONS}
    histogram = Counter()
    survivor_count = 0
    rejection_count = 0
    for primer in request["primers"]:
        key = expand(primer)[:97]
        expanded = "".join(map(str, key))
        for pair in request["alphabet_pairs"]:
            plain_order = orders[pair["plaintext"]]
            for rotation in request["ciphertext_rotations"]:
                identity = candidate_identity(primer, pair, rotation)
                try:
                    decision, record = records[identity["id"]]
                except KeyError as error:
                    raise ValueError(f"missing candidate {identity['id']}") from error
                cipher_order = rotate_left(orders[pair["ciphertext"]], rotation)
                equations = equation_trace(
                    plain_order, cipher_order, evidence["ciphertext"], known, key
                )
                mismatches = [
                    equation for equation in equations
                    if equation["observed_residue"] != equation["required_residue"]
                ]
                match_count = len(equations) - len(mismatches)
                histogram[match_count] += 1
                if any(record.get(field) != value for field, value in identity.items()):
                    raise ValueError("candidate identity fields disagree")
                if mismatches:
                    expected_keys = set(identity) | {"match_count", "first_mismatch"}
                    validate_equation(record.get("first_mismatch"), "first mismatch")
                    if (
                        decision != "rejected"
                        or set(record) != expected_keys
                        or type(record["match_count"]) is not int
                        or record["match_count"] != match_count
                        or record["first_mismatch"] != mismatches[0]
                    ):
                        raise ValueError(f"invalid rejection certificate: {identity['id']}")
                    rejection_count += 1
                else:
                    expected_keys = set(identity) | {
                        "expanded_key", "plaintext_alphabet", "ciphertext_alphabet", "equations"
                    }
                    if not isinstance(record.get("equations"), list):
                        raise ValueError("survivor equations must be an array")
                    for index, equation in enumerate(record["equations"]):
                        validate_equation(equation, f"survivor equation {index}")
                    if (
                        decision != "survived"
                        or set(record) != expected_keys
                        or record["expanded_key"] != expanded
                        or record["plaintext_alphabet"] != plain_order
                        or record["ciphertext_alphabet"] != cipher_order
                        or record["equations"] != equations
                    ):
                        raise ValueError(f"invalid survivor trace: {identity['id']}")
                    survivor_count += 1

    expected_histogram = {str(score): count for score, count in sorted(histogram.items())}
    if report["match_histogram"] != expected_histogram:
        raise ValueError("aggregate match histogram differs")
    if rejection_count + survivor_count != report["models_evaluated"]:
        raise ValueError("aggregate decision count differs")
    best_match = max(histogram)
    return {
        "status": "verified",
        "models_checked": len(records),
        "equations_checked": len(records) * len(known),
        "rejections": rejection_count,
        "survivors": survivor_count,
        "best_match_count": best_match,
        "best_model_count": histogram[best_match],
        "match_histogram": expected_histogram,
        "limitations": (
            "Exact exclusion only for four registered orders, all ordered pairs, and relative "
            "rotations; no plaintext recovery or historical attribution. Same coordinator, not "
            "fresh-context A7."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(
            read_json(args.report),
            read_json(args.request),
            read_json(ROOT / "evidence/k4.json"),
            read_json(ROOT / "results/PRIMERS-0001/run-002/primers.json"),
        )
        result["report_sha256"] = hashlib.sha256(args.report.read_bytes()).hexdigest()
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"structured-alphabet verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
