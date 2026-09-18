#!/usr/bin/env python3
"""Independently verify keyword construction, calibration and complete K4 search."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys

from verify_baseline import read_json, validate_evidence
from verify_primers import expand

ROOT = Path(__file__).resolve().parents[1]
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
BASE_COUNT = 12
PRIMER_COUNT = 39
CANDIDATE_COUNT = 146_016
ENCODING = "((((primer_index*12)+plaintext_base_index)*12+ciphertext_base_index)*26)+ciphertext_rotation"


def integer(value, name, low=None, high=None):
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")
    if low is not None and value < low or high is not None and value > high:
        raise ValueError(f"{name} outside allowed range")
    return value


def deduplicate(keyword):
    if not isinstance(keyword, str) or not keyword or any(letter not in AZ for letter in keyword):
        raise ValueError("keyword must be nonempty uppercase A-Z")
    return "".join(dict.fromkeys(keyword))


def keyword_fill(keyword):
    unique = deduplicate(keyword)
    return unique + "".join(letter for letter in AZ if letter not in unique)


def aca_transposed(keyword):
    unique = deduplicate(keyword)
    keyed = keyword_fill(keyword)
    columns = sorted(range(len(unique)), key=lambda index: unique[index])
    return "".join(keyed[index] for column in columns for index in range(column, 26, len(unique)))


def base_orders(request):
    orders = []
    for entry in request["keywords"]:
        for constructor in request["constructors"]:
            forward = keyword_fill(entry["keyword"]) if constructor == "keyword_fill" else aca_transposed(entry["keyword"])
            for orientation in request["orientations"]:
                order = forward if orientation == "forward" else forward[::-1]
                orders.append((f"{entry['id']}:{constructor}:{orientation}", order))
    if len(orders) != 12 or len({order for _, order in orders}) != 12:
        raise ValueError("derived base orders are not unique")
    rotation_classes = {min(order[n:] + order[:n] for n in range(26)) for _, order in orders}
    if len(rotation_classes) != 12:
        raise ValueError("derived base orders collide under rotation")
    return orders


def validate_request(request, primer_report, reference, source_ids):
    expected_primers = [entry["primer"] for entry in primer_report["survivors"]]
    expected_keywords = [
        {"id": "kryptos", "keyword": "KRYPTOS", "source_id": "S210", "role": "tableau_keyword"},
        {"id": "palimpsest", "keyword": "PALIMPSEST", "source_id": "S203", "role": "k1_indicator_repurposed"},
        {"id": "abscissa", "keyword": "ABSCISSA", "source_id": "S203", "role": "k2_indicator_repurposed"},
    ]
    if set(request) != {"schema_version", "primers", "keywords", "constructors", "orientations", "ciphertext_rotations", "key_offset", "calibration"}:
        raise ValueError("invalid keyword request schema")
    calibration = request["calibration"]
    if not isinstance(calibration, dict) or set(calibration) != {"seed", "case_count", "message_length", "rng", "assignment"}:
        raise ValueError("invalid calibration request schema")
    if (
        type(request["schema_version"]) is not int or request["schema_version"] != 1
        or request["primers"] != expected_primers
        or request["keywords"] != expected_keywords
        or request["constructors"] != ["keyword_fill", "aca_gromark_transposed"]
        or request["orientations"] != ["forward", "reversed"]
        or any(type(rotation) is not int for rotation in request["ciphertext_rotations"])
        or request["ciphertext_rotations"] != list(range(26))
        or type(request["key_offset"]) is not int or request["key_offset"] != 0
        or type(calibration["seed"]) is not int or not 0 < calibration["seed"] < 2**32
        or type(calibration["case_count"]) is not int or calibration["case_count"] != 144
        or type(calibration["message_length"]) is not int or calibration["message_length"] != 97
        or calibration["rng"] != "xorshift32(13,17,5); modulo-26 letter selection"
        or calibration["assignment"] != "case=ordered_pair_index; primer=case%39; rotation=case%26"
    ):
        raise ValueError("request differs from registered keyword domain")
    if not {"S203", "S210"} <= source_ids:
        raise ValueError("keyword provenance sources are missing")
    sections = {section["id"]: section for section in reference["sections"]}
    if (
        reference["tableau"]["keyword_alphabet"] != "KRYPTOSABCDEFGHIJLMNQUVWXZ"
        or "S210" not in reference["tableau"]["source_ids"]
        or sections["K1"]["indicator_key"] != "PALIMPSEST"
        or sections["K1"]["key_source_id"] != "S203"
        or sections["K2"]["indicator_key"] != "ABSCISSA"
        or sections["K2"]["key_source_id"] != "S203"
    ):
        raise ValueError("keyword provenance differs from frozen reference material")
    return base_orders(request)


def encode(primer, plain, cipher, rotation):
    return (((primer * 12 + plain) * 12 + cipher) * 26) + rotation


def decode(index):
    integer(index, "candidate index", 0, CANDIDATE_COUNT - 1)
    rotation = index % 26
    index //= 26
    cipher = index % 12
    index //= 12
    plain = index % 12
    primer = index // 12
    return primer, plain, cipher, rotation


def rotate(order, amount):
    return order[amount:] + order[:amount]


def signature(known, key, plain_order, cipher_order):
    plain = {letter: index for index, letter in enumerate(plain_order)}
    return "".join(cipher_order[(plain[letter] + key[position]) % 26] for position, letter in sorted(known.items()))


def signatures(request, known, orders):
    keys = [expand(primer)[:97] for primer in request["primers"]]
    buckets = defaultdict(list)
    for candidate in range(CANDIDATE_COUNT):
        primer, plain, cipher, rotation = decode(candidate)
        value = signature(known, keys[primer], orders[plain][1], rotate(orders[cipher][1], rotation))
        buckets[value].append(candidate)
    return buckets, keys


class XorShift32:
    def __init__(self, seed): self.state = seed
    def next(self):
        value = self.state
        value ^= (value << 13) & 0xffffffff
        value ^= value >> 17
        value ^= (value << 5) & 0xffffffff
        self.state = value
        return value
    def text(self, length): return "".join(AZ[self.next() % 26] for _ in range(length))


def encrypt(plaintext, key, plain_order, cipher_order):
    if len(plaintext) != len(key):
        raise ValueError("plaintext and key lengths differ")
    plain = {letter: index for index, letter in enumerate(plain_order)}
    return "".join(cipher_order[(plain[letter] + key[position]) % 26] for position, letter in enumerate(plaintext))


def decrypt(ciphertext, key, plain_order, cipher_order):
    if len(ciphertext) != len(key):
        raise ValueError("ciphertext and key lengths differ")
    cipher = {letter: index for index, letter in enumerate(cipher_order)}
    return "".join(plain_order[(cipher[letter] - key[position]) % 26]
                   for position, letter in enumerate(ciphertext))


def calibration_reference(request, evidence, known, orders):
    buckets, keys = signatures(request, known, orders)
    sizes = Counter(map(len, buckets.values()))
    census = {
        "physical_candidates": sum(len(bucket) for bucket in buckets.values()),
        "distinct_signatures": len(buckets),
        "singleton_buckets": sizes[1],
        "doubleton_buckets": sizes[2],
        "unique_physical_candidates": sizes[1],
        "maximum_bucket_size": max(sizes),
    }
    rng = XorShift32(request["calibration"]["seed"])
    cases = []
    for case_index in range(144):
        primer, plain, cipher, rotation = case_index % 39, case_index // 12, case_index % 12, case_index % 26
        candidate = encode(primer, plain, cipher, rotation)
        plaintext = list(rng.text(97))
        for position, letter in known.items(): plaintext[position] = letter
        plaintext = "".join(plaintext)
        cipher_order = rotate(orders[cipher][1], rotation)
        ciphertext = encrypt(plaintext, keys[primer], orders[plain][1], cipher_order)
        crib = "".join(ciphertext[position] for position in sorted(known))
        recovered = buckets.get(crib, [])
        plaintext_matches = reencrypts = False
        if candidate in recovered:
            recovered_primer, recovered_plain, recovered_cipher, recovered_rotation = decode(candidate)
            recovered_cipher_order = rotate(orders[recovered_cipher][1], recovered_rotation)
            recovered_plaintext = decrypt(ciphertext, keys[recovered_primer],
                                          orders[recovered_plain][1], recovered_cipher_order)
            plaintext_matches = recovered_plaintext == plaintext
            reencrypts = encrypt(recovered_plaintext, keys[recovered_primer],
                                 orders[recovered_plain][1], recovered_cipher_order) == ciphertext
        cases.append({
            "case_index": case_index,
            "true_candidate_index": candidate,
            "recovered_candidate_indices": recovered,
            "true_candidate_retained": candidate in recovered,
            "full_message": {
                "plaintext_recovery_matches": plaintext_matches,
                "recovered_plaintext_reencrypts": reencrypts,
                "passed": plaintext_matches and reencrypts,
            },
            "unique_recovery": len(recovered) == 1,
            "ciphertext": ciphertext,
        })
    retained = sum(case["true_candidate_retained"] for case in cases)
    plaintext_recovery = sum(case["full_message"]["plaintext_recovery_matches"] for case in cases)
    reencryption = sum(case["full_message"]["recovered_plaintext_reencrypts"] for case in cases)
    full_message_recovery = sum(case["full_message"]["passed"] for case in cases)
    return {
        "schema_version": 2,
        "evidence_id": evidence["evidence_id"],
        "candidate_count": CANDIDATE_COUNT,
        "signature_census": census,
        "operation_counts": {
            "signature_equation_evaluations": CANDIDATE_COUNT * 24,
            "planted_encryption_positions": 144 * 97,
            "planted_decryption_positions": 144 * 97,
            "planted_reencryption_positions": 144 * 97,
        },
        "cases": cases,
        "retained_cases": retained,
        "plaintext_recovery_cases": plaintext_recovery,
        "reencryption_cases": reencryption,
        "full_message_recovery_cases": full_message_recovery,
        "unique_recovery_cases": sum(case["unique_recovery"] for case in cases),
        "passed": retained == 144 and plaintext_recovery == 144
                  and reencryption == 144 and full_message_recovery == 144,
    }, keys


def strict_calibration_types(report):
    for field in ("schema_version", "candidate_count", "retained_cases", "plaintext_recovery_cases",
                  "reencryption_cases", "full_message_recovery_cases", "unique_recovery_cases"):
        integer(report.get(field), f"calibration {field}", 0)
    if type(report.get("passed")) is not bool or not isinstance(report.get("cases"), list):
        raise ValueError("invalid calibration boolean or cases")
    operations = report.get("operation_counts")
    expected_operation_keys = {
        "signature_equation_evaluations",
        "planted_encryption_positions",
        "planted_decryption_positions",
        "planted_reencryption_positions",
    }
    if not isinstance(operations, dict) or set(operations) != expected_operation_keys:
        raise ValueError("invalid calibration operation-count schema")
    for field, value in operations.items():
        integer(value, f"calibration operation {field}", 0)
    for field, value in report.get("signature_census", {}).items(): integer(value, f"census {field}", 0)
    for case in report["cases"]:
        for field in ("case_index", "true_candidate_index"):
            integer(case.get(field), f"case {field}", 0)
        if not isinstance(case.get("recovered_candidate_indices"), list): raise ValueError("invalid recovery set")
        for candidate in case["recovered_candidate_indices"]: integer(candidate, "recovered candidate", 0, CANDIDATE_COUNT - 1)
        for field in ("true_candidate_retained", "unique_recovery"):
            if type(case.get(field)) is not bool: raise ValueError(f"case {field} must be boolean")
        if not isinstance(case.get("full_message"), dict): raise ValueError("invalid full-message checks")
        for field in ("plaintext_recovery_matches", "recovered_plaintext_reencrypts", "passed"):
            if type(case["full_message"].get(field)) is not bool:
                raise ValueError(f"case full_message.{field} must be boolean")


def equation(position, plain_letter, cipher_letter, key, plain_order, cipher_order):
    pi, ci = plain_order.index(plain_letter), cipher_order.index(cipher_letter)
    return {"position": position, "plaintext": plain_letter, "ciphertext": cipher_letter,
            "plaintext_index": pi, "ciphertext_index": ci, "key": key,
            "observed_residue": (ci - pi) % 26, "required_residue": key % 26}


def k4_reference(request, evidence, known, orders, keys):
    """Construct the complete compact report, including any survivor traces."""
    counts, mismatches_by_candidate, histogram, survivors = [], [], Counter(), []
    crib_items = sorted(known.items())
    for candidate in range(CANDIDATE_COUNT):
        primer, plain, cipher, rotation = decode(candidate)
        plain_order, cipher_order = orders[plain][1], rotate(orders[cipher][1], rotation)
        equations = [
            equation(position, letter, evidence["ciphertext"][position], keys[primer][position], plain_order, cipher_order)
            for position, letter in crib_items
        ]
        mismatches = [index for index, row in enumerate(equations) if row["observed_residue"] != row["required_residue"]]
        matches = 24 - len(mismatches)
        counts.append(matches)
        mismatches_by_candidate.append(mismatches[0] if mismatches else None)
        histogram[matches] += 1
        if not mismatches:
            survivors.append({
                "candidate_index": candidate,
                "coordinates": {"primer_index": primer, "plaintext_base_index": plain, "ciphertext_base_index": cipher, "ciphertext_rotation": rotation},
                "primer": request["primers"][primer], "plaintext_base": orders[plain][0], "ciphertext_base": orders[cipher][0],
                "expanded_key": "".join(map(str, keys[primer])), "plaintext_alphabet": plain_order,
                "ciphertext_alphabet": cipher_order, "equations": equations,
            })
    return {
        "schema_version": 2, "evidence_id": evidence["evidence_id"],
        "candidate_count": CANDIDATE_COUNT, "equation_evaluations": CANDIDATE_COUNT * 24,
        "candidate_index_encoding": ENCODING, "match_counts": counts,
        "first_mismatch_crib_indices": mismatches_by_candidate,
        "match_histogram": {str(score): count for score, count in sorted(histogram.items())},
        "survivors": survivors,
    }, histogram


def verify(calibration, report, request, evidence, primer_report, reference, source_ids):
    known = validate_evidence(evidence)
    orders = validate_request(request, primer_report, reference, source_ids)
    expected_calibration, keys = calibration_reference(request, evidence, known, orders)
    strict_calibration_types(calibration)
    if calibration != expected_calibration or not calibration["passed"]:
        raise ValueError("calibration differs from independent complete regeneration")
    if set(report) != {"schema_version", "evidence_id", "candidate_count", "equation_evaluations", "candidate_index_encoding", "match_counts", "first_mismatch_crib_indices", "match_histogram", "survivors"}:
        raise ValueError("invalid K4 report schema")
    integer(report["schema_version"], "schema", 2, 2)
    integer(report["candidate_count"], "candidate count", CANDIDATE_COUNT, CANDIDATE_COUNT)
    integer(report["equation_evaluations"], "equation evaluations", 3_504_384, 3_504_384)
    if report["evidence_id"] != evidence["evidence_id"] or report["candidate_index_encoding"] != ENCODING:
        raise ValueError("K4 report metadata differs")
    if len(report["match_counts"]) != CANDIDATE_COUNT or len(report["first_mismatch_crib_indices"]) != CANDIDATE_COUNT:
        raise ValueError("compact arrays do not cover complete domain")
    for value in report["match_counts"]: integer(value, "match count", 0, 24)
    for value in report["first_mismatch_crib_indices"]:
        if value is not None: integer(value, "mismatch crib index", 0, 23)
    expected_report, histogram = k4_reference(request, evidence, known, orders, keys)
    if report["match_counts"] != expected_report["match_counts"] or report["first_mismatch_crib_indices"] != expected_report["first_mismatch_crib_indices"]:
        raise ValueError("compact K4 certificate arrays differ")
    if not isinstance(report["match_histogram"], dict) or any(type(v) is not int for v in report["match_histogram"].values()) or report["match_histogram"] != expected_report["match_histogram"]:
        raise ValueError("K4 histogram differs")
    if report["survivors"] != expected_report["survivors"]:
        raise ValueError("K4 survivor traces differ")
    return {
        "status": "verified", "candidate_count": CANDIDATE_COUNT,
        "equations_checked": CANDIDATE_COUNT * 24, "survivors": len(expected_report["survivors"]),
        "best_match_count": max(histogram), "best_model_count": histogram[max(histogram)],
        "signature_census": expected_calibration["signature_census"],
        "calibration_cases": 144, "retained_cases": expected_calibration["retained_cases"],
        "plaintext_recovery_cases": expected_calibration["plaintext_recovery_cases"],
        "reencryption_cases": expected_calibration["reencryption_cases"],
        "full_message_recovery_cases": expected_calibration["full_message_recovery_cases"],
        "unique_recovery_cases": expected_calibration["unique_recovery_cases"],
        "operation_counts": {
            **expected_calibration["operation_counts"],
            "k4_equation_evaluations": CANDIDATE_COUNT * 24,
            "total": sum(expected_calibration["operation_counts"].values()) + CANDIDATE_COUNT * 24,
        },
        "limitations": "Exact registered keyword family only; indicators are repurposed hypotheses; same-coordinator independent implementation, not external A7.",
    }


def source_identifiers(path):
    return {json.loads(line)["source_id"] for line in path.read_text().splitlines() if line.strip()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(
            read_json(args.calibration), read_json(args.report), read_json(args.request),
            read_json(ROOT / "evidence/k4.json"), read_json(ROOT / "results/PRIMERS-0001/run-002/primers.json"),
            read_json(ROOT / "evidence/reference-material.json"), source_identifiers(ROOT / "evidence/sources.jsonl"),
        )
        result["calibration_sha256"] = hashlib.sha256(args.calibration.read_bytes()).hexdigest()
        result["report_sha256"] = hashlib.sha256(args.report.read_bytes()).hexdigest()
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"keyword-alphabet verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__": sys.exit(main())
