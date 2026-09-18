#!/usr/bin/env python3
"""Independently regenerate and verify the keyword calibration before K4 search."""

import argparse
import hashlib
import json
from pathlib import Path
import sys

from verify_baseline import read_json, validate_evidence
from verify_keyword_alphabets import (
    ROOT,
    calibration_reference,
    source_identifiers,
    strict_calibration_types,
    validate_request,
)


def verify_calibration(calibration, request, evidence, primer_report, reference, source_ids):
    """Return a compact summary after independently regenerating the full gate."""
    known = validate_evidence(evidence)
    orders = validate_request(request, primer_report, reference, source_ids)
    expected, _ = calibration_reference(request, evidence, known, orders)
    strict_calibration_types(calibration)
    if calibration != expected or not calibration["passed"]:
        raise ValueError("calibration differs from independent complete regeneration")
    return {
        "status": "verified",
        "candidate_count": expected["candidate_count"],
        "signature_census": expected["signature_census"],
        "calibration_cases": len(expected["cases"]),
        "true_model_retained_cases": expected["retained_cases"],
        "known_true_model_roundtrip_cases": expected["full_message_recovery_cases"],
        "singleton_recovery_sets": expected["unique_recovery_cases"],
        "operation_counts": expected["operation_counts"],
        "interpretation": (
            "The known planted candidate is retained and round-trips in every case; "
            "only singleton sets are blind model identifications."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_calibration(
            read_json(args.calibration),
            read_json(args.request),
            read_json(ROOT / "evidence/k4.json"),
            read_json(ROOT / "results/PRIMERS-0001/run-002/primers.json"),
            read_json(ROOT / "evidence/reference-material.json"),
            source_identifiers(ROOT / "evidence/sources.jsonl"),
        )
        result["calibration_sha256"] = hashlib.sha256(args.calibration.read_bytes()).hexdigest()
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"keyword-calibration verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
