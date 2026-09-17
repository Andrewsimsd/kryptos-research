#!/usr/bin/env python3
"""Regenerate a separately calibrated maximum-statistic width scan in Python."""

import argparse
from collections import Counter
from functools import cmp_to_key
import hashlib
import json
import math
from pathlib import Path
import sys

from verify_baseline import read_json, validate_evidence
from verify_statistics import ROOT, SplitMix64, compare, wilson


def counts(text):
    return [sum(n >= 2 for n in Counter(zip(text, text[width:])).values()) for width in range(1, 49)]


def empty_histograms():
    return [[0] * ((97 - width) // 2 + 1) for width in range(1, 49)]


def validate_request(request):
    names = {"schema_version", "samples", "calibration_samples", "seed", "calibration_seed"}
    if set(request) != names or any(type(v) is not int for v in request.values()):
        raise ValueError("invalid width-scan request schema")
    if (request["schema_version"] != 1 or not 2 <= request["calibration_samples"] <= 1_000_000
            or not 1 <= request["samples"] <= 1_000_000 or request["seed"] == request["calibration_seed"]
            or not all(0 <= request[key] < 2**64 for key in ("seed", "calibration_seed"))):
        raise ValueError("invalid width-scan request bounds or seeds")


def score_compare(a, b):
    # Scores are (signed numerator, positive variance numerator).
    sign_a, sign_b = (a[0] > 0) - (a[0] < 0), (b[0] > 0) - (b[0] < 0)
    if sign_a != sign_b:
        return (sign_a > sign_b) - (sign_a < sign_b)
    left, right = a[0] ** 2 * b[1], b[0] ** 2 * a[1]
    return ((left > right) - (left < right)) * (-1 if sign_a < 0 else 1)


def calibration_tables(histograms, n):
    sums = [sum(v * c for v, c in enumerate(h)) for h in histograms]
    squares = [sum(v * v * c for v, c in enumerate(h)) for h in histograms]
    variances = [n * sq - total * total for total, sq in zip(sums, squares)]
    if any(v <= 0 for v in variances):
        raise ValueError("zero calibration variance")
    scores = [[(n * x - total, variance) for x in range(len(h))]
              for total, variance, h in zip(sums, variances, histograms)]
    # A rank table avoids repeated square roots or cross-products in selection.
    # Mathematically equal scores share ranks, preserving the smallest-width tie rule.
    ordered = sorted({score for row in scores for score in row}, key=cmp_to_key(score_compare))
    ranks = {}
    rank, previous = 0, None
    for score in ordered:
        if previous is not None and score_compare(previous, score) != 0:
            rank += 1
        ranks[score] = rank
        previous = score
    return sums, squares, variances, scores, [[ranks[s] for s in row] for row in scores]


def winner(values, ranks):
    return max(range(48), key=lambda width: ranks[width][values[width]])


def stage(original, n, seed, visit):
    rng = SplitMix64(seed)
    histograms, first = empty_histograms(), []
    for trial in range(n):
        text = rng.shuffle(original)
        values = counts(text)
        for h, value in zip(histograms, values):
            h[value] += 1
        visit(values)
        if trial < 16:
            first.append("".join(text))
    return {"histograms": histograms, "first_permutations": first,
            "rng_final_state": rng.state, "rng_draws": rng.draws}


def reference(evidence, request):
    validate_evidence(evidence)
    validate_request(request)
    original = evidence["ciphertext"]
    calibration = stage(original, request["calibration_samples"], request["calibration_seed"], lambda _: None)
    sums, squares, variances, scores, ranks = calibration_tables(calibration["histograms"], request["calibration_samples"])
    observed = counts(original)
    selected = winner(observed, ranks)
    threshold = ranks[selected][observed[selected]]
    maxima = empty_histograms()
    exceedances = 0

    def visit(values):
        nonlocal exceedances
        width = winner(values, ranks)
        value = values[width]
        maxima[width][value] += 1
        exceedances += ranks[width][value] >= threshold

    evaluation = stage(original, request["samples"], request["seed"], visit)
    return {"request": request, "observed": observed, "selected_width": selected + 1,
            "calibration_sums": sums, "calibration_sum_squares": squares, "variance_numerators": variances,
            "calibration": calibration, "evaluation": evaluation, "maxima_histograms": maxima,
            "global_exceedances": exceedances}


def estimate(r, n):
    return {"exceedances": r, "samples": n, "estimate_plus_one": (r + 1) / (n + 1), "wilson_95": wilson(r, n)}


def summarize(report):
    n, calibration_n = report["request"]["samples"], report["request"]["calibration_samples"]
    sums, squares, variances, scores, ranks = calibration_tables(report["calibration"]["histograms"], calibration_n)
    rows = []
    for width, observed in enumerate(report["observed"]):
        local = sum(report["evaluation"]["histograms"][width][observed:])
        adjusted = sum(count for w, h in enumerate(report["maxima_histograms"]) for value, count in enumerate(h)
                       if ranks[w][value] >= ranks[width][observed])
        if adjusted < local:
            raise ValueError("maximum tail cannot be smaller than its local tail")
        rows.append({"width": width + 1, "available_pairs": 96 - width, "observed": observed,
                     "calibration_mean": sums[width] / calibration_n,
                     "calibration_sd": math.sqrt(variances[width]) / calibration_n,
                     "standardized_score": scores[width][observed][0] / math.sqrt(variances[width]),
                     "local_tail": estimate(local, n), "maximum_adjusted_tail": estimate(adjusted, n),
                     "null_selected_count": sum(report["maxima_histograms"][width])})
    return {"selected_width": report["selected_width"], "global_tail": estimate(report["global_exceedances"], n),
            "widths": rows, "scope": "Upper maximum of separately calibrated repeated-type counts over widths 1-48 only; no historical alphabet/statistic selection correction.",
            "calibration_uncertainty": "Inference conditional on the fixed independent calibration; Wilson intervals cover evaluation Monte Carlo uncertainty only."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        expected = reference(read_json(ROOT / "evidence/k4.json"), read_json(args.request))
        compare(read_json(args.report), expected)
        result = {"status": "verified", "calibration_samples_regenerated": expected["request"]["calibration_samples"],
                  "evaluation_samples_regenerated": expected["request"]["samples"], "widths_per_sample": 48,
                  "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(), **summarize(expected),
                  "implementation_review": "Python counts/rank selection separate from Rust; shared previously tested Python RNG; same coordinator, not fresh-context A7."}
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"width-scan verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
