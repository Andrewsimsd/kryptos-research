#!/usr/bin/env python3
"""Regenerate every permutation, cross-check C statistics, and report uncertainty."""

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys

from verify_baseline import read_json, validate_evidence

ROOT = Path(__file__).resolve().parents[1]
NAMES = ["width21_repeated_types", "kryptos_minor_sum", "repeated_plain_minor_sum",
         "repeated_plain_below_five", "adjacent_equal_pairs"]
UPPER = [True, False, False, True, True]
MASK = (1 << 64) - 1


class SplitMix64:
    def __init__(self, seed):
        self.state, self.draws = seed, 0

    def next(self):
        self.state = (self.state + 0x9e3779b97f4a7c15) & MASK
        self.draws += 1
        value = self.state
        value = ((value ^ (value >> 30)) * 0xbf58476d1ce4e5b9) & MASK
        value = ((value ^ (value >> 27)) * 0x94d049bb133111eb) & MASK
        return value ^ (value >> 31)

    def shuffle(self, original):
        text = list(original)
        for bound in range(len(text), 1, -1):
            threshold = (1 << 64) % bound
            value = self.next()
            while value < threshold:
                value = self.next()
            index = value % bound
            text[bound - 1], text[index] = text[index], text[bound - 1]
        return text


class Model:
    def __init__(self, evidence):
        known = validate_evidence(evidence)
        self.original = [ord(c) - 65 for c in evidence["ciphertext"]]
        self.selected = [(i, ord(p) - 65) for i, p in sorted(known.items()) if p in "KRYPTOS"]
        groups = {}
        for i, p in known.items():
            groups.setdefault(p, []).append(i)
        self.pairs = [(a, b) for positions in groups.values() for n, a in enumerate(positions) for b in positions[n + 1:]]
        self.sizes = [39, 13 * len(self.selected) + 1, 13 * len(self.pairs) + 1, len(self.pairs) + 1, 97]

    def measure(self, text):
        distances = [minor(text[a], text[b]) for a, b in self.pairs]
        return [sum(n >= 2 for n in Counter(zip(text, text[21:])).values()),
                sum(minor(p, text[i]) for i, p in self.selected), sum(distances),
                sum(d < 5 for d in distances), sum(a == b for a, b in zip(text, text[1:]))]


def minor(a, b):
    return min((a - b) % 26, (b - a) % 26)


def validate_request(request):
    if set(request) != {"schema_version", "samples", "seed"} or any(type(value) is not int for value in request.values()):
        raise ValueError("invalid request schema or integer types")
    if request["schema_version"] != 1 or not 1 <= request["samples"] <= 10_000_000 or not 0 <= request["seed"] <= MASK:
        raise ValueError("invalid request bounds")


def reference(request, model):
    validate_request(request)
    rng = SplitMix64(request["seed"])
    histograms = [[0] * size for size in model.sizes]
    first, c_texts, c_values = [], [], []
    c_texts.append("".join(chr(c + 65) for c in model.original))
    c_values.append(model.measure(model.original))
    for trial in range(request["samples"]):
        text = rng.shuffle(model.original)
        values = model.measure(text)
        for histogram, value in zip(histograms, values):
            histogram[value] += 1
        if trial < 10000:
            c_texts.append("".join(chr(c + 65) for c in text))
            c_values.append(values)
            if trial < 16:
                first.append(c_texts[-1])
    report = {"request": request, "observed": model.measure(model.original), "histograms": histograms,
              "first_permutations": first, "rng_final_state": rng.state, "rng_draws": rng.draws}
    return report, c_texts, c_values


def wilson(successes, samples):
    if type(successes) is not int or type(samples) is not int or not 0 <= successes <= samples or samples < 1:
        raise ValueError("invalid binomial counts")
    z = 1.959963984540054
    p = successes / samples
    denominator = 1 + z * z / samples
    center = (p + z * z / (2 * samples)) / denominator
    half = z * math.sqrt(p * (1 - p) / samples + z * z / (4 * samples * samples)) / denominator
    return [0.0 if successes == 0 else max(0.0, center - half),
            1.0 if successes == samples else min(1.0, center + half)]


def summarize(report):
    n = report["request"]["samples"]
    rows = []
    for name, upper, observed, histogram in zip(NAMES, UPPER, report["observed"], report["histograms"], strict=True):
        if any(type(c) is not int or c < 0 for c in histogram) or sum(histogram) != n:
            raise ValueError("histogram does not cover the sample count")
        r = sum(count for value, count in enumerate(histogram) if (value >= observed if upper else value <= observed))
        mean = sum(value * count for value, count in enumerate(histogram)) / n
        variance = sum(count * (value - mean) ** 2 for value, count in enumerate(histogram)) / n
        estimate = (r + 1) / (n + 1)
        rows.append({"statistic": name, "tail": ">=" if upper else "<=", "observed": observed,
                     "samples": n, "exceedances": r, "estimate_plus_one": estimate,
                     "wilson_95": wilson(r, n), "bonferroni_five": min(1.0, 5 * estimate),
                     "null_mean": mean, "null_sd": math.sqrt(variance), "observed_minus_null_mean": observed - mean})
    return rows


def compare(actual, expected):
    # Canonical JSON deliberately distinguishes booleans/floats from integer counts.
    if json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError("Rust/Python report disagreement (including every histogram bin and generator state)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--upstream-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="existing run directory; files must be new")
    args = parser.parse_args()
    try:
        expected, texts, values = reference(read_json(args.request), Model(read_json(ROOT / "evidence/k4.json")))
        compare(read_json(args.report), expected)
        input_path, output_path = args.output / "upstream-input.txt", args.output / "upstream-output.txt"
        with input_path.open("x") as handle:
            handle.write("\n".join(texts) + "\n")
        with input_path.open("rb") as stdin, output_path.open("xb") as stdout:
            subprocess.run([str(args.upstream_binary)], stdin=stdin, stdout=stdout, check=True, timeout=30)
        actual = [list(map(int, line.split())) for line in output_path.read_text().splitlines()]
        if actual != values:
            raise ValueError("pinned C statistic functions disagree")
        result = {"status": "verified", "samples_regenerated": expected["request"]["samples"],
                  "upstream_texts_checked": len(texts), "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
                  "statistics": summarize(expected), "interpretation": "Fixed historical five-test reproduction; no global selection correction or cipher identification.",
                  "implementation_review": "separate implementations by same coordinator; not fresh-context A7"}
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print(f"statistical verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
