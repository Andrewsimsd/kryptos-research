#!/usr/bin/env python3
"""Reference equations, grid operations, and seeded differential cipher checks.

This implementation is separate from Rust but authored/integrated by the same
coordinator. It is not a fresh-context A7 review. It never imports Rust or uses
expected plaintext inside a cipher operation.
"""

import argparse
import hashlib
import json
from pathlib import Path
import string
import subprocess
import sys
import tempfile

from verify_baseline import VerificationError, read_json, require, source_references

AZ = string.ascii_uppercase
ROOT = Path(__file__).resolve().parents[1]
FAMILIES = ("vigenere", "beaufort", "variant_beaufort", "gromark", "columnar", "compound")


def keyed(keyword):
    require(keyword and all(c in AZ for c in keyword), "invalid keyword")
    return "".join(dict.fromkeys(keyword + AZ))


def route_sources(length, order, reverse_rows):
    """Read occupied grid cells directly, preserving original position labels."""
    require(order and sorted(order) == list(range(len(order))), "invalid column order")
    grid = [list(range(start, min(start + len(order), length))) for start in range(0, length, len(order))]
    if reverse_rows:
        grid.reverse()
    return [row[column] for column in order for row in grid if column < len(row)]


def invert_sources(sources):
    """Find each label's location independently of the Rust inversion loop."""
    return [sources.index(index) for index in range(len(sources))]


def gromark_parameters(keyword, primer, length):
    require(len(primer) == 5 and all(type(d) is int and 0 <= d <= 9 for d in primer), "invalid primer")
    alphabet = keyed(keyword)
    unique = "".join(dict.fromkeys(keyword))
    columns = sorted(range(len(unique)), key=lambda i: unique[i])
    mixed = "".join(alphabet[column::len(unique)] for column in columns)
    digits = list(primer)
    while len(digits) < length:
        position = len(digits) - 5
        digits.append((digits[position] + digits[position + 1]) % 10)
    return mixed, digits[:length]


def canonical_repeating(stage, shifts):
    period = next(p for p in range(1, len(shifts) + 1)
                  if len(shifts) % p == 0 and shifts == shifts[:p] * (len(shifts) // p))
    phase = stage["offset"] % period
    minimal = shifts[:period]
    minimal = minimal[phase:] + minimal[:phase]
    equation = {"vigenere": "Vigenere", "beaufort": "Beaufort", "variant_beaufort": "VariantBeaufort"}[stage["equation"]]
    return f"repeat-v1:{equation}:{stage['plaintext_alphabet']}:{stage['ciphertext_alphabet']}:{stage['key_alphabet']}:{minimal}"


def reference_stage(text, stage, direction):
    require(all(c in AZ for c in text), "text must already be uppercase ASCII")
    require(direction in ("encrypt", "decrypt"), "invalid direction")
    family = stage["family"]
    if family == "columnar":
        sources = route_sources(len(text), stage["column_order"], stage["reverse_rows"])
        if stage["inverse"]:
            sources = invert_sources(sources)
        canonical = f"pull-v1:{sources}"
        if direction == "decrypt":
            sources = invert_sources(sources)
        trace = [{"output_index": i, "input_index": source, "input": text[source], "output": text[source],
                  "input_value": None, "key_value": None, "output_value": None}
                 for i, source in enumerate(sources)]
        return canonical, {"text": "".join(text[s] for s in sources), "trace": trace}
    if family == "repeating":
        plain, cipher, key_alpha = (stage[name] for name in ("plaintext_alphabet", "ciphertext_alphabet", "key_alphabet"))
        require(all(sorted(a) == list(AZ) for a in (plain, cipher, key_alpha)), "invalid alphabet")
        require(stage["keyword"] and all(c in AZ for c in stage["keyword"]), "invalid keyword")
        require(type(stage["offset"]) is int and stage["offset"] >= 0, "invalid offset")
        shifts = [key_alpha.index(c) for c in stage["keyword"]]
        keys = [shifts[(i + stage["offset"]) % len(shifts)] for i in range(len(text))]
        canonical = canonical_repeating(stage, shifts)
        equation = stage["equation"]
    elif family == "gromark":
        plain = AZ
        cipher, keys = gromark_parameters(stage["keyword"], stage["primer"], len(text))
        canonical = f"aca-gromark-v1:{cipher}:{stage['primer']}"
        equation = "vigenere"
    else:
        raise VerificationError("unknown stage family")
    source_alpha, target_alpha = (plain, cipher) if direction == "encrypt" else (cipher, plain)
    trace = []
    for i, (letter, key) in enumerate(zip(text, keys)):
        value = source_alpha.index(letter)
        if equation == "beaufort":
            result = (key - value) % 26
        elif (equation, direction) in (("vigenere", "encrypt"), ("variant_beaufort", "decrypt")):
            result = (value + key) % 26
        elif (equation, direction) in (("vigenere", "decrypt"), ("variant_beaufort", "encrypt")):
            result = (value - key) % 26
        else:
            raise VerificationError("unknown equation")
        trace.append({"output_index": i, "input_index": i, "input": letter, "output": target_alpha[result],
                      "input_value": value, "key_value": key, "output_value": result})
    return canonical, {"text": "".join(p["output"] for p in trace), "trace": trace}


def reference_case(case):
    require(bool(case["stages"]), "empty pipeline")
    text = case["input"]
    canonical = [None] * len(case["stages"])
    traces = []
    indexes = list(range(len(case["stages"])))
    if case["direction"] == "decrypt":
        indexes.reverse()
    for index in indexes:
        canonical[index], stage = reference_stage(text, case["stages"][index], case["direction"])
        text = stage["text"]
        traces.append(stage)
    return {"id": case["id"], "direction": case["direction"], "output": text,
            "canonical_encryption_stages": canonical, "stages": traces}


def verify_batch(request, actual):
    """Compare every output, position, numeric value, and canonical identifier."""
    expected = {"schema_version": 1, "cases": [reference_case(case) for case in request["cases"]]}
    # JSON comparison also distinguishes false/0 and true/1 in trace fields.
    require(json.dumps(expected, sort_keys=True, allow_nan=False) == json.dumps(actual, sort_keys=True, allow_nan=False),
            "Rust outputs/traces/canonical identifiers differ from the Python reference")
    return expected


def fixture_requests(fixtures):
    cases = []
    for fixture in fixtures["cases"]:
        for direction, field in (("encrypt", "plaintext"), ("decrypt", "ciphertext")):
            cases.append({"id": fixture["id"] + "-" + direction, "input": fixture[field],
                          "direction": direction, "stages": fixture["stages"]})
    return {"schema_version": 1, "cases": cases}


def verify_known_answers(fixtures, actual):
    request = fixture_requests(fixtures)
    verify_batch(request, actual)
    by_id = {case["id"]: case for case in actual["cases"]}
    for fixture in fixtures["cases"]:
        require(len(fixture["plaintext"]) == len(fixture["ciphertext"]) == fixture["length"], "fixture length mismatch")
        require(by_id[fixture["id"] + "-encrypt"]["output"] == fixture["ciphertext"], "published encryption answer mismatch")
        require(by_id[fixture["id"] + "-decrypt"]["output"] == fixture["plaintext"], "published decryption answer mismatch")
    stages = by_id["K3-decrypt"]["stages"]
    composed = [stages[0]["trace"][row["input_index"]]["input_index"] for row in stages[1]["trace"]]
    require(composed == fixtures["k3_decryption_source_indices"], "K3 full permutation differs")
    alphabet, digits = gromark_parameters("ENIGMA", [2, 3, 4, 5, 2], 35)
    require(alphabet == fixtures["aca_gromark"]["ciphertext_alphabet"], "ACA alphabet differs")
    require("".join(map(str, digits)) == fixtures["aca_gromark"]["numeric_key"], "ACA numeric stream differs")
    require(digits[-1] == fixtures["aca_gromark"]["last_check_digit"], "ACA check digit differs")


class XorShift32:
    """Pinned Marsaglia xorshift32: shifts 13,17,5, masking to 32 bits."""
    def __init__(self, seed):
        require(type(seed) is int and 0 < seed < 2 ** 32, "seed must be a nonzero u32")
        self.state = seed

    def next(self):
        x = self.state
        x ^= (x << 13) & 0xffffffff
        x ^= x >> 17
        x ^= (x << 5) & 0xffffffff
        self.state = x
        return x

    def word(self, length):
        return "".join(AZ[self.next() % 26] for _ in range(length))

    def shuffle(self, values):
        result = list(values)
        for i in range(len(result) - 1, 0, -1):
            j = self.next() % (i + 1)
            result[i], result[j] = result[j], result[i]
        return result


def synthetic_requests(family, count, rng):
    """Generate fresh deterministic examples, including 97-letter/ragged cases."""
    lengths = [0, 1, 2, 7, 25, 26, 27, 96, 97, 98, 127]
    cases = []
    for number in range(count):
        text = rng.word(lengths[number % len(lengths)])
        width = 1 + rng.next() % 32
        route = {"family": "columnar", "column_order": rng.shuffle(range(width)),
                 "reverse_rows": bool(rng.next() % 2), "inverse": bool(rng.next() % 2)}
        repeating = {"family": "repeating", "plaintext_alphabet": "".join(rng.shuffle(AZ)),
                     "ciphertext_alphabet": "".join(rng.shuffle(AZ)), "key_alphabet": "".join(rng.shuffle(AZ)),
                     "keyword": rng.word(1 + rng.next() % 32), "equation": family if family in FAMILIES[:3] else "vigenere",
                     "offset": rng.next()}
        if family == "gromark":
            stages = [{"family": "gromark", "keyword": rng.word(1 + rng.next() % 32), "primer": [rng.next() % 10 for _ in range(5)]}]
        elif family == "columnar":
            stages = [route]
        elif family == "compound":
            stages = [route, repeating] if number % 2 else [repeating, route]
        else:
            stages = [repeating]
        encryption = {"id": f"{family}-{number}-encrypt", "input": text, "direction": "encrypt", "stages": stages}
        encrypted = reference_case(encryption)["output"]
        decryption = {"id": f"{family}-{number}-decrypt", "input": encrypted, "direction": "decrypt", "stages": stages}
        require(reference_case(decryption)["output"] == text, "reference round trip failed")
        cases.extend([encryption, decryption])
    return {"schema_version": 1, "cases": cases}


def invoke(binary, request):
    """Thin filesystem/process adapter; temporary request data is removed."""
    with tempfile.TemporaryDirectory(prefix="k4-ciphers-") as directory:
        path = Path(directory) / "requests.json"
        path.write_text(json.dumps(request), encoding="utf-8")
        process = subprocess.run([str(binary), "transform", str(path)], capture_output=True, timeout=60, check=False)
        require(process.returncode == 0, f"Rust transform failed: {process.stderr.decode(errors='replace')}")
        return json.loads(process.stdout)


def json_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def verify_sources(fixtures):
    sources = [json.loads(line) for name in ("evidence/sources.jsonl", "fixtures/sources.jsonl")
               for line in (ROOT / name).read_text().splitlines()]
    identifiers = [source["source_id"] for source in sources]
    require(len(set(identifiers)) == len(identifiers), "duplicate source ID")
    for ref in source_references(fixtures):
        require(ref in identifiers, f"unresolved fixture source {ref}")
    statements = [json.loads(line) for name in ("evidence/statements.jsonl", "fixtures/statements.jsonl")
                  for line in (ROOT / name).read_text().splitlines()]
    claims = [statement["claim_id"] for statement in statements]
    require(len(set(claims)) == len(claims), "duplicate claim ID")
    for source in sources:
        for claim in source["supports"] + source["contradicts"]:
            require(claim in claims, f"unresolved claim {claim}")
    for ref in source_references(statements):
        require(ref in identifiers, f"unresolved statement source {ref}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="execute Rust for fixtures and synthetic cases")
    parser.add_argument("--report", type=Path, help="verify an existing known-fixture transform report")
    parser.add_argument("--fixture-output", type=Path, help="new file to preserve full known-fixture traces")
    parser.add_argument("--seed", type=int, default=1261723442)
    parser.add_argument("--cases-per-family", type=int, default=100)
    args = parser.parse_args(argv)
    try:
        require(bool(args.binary) != bool(args.report), "choose exactly one of --binary or --report")
        require(1 <= args.cases_per_family <= 1000, "cases per family must be in 1..=1000")
        fixtures = read_json(ROOT / "fixtures/known-answers.json")
        verify_sources(fixtures)
        actual = read_json(args.report) if args.report else invoke(args.binary.resolve(), fixture_requests(fixtures))
        verify_known_answers(fixtures, actual)
        if args.fixture_output:
            with args.fixture_output.open("x", encoding="utf-8") as handle:
                json.dump(actual, handle, indent=2)
                handle.write("\n")
        summary = {"status": "verified", "fixture_pairs": len(fixtures["cases"]), "fixture_trace_digest": json_digest(actual),
                   "seed": args.seed if args.binary else None, "rng": "xorshift32(13,17,5); modulo selection; Fisher-Yates; implementation verification only",
                   "synthetic": [], "review_scope": "separate Python implementation by same coordinator; not fresh-context A7"}
        if args.binary:
            rng = XorShift32(args.seed)
            for family in FAMILIES:
                request = synthetic_requests(family, args.cases_per_family, rng)
                report = invoke(args.binary.resolve(), request)
                verify_batch(request, report)
                summary["synthetic"].append({"family": family, "message_pairs": args.cases_per_family,
                                             "requests_sha256": json_digest(request), "outputs_sha256": json_digest(report)})
        print(json.dumps(summary, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"cipher verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
