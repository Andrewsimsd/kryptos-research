#!/usr/bin/env python3
"""Independent full-domain and truth verifier for BLIND-0001 artifacts."""

import hashlib
import json
from pathlib import Path
import sys

LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ROOT = Path(__file__).resolve().parents[1]


class IndependentHashRng:
    def __init__(self, seed):
        self.seed = seed
        self.counter = 0
        self.buffer = b""

    def choice(self, count):
        if not self.buffer:
            self.buffer = hashlib.sha256(self.seed + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
        word = int.from_bytes(self.buffer[:4], "big")
        self.buffer = self.buffer[4:]
        return word % count


def independent_encrypt(message, route, equation, key):
    cipher = [None] * len(message)
    for i, letter in enumerate(message):
        p, k = LETTERS.index(letter), LETTERS.index(key[i % len(key)])
        value = (p + k if equation == "add" else p - k if equation == "variant" else k - p) % 26
        target = i if route == "identity" else len(message) - i - 1
        cipher[target] = LETTERS[value]
    return "".join(cipher)


def regenerate_v2(spec, seed):
    """Recreate public and private cases without importing controller logic."""
    rng = IndependentHashRng(seed)
    evidence = json.loads((ROOT / "evidence/k4.json").read_text(encoding="utf-8"))
    clues = [{"position": anchor["start"] + index, "letter": letter}
             for anchor in evidence["anchors"] for index, letter in enumerate(anchor["plaintext"])]
    corpus = "".join((ROOT / "fixtures/blind-heldout-prose.txt").read_text(encoding="ascii").splitlines())
    length = spec["message_length"]
    all_cases = []
    for kind, count in (("random", spec["positive_random"]), ("prose", spec["positive_prose"]),
                        ("period_three", spec["negative_period_three"]), ("tamper", spec["negative_tampered"])):
        for _ in range(count):
            if kind == "prose":
                start = rng.choice(len(corpus) - length + 1)
                message = list(corpus[start:start + length])
            else:
                message = [LETTERS[rng.choice(26)] for _ in range(length)]
            for clue in clues:
                message[clue["position"]] = clue["letter"]
            message = "".join(message)
            route = ("identity", "reverse")[rng.choice(2)]
            equation = ("add", "variant", "reflect")[rng.choice(3)]
            period = 3 if kind == "period_three" else 1 + rng.choice(2)
            key = "".join(LETTERS[rng.choice(26)] for _ in range(period))
            if period == 2 and key[0] == key[1]:
                key = key[0] + LETTERS[(ord(key[1]) - 64) % 26]
            if period == 3 and len(set(key)) < 3:
                key = "ABC"
            cipher = independent_encrypt(message, route, equation, key)
            if kind == "tamper":
                i = clues[rng.choice(len(clues))]["position"]
                j = i if route == "identity" else length - 1 - i
                cipher = cipher[:j] + LETTERS[(ord(cipher[j]) - 64) % 26] + cipher[j + 1:]
            true_id = None
            if kind in ("random", "prose"):
                if equation == "variant":
                    equation = "add"
                    key = "".join(LETTERS[-LETTERS.index(letter) % 26] for letter in key)
                if len(key) == 2 and key[0] == key[1]:
                    key = key[:1]
                true_id = f"{route}:{equation}:{len(key)}:{key}"
            all_cases.append((kind, message, cipher, true_id))
    for i in range(len(all_cases) - 1, 0, -1):
        j = rng.choice(i + 1)
        all_cases[i], all_cases[j] = all_cases[j], all_cases[i]
    public = []
    private = []
    for i, (kind, message, cipher, true_id) in enumerate(all_cases):
        identifier = f"B{i:04}"
        public.append({"id": identifier, "ciphertext": cipher, "clues": clues,
                       "budget": spec["model_checks_per_case"]})
        private.append({"id": identifier, "kind": kind, "plaintext": message,
                        "true_model_id": true_id})
    return public, private


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def expected_survivors(case):
    """Re-enumerate the eight registered models, independently of attacker code."""
    cipher = case["ciphertext"]
    clues = {entry["position"]: entry["letter"] for entry in case["clues"]}
    if len(clues) != 24 or len(cipher) != 97 or case["budget"] != 8:
        raise ValueError("production case violates frozen domain")
    output = []
    seen = set()
    for route in ("identity", "reverse"):
        for equation in ("add", "reflect"):
            for period in (1, 2):
                requirements = [[] for _ in range(period)]
                for i, letter in clues.items():
                    j = i if route == "identity" else len(cipher) - 1 - i
                    p = LETTERS.index(letter)
                    c = LETTERS.index(cipher[j])
                    requirements[i % period].append((c - p if equation == "add" else c + p) % 26)
                if any(not part or len(set(part)) != 1 for part in requirements):
                    continue
                key = "".join(LETTERS[part[0]] for part in requirements)
                if key == key[0] * len(key):
                    key = key[:1]
                identifier = f"{route}:{equation}:{len(key)}:{key}"
                if identifier in seen:
                    continue
                seen.add(identifier)
                plain = []
                for i in range(len(cipher)):
                    j = i if route == "identity" else len(cipher) - 1 - i
                    c = LETTERS.index(cipher[j])
                    k = LETTERS.index(key[i % len(key)])
                    plain.append(LETTERS[(c - k if equation == "add" else k - c) % 26])
                plaintext = "".join(plain)
                if any(plaintext[i] != letter for i, letter in clues.items()):
                    raise AssertionError("candidate violates clue")
                output.append({"model_id": identifier, "plaintext": plaintext})
    return output


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def verify_registration(manifest, directory=None):
    """Bind scientific fields and inputs to the frozen registration and code."""
    experiment_id = manifest.get("experiment_id")
    if experiment_id not in ("BLIND-0002", "BLIND-0003", "BLIND-0004"):
        return
    registered_path = ROOT / "experiments" / f"{experiment_id}.json"
    registered = json.loads(registered_path.read_text(encoding="utf-8"))
    for name, value in registered.items():
        if name == "status":
            continue
        if manifest.get(name) != value:
            raise ValueError(f"manifest differs from frozen registration: {name}")
    permitted_metadata = {"run_id", "started_at", "environment", "implementation_sha256"}
    if set(manifest) - set(registered) != permitted_metadata:
        raise ValueError("manifest has missing or extra run metadata")
    if manifest["status"] != "running":
        raise ValueError("manifest must retain its running snapshot")
    for relative, expected in registered["evidence_file_hashes"].items():
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file():
            raise ValueError(f"invalid frozen input path: {relative}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"frozen input hash differs: {relative}")
    code_hashes = manifest["implementation_sha256"]
    expected_paths = {f"experiments/{experiment_id}.json", "experiments/run_blind.py",
                      "experiments/run_blind_v2.py", "experiments/blind_attack.py",
                      "verification/verify_blind.py"}
    if experiment_id in ("BLIND-0003", "BLIND-0004"):
        expected_paths.add(f"experiments/run_blind_v{experiment_id[-1]}.py")
    if not isinstance(code_hashes, dict) or set(code_hashes) != expected_paths:
        raise ValueError("implementation path set differs from registered runner contract")
    historical_archives = {
        "BLIND-0003": {
            "experiments/run_blind_v2.py": "experiments/run_blind_v2_v3_snapshot.py",
            "verification/verify_blind.py": "verification/verify_blind_v3_snapshot.py",
        }
    }
    for relative, expected in code_hashes.items():
        if not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
            raise ValueError(f"invalid implementation digest: {relative}")
        if experiment_id == "BLIND-0002":
            # The old source was not archived. Its hash remains bound to the
            # immutable manifest; regenerated cases and independent equations
            # are still checked below.
            continue
        source = historical_archives.get(experiment_id, {}).get(relative, relative)
        path = (ROOT / source).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file():
            raise ValueError(f"invalid implementation path: {source}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"implementation changed: {source}")
    if directory is not None and (directory / "completion.json").is_file():
        completion_path = directory / "completion.json"
        completion = json.loads(completion_path.read_text(encoding="utf-8"))
        manifest_digest = hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest()
        if completion["artifact_sha256"].get("manifest.json") != manifest_digest:
            raise ValueError("manifest differs from immutable completion artifact")
        run_id = str(directory.resolve().relative_to(ROOT.resolve()))
        if completion["run_id"] != run_id or manifest["run_id"] != run_id:
            raise ValueError("run ID differs from completion directory")
        completion_digest = hashlib.sha256(completion_path.read_bytes()).hexdigest()
        events = [json.loads(line) for line in (ROOT / "experiments/registry.jsonl").read_text().splitlines()
                  if line.strip()]
        if not any(event.get("run_id") == run_id and event.get("completion_sha256") == completion_digest
                   for event in events):
            raise ValueError("completion differs from append-only registry event")


def verify(directory):
    spec = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    verify_registration(spec, directory)
    public = rows(directory / "public-cases.jsonl")
    private = rows(directory / "controller-private.jsonl")
    attacked = rows(directory / "attacker-output.jsonl")
    if spec["experiment_id"] in ("BLIND-0002", "BLIND-0003", "BLIND-0004"):
        reveal = json.loads((directory / "seed-reveal.json").read_text(encoding="utf-8"))
        seed = bytes.fromhex(reveal["seed_hex"])
        if len(seed) != 32 or hashlib.sha256(seed).hexdigest() != spec["seed_commitment_sha256"]:
            raise ValueError("revealed seed does not match frozen commitment")
        if reveal["commitment_sha256"] != spec["seed_commitment_sha256"] or not reveal["revealed_after_attacker_exit"]:
            raise ValueError("invalid seed reveal record")
        independent_public, independent_private = regenerate_v2(spec, seed)
        if public != independent_public or private != independent_private:
            raise ValueError("case content differs from independently regenerated frozen corpus")
    expected_count = sum(spec[name] for name in ("positive_random", "positive_prose",
                        "negative_period_three", "negative_tampered"))
    if len(public) != expected_count or len(private) != expected_count or len(attacked) != expected_count:
        raise ValueError("case count mismatch")
    counts = {name: {"cases": 0, "retained": 0, "top_one": 0, "top_five": 0,
                     "survivor_cases": 0, "ambiguity_sum": 0, "max_ambiguity": 0}
              for name in ("random", "prose", "period_three", "tamper")}
    total_checks = 0
    total_seconds = 0.0
    unknowns = 0
    for case, secret, answer in zip(public, private, attacked, strict=True):
        if case["id"] != secret["id"] or case["id"] != answer["id"]:
            raise ValueError("public, secret, and attacker IDs differ")
        kind = secret["kind"]
        if kind not in counts:
            raise ValueError("unexpected case kind")
        tally = counts[kind]
        tally["cases"] += 1
        expected = expected_survivors(case)
        if answer["survivors"] != expected:
            raise ValueError(f"{case['id']}: missing, extra, misordered, or incorrect survivor")
        if answer["checks"] != 8 or answer["status"] != "complete":
            unknowns += 1
        if not isinstance(answer["elapsed_seconds"], (int, float)) or answer["elapsed_seconds"] < 0:
            raise ValueError("invalid elapsed time")
        total_checks += answer["checks"]
        total_seconds += answer["elapsed_seconds"]
        size = len(expected)
        tally["ambiguity_sum"] += size
        tally["max_ambiguity"] = max(tally["max_ambiguity"], size)
        tally["survivor_cases"] += bool(size)
        if kind in ("random", "prose"):
            true_id = secret["true_model_id"]
            true_plain = secret["plaintext"]
            for rank, survivor in enumerate(expected):
                if survivor["model_id"] == true_id and survivor["plaintext"] == true_plain:
                    tally["retained"] += 1
                    tally["top_one"] += rank == 0
                    tally["top_five"] += rank < 5
                    break
        elif secret["true_model_id"] is not None:
            raise ValueError("negative has in-family truth ID")
    if total_checks > spec["operation_cap"]:
        raise ValueError("operation cap exceeded")
    positive = [counts["random"], counts["prose"]]
    negative = [counts["period_three"], counts["tamper"]]
    pos_n = sum(t["cases"] for t in positive)
    neg_n = sum(t["cases"] for t in negative)
    metrics = {"class_retention": ratio(sum(t["retained"] for t in positive), pos_n),
               "top_one": ratio(sum(t["top_one"] for t in positive), pos_n),
               "top_five": ratio(sum(t["top_five"] for t in positive), pos_n),
               "negative_survivor_rate": ratio(sum(t["survivor_cases"] for t in negative), neg_n),
               "unclassified_overrun": unknowns}
    targets = spec["targets"]
    passed = (metrics["class_retention"] >= targets["class_retention_minimum"]
              and metrics["top_one"] >= targets["top_one_minimum"]
              and metrics["top_five"] >= targets["top_five_minimum"]
              and metrics["negative_survivor_rate"] <= targets["negative_survivor_maximum"]
              and unknowns <= targets["unclassified_overrun_maximum"])
    return {"status": "verified", "experiment_id": spec["experiment_id"], "case_counts": counts,
            "metrics": metrics, "targets_pass": passed, "model_checks": total_checks,
            "attacker_reported_seconds_sum": total_seconds,
            "scope": "Synthetic exact family only; no K4 search or language-ranker calibration"}


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) != 1:
        print("usage: verify_blind.py RUN_DIRECTORY", file=sys.stderr)
        return 2
    try:
        print(json.dumps(verify(Path(argv[0])), indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as error:
        print(f"blind verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
