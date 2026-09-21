#!/usr/bin/env python3
"""Generate and execute frozen BLIND-0001 without passing truth to attacker."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "experiments/BLIND-0001.json"
LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8") as target:
        json.dump(value, target, indent=2, allow_nan=False)
        target.write("\n")


def write_jsonl(path, values):
    with path.open("x", encoding="utf-8") as target:
        for value in values:
            target.write(json.dumps(value, allow_nan=False) + "\n")


class XorShift32:
    def __init__(self, seed):
        self.state = seed

    def next(self):
        x = self.state
        x ^= (x << 13) & 0xffffffff
        x ^= x >> 17
        x ^= (x << 5) & 0xffffffff
        self.state = x & 0xffffffff
        return self.state

    def choice(self, count):
        return self.next() % count


def public_clues():
    evidence = json.loads((ROOT / "evidence/k4.json").read_text(encoding="utf-8"))
    clues = []
    for anchor in evidence["anchors"]:
        clues.extend({"position": anchor["start"] + offset, "letter": letter}
                     for offset, letter in enumerate(anchor["plaintext"]))
    assert len(clues) == 24 and len({clue["position"] for clue in clues}) == 24
    return clues


def plant_message(rng, kind, corpus, clues, length):
    if kind == "prose":
        start = rng.choice(len(corpus) - length + 1)
        message = list(corpus[start:start + length])
    else:
        message = [LETTERS[rng.choice(26)] for _ in range(length)]
    for clue in clues:
        message[clue["position"]] = clue["letter"]
    return "".join(message)


def encrypt(plaintext, route, equation, key):
    """Controller encryption; independent from the attack's inference code."""
    output = [None] * len(plaintext)
    for i, letter in enumerate(plaintext):
        p, k = ord(letter) - 65, ord(key[i % len(key)]) - 65
        if equation == "add":
            c = p + k
        elif equation == "variant":
            c = p - k
        else:
            c = k - p
        j = i if route == "identity" else len(plaintext) - 1 - i
        output[j] = LETTERS[c % 26]
    return "".join(output)


def canonical_truth(route, equation, key):
    if equation == "variant":
        equation = "add"
        key = "".join(LETTERS[(- (ord(letter) - 65)) % 26] for letter in key)
    if len(key) == 2 and key[0] == key[1]:
        key = key[:1]
    return f"{route}:{equation}:{len(key)}:{key}"


def make_cases(spec, rng=None):
    if rng is None:
        rng = XorShift32(spec["seed"])
    clues = public_clues()
    length = spec["message_length"]
    corpus = "".join((ROOT / "fixtures/blind-heldout-prose.txt").read_text(encoding="ascii").splitlines())
    if len(corpus) < length or any(letter not in LETTERS for letter in corpus):
        raise ValueError("held-out corpus is too short or invalid")
    cases = []
    classes = (("random", spec["positive_random"]), ("prose", spec["positive_prose"]),
               ("period_three", spec["negative_period_three"]), ("tamper", spec["negative_tampered"]))
    for kind, count in classes:
        for _ in range(count):
            message = plant_message(rng, kind, corpus, clues, length)
            route = ("identity", "reverse")[rng.choice(2)]
            equation = ("add", "variant", "reflect")[rng.choice(3)]
            period = 3 if kind == "period_three" else 1 + rng.choice(2)
            key = "".join(LETTERS[rng.choice(26)] for _ in range(period))
            if period == 2 and key[0] == key[1]:
                key = key[0] + LETTERS[(ord(key[1]) - 64) % 26]
            if period == 3 and len(set(key)) < 3:
                key = "ABC"
            ciphertext = encrypt(message, route, equation, key)
            if kind == "tamper":
                position = clues[rng.choice(len(clues))]["position"]
                j = position if route == "identity" else length - 1 - position
                altered = LETTERS[(ord(ciphertext[j]) - 64) % 26]
                ciphertext = ciphertext[:j] + altered + ciphertext[j + 1:]
            true_id = canonical_truth(route, equation, key) if kind in ("random", "prose") else None
            cases.append((kind, message, ciphertext, true_id))
    for i in range(len(cases) - 1, 0, -1):
        j = rng.choice(i + 1)
        cases[i], cases[j] = cases[j], cases[i]
    public = []
    private = []
    for index, (kind, message, ciphertext, true_id) in enumerate(cases):
        case_id = f"B{index:04}"
        public.append({"id": case_id, "ciphertext": ciphertext, "clues": clues,
                       "budget": spec["model_checks_per_case"]})
        private.append({"id": case_id, "kind": kind, "plaintext": message, "true_model_id": true_id})
    return public, private


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) != 1:
        print("usage: python3 experiments/run_blind.py results/BLIND-0001/run-NNN", file=sys.stderr)
        return 2
    output = (ROOT / argv[0]).resolve()
    if not output.is_relative_to((ROOT / "results/BLIND-0001").resolve()):
        print("output must be under results/BLIND-0001", file=sys.stderr)
        return 2
    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    for path, expected in spec["evidence_file_hashes"].items():
        if digest(ROOT / path) != expected:
            print(f"frozen input changed: {path}", file=sys.stderr)
            return 1
    output.mkdir(parents=True, exist_ok=False)
    run_id = str(output.relative_to(ROOT))
    started = datetime.now(timezone.utc).isoformat()
    inputs = [SPEC, ROOT / "experiments/run_blind.py", ROOT / "experiments/blind_attack.py",
              ROOT / "verification/verify_blind.py"]
    manifest = {**spec, "run_id": run_id, "started_at": started, "status": "running",
                "environment": {"python": sys.version, "platform": platform.platform()},
                "implementation_sha256": {str(path.relative_to(ROOT)): digest(path) for path in inputs}}
    write_json(output / "manifest.json", manifest)
    with (ROOT / "experiments/registry.jsonl").open("a", encoding="utf-8") as registry:
        registry.write(json.dumps({"experiment_id": spec["experiment_id"], "run_id": run_id,
                                   "status": "started", "at": started}) + "\n")
    start = time.monotonic()
    completion = {"run_id": run_id, "status": "failed", "exit_status": 1}
    try:
        public, private = make_cases(spec)
        if len(public) * spec["model_checks_per_case"] > spec["operation_cap"]:
            raise ValueError("registered operation cap exceeded")
        write_jsonl(output / "public-cases.jsonl", public)
        write_jsonl(output / "controller-private.jsonl", private)
        remaining = spec["wall_time_cap_seconds"] - (time.monotonic() - start)
        if remaining <= 0:
            raise subprocess.TimeoutExpired("attacker", 0)
        with (output / "attacker.stderr").open("xb") as stderr:
            result = subprocess.run([sys.executable, str(ROOT / "experiments/blind_attack.py"),
                                     str(output / "public-cases.jsonl"), str(output / "attacker-output.jsonl")],
                                    cwd=ROOT, stderr=stderr, timeout=remaining, check=False)
        if result.returncode:
            raise RuntimeError(f"attacker exited {result.returncode}")
        remaining = spec["wall_time_cap_seconds"] - (time.monotonic() - start)
        if remaining <= 0:
            raise subprocess.TimeoutExpired("verifier", 0)
        with (output / "verification.stderr").open("xb") as stderr, (output / "verification.json").open("xb") as stdout:
            result = subprocess.run([sys.executable, str(ROOT / "verification/verify_blind.py"), str(output)],
                                    cwd=ROOT, stdout=stdout, stderr=stderr, timeout=remaining, check=False)
        if result.returncode:
            raise RuntimeError(f"verifier exited {result.returncode}")
        for path in inputs:
            if digest(path) != manifest["implementation_sha256"][str(path.relative_to(ROOT))]:
                raise RuntimeError(f"implementation changed during run: {path}")
        for path, expected in spec["evidence_file_hashes"].items():
            if digest(ROOT / path) != expected:
                raise RuntimeError(f"frozen input changed during run: {path}")
        metrics = json.loads((output / "verification.json").read_text())
        completion.update(status="completed", exit_status=0, targets_pass=metrics["targets_pass"],
                          counters={"cases": len(public), "model_checks": sum(row["checks"] for row in
                                    map(json.loads, (output / "attacker-output.jsonl").read_text().splitlines())),
                                    "k4_models_checked": 0})
    except subprocess.TimeoutExpired as error:
        completion.update(status="timeout", error=str(error))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        completion["error"] = str(error)
    completion.update(finished_at=datetime.now(timezone.utc).isoformat(),
                      elapsed_seconds=time.monotonic() - start)
    completion["artifact_sha256"] = {path.name: digest(path) for path in sorted(output.iterdir()) if path.is_file()}
    write_json(output / "completion.json", completion)
    with (ROOT / "experiments/registry.jsonl").open("a", encoding="utf-8") as registry:
        registry.write(json.dumps({"experiment_id": spec["experiment_id"], "run_id": run_id,
                                   "status": completion["status"], "at": completion["finished_at"],
                                   "completion_sha256": digest(output / "completion.json")}) + "\n")
    print(json.dumps({key: completion[key] for key in ("status", "targets_pass") if key in completion}))
    return completion["exit_status"]


if __name__ == "__main__":
    sys.exit(main())
