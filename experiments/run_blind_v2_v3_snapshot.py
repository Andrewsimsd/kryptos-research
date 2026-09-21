#!/usr/bin/env python3
"""Run corrected hidden-seed BLIND-0002; reveal truth after attacker exits."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time

from run_blind import ROOT, digest, make_cases, write_json, write_jsonl

SPEC = ROOT / "experiments/BLIND-0002.json"


class HashRng:
    """Counter-mode SHA-256 stream consumed as big-endian u32 words."""

    def __init__(self, seed):
        if len(seed) != 32:
            raise ValueError("seed must contain 32 bytes")
        self.seed = seed
        self.counter = 0
        self.words = []

    def next(self):
        if not self.words:
            block = hashlib.sha256(self.seed + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
            self.words = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 32, 4)]
        return self.words.pop(0)

    def choice(self, count):
        return self.next() % count


def now():
    return datetime.now(timezone.utc).isoformat()


def require_within_wall_cap(start, limit, clock=time.monotonic):
    """Classify a final overrun as timeout, including post-verifier work."""
    elapsed = clock() - start
    if elapsed > limit:
        raise subprocess.TimeoutExpired("blind run", limit)
    return elapsed


def main(argv=None, spec_path=SPEC, family="BLIND-0002", runner_path=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) != 2:
        print(f"usage: runner SEED_FILE results/{family}/run-NNN", file=sys.stderr)
        return 2
    seed_path = Path(argv[0]).resolve()
    output = (ROOT / argv[1]).resolve()
    if not output.is_relative_to((ROOT / "results" / family).resolve()):
        print(f"output must be under results/{family}", file=sys.stderr)
        return 2
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    try:
        seed_text = seed_path.read_text(encoding="ascii").strip()
        seed = bytes.fromhex(seed_text)
        if len(seed) != 32 or hashlib.sha256(seed).hexdigest() != spec["seed_commitment_sha256"]:
            raise ValueError("seed does not match preregistered commitment")
        if seed_path.is_relative_to(ROOT):
            raise ValueError("seed file must be outside repository before attacker exits")
        for path, expected in spec["evidence_file_hashes"].items():
            if digest(ROOT / path) != expected:
                raise ValueError(f"frozen input changed: {path}")
        output.mkdir(parents=True, exist_ok=False)
        run_id = str(output.relative_to(ROOT))
        code_paths = [spec_path, ROOT / "experiments/run_blind.py", Path(__file__),
                      ROOT / "experiments/blind_attack.py", ROOT / "verification/verify_blind.py"]
        if runner_path is not None:
            code_paths.append(runner_path)
        manifest = {**spec, "run_id": run_id, "started_at": now(), "status": "running",
                    "environment": {"python": sys.version, "platform": platform.platform()},
                    "implementation_sha256": {str(path.relative_to(ROOT)): digest(path) for path in code_paths}}
        write_json(output / "manifest.json", manifest)
        with (ROOT / "experiments/registry.jsonl").open("a", encoding="utf-8") as registry:
            registry.write(json.dumps({"experiment_id": spec["experiment_id"], "run_id": run_id,
                                       "status": "started", "at": manifest["started_at"]}) + "\n")
        start = time.monotonic()
        completion = {"run_id": run_id, "status": "failed", "exit_status": 1}
        temp_private = None
        try:
            public, private = make_cases(spec, HashRng(seed))
            if len(public) * spec["model_checks_per_case"] > spec["operation_cap"]:
                raise ValueError("operation cap exceeded")
            write_jsonl(output / "public-cases.jsonl", public)
            with tempfile.NamedTemporaryFile(prefix="blind-private-", suffix=".jsonl", delete=False) as temporary:
                temp_private = Path(temporary.name)
            temp_private.unlink()
            write_jsonl(temp_private, private)
            remaining = spec["wall_time_cap_seconds"] - (time.monotonic() - start)
            if remaining <= 0:
                raise subprocess.TimeoutExpired("attacker", 0)
            with (output / "attacker.stderr").open("xb") as stderr:
                result = subprocess.run([sys.executable, str(ROOT / "experiments/blind_attack.py"),
                                         str(output / "public-cases.jsonl"), str(output / "attacker-output.jsonl")],
                                        cwd=ROOT, stderr=stderr, timeout=remaining, check=False)
            if result.returncode:
                raise RuntimeError(f"attacker exited {result.returncode}")
            # /tmp may be on another filesystem; copy only after attack exit.
            with (output / "controller-private.jsonl").open("xb") as destination:
                with temp_private.open("rb") as source:
                    shutil.copyfileobj(source, destination)
            temp_private.unlink()
            temp_private = None
            write_json(output / "seed-reveal.json", {"seed_hex": seed_text,
                       "commitment_sha256": spec["seed_commitment_sha256"],
                       "revealed_after_attacker_exit": True})
            remaining = spec["wall_time_cap_seconds"] - (time.monotonic() - start)
            if remaining <= 0:
                raise subprocess.TimeoutExpired("verifier", 0)
            with (output / "verification.stderr").open("xb") as stderr, (output / "verification.json").open("xb") as stdout:
                result = subprocess.run([sys.executable, str(ROOT / "verification/verify_blind.py"), str(output)],
                                        cwd=ROOT, stderr=stderr, stdout=stdout, timeout=remaining, check=False)
            if result.returncode:
                raise RuntimeError(f"verifier exited {result.returncode}")
            for path in code_paths:
                if digest(path) != manifest["implementation_sha256"][str(path.relative_to(ROOT))]:
                    raise RuntimeError(f"implementation changed during run: {path}")
            for path, expected in spec["evidence_file_hashes"].items():
                if digest(ROOT / path) != expected:
                    raise RuntimeError(f"frozen input changed during run: {path}")
            metrics = json.loads((output / "verification.json").read_text())
            require_within_wall_cap(start, spec["wall_time_cap_seconds"])
            completion.update(status="completed", exit_status=0, targets_pass=metrics["targets_pass"],
                              counters={"cases": len(public), "model_checks": metrics["model_checks"],
                                        "k4_models_checked": 0})
        except subprocess.TimeoutExpired as error:
            completion.update(status="timeout", error=str(error))
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
            completion["error"] = str(error)
        finally:
            if temp_private is not None:
                temp_private.unlink(missing_ok=True)
        completion.update(finished_at=now(), elapsed_seconds=time.monotonic() - start)
        completion["artifact_sha256"] = {path.name: digest(path) for path in sorted(output.iterdir()) if path.is_file()}
        write_json(output / "completion.json", completion)
        with (ROOT / "experiments/registry.jsonl").open("a", encoding="utf-8") as registry:
            registry.write(json.dumps({"experiment_id": spec["experiment_id"], "run_id": run_id,
                                       "status": completion["status"], "at": completion["finished_at"],
                                       "completion_sha256": digest(output / "completion.json")}) + "\n")
        print(json.dumps({key: completion[key] for key in ("status", "targets_pass") if key in completion}))
        return completion["exit_status"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"blind run failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
