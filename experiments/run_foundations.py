#!/usr/bin/env python3
"""Preserve a bounded run of published fixtures and seeded differential checks."""

import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

from run_baseline import ROOT, digest, peak_memory, record_event, timestamp, verify_inputs, write_json


def execute(output, specification, versions):
    """Record inputs before running; keep failure artifacts and never overwrite."""
    paths = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "experiments/FOUNDATIONS-0001.json"]
    for directory, pattern in [("src", "*.rs"), ("tests", "*.rs"), ("verification", "*.py"), ("experiments", "*.py")]:
        paths.extend(sorted((ROOT / directory).rglob(pattern)))
    source_hashes = {str(path.relative_to(ROOT)): digest(path) for path in paths}
    run_id = str(output.relative_to(ROOT))
    manifest = {**specification, "status": "running", "run_id": run_id, "started_at": timestamp(),
                "environment": versions, "implementation_sha256": source_hashes}
    write_json(output / "manifest.json", manifest)
    record_event({"experiment_id": specification["experiment_id"], "run_id": run_id, "status": "started", "at": manifest["started_at"]})
    binary = ROOT / "target/debug" / ("kryptos-research.exe" if sys.platform == "win32" else "kryptos-research")
    commands = [
        ("build", ["cargo", "build", "--locked", "--offline", "--target-dir", str(ROOT / "target")], "build.stdout"),
        ("fixtures", [sys.executable, "verification/verify_ciphers.py", "--binary", str(binary),
                      "--fixture-output", str(output / "fixture-traces.json"), "--seed", str(specification["seed"]),
                      "--cases-per-family", str(specification["cases_per_family"])], "verification.json"),
        ("baseline", [str(binary), "diagnose", "evidence/k4.json"], "baseline.json"),
        ("baseline-verify", [sys.executable, "verification/verify_baseline.py", "--report", str(output / "baseline.json"),
                             "--ledger", "evidence/sources.jsonl"], "baseline-verification.json"),
    ]
    completion = {"run_id": run_id, "status": "failed", "exit_status": 1, "stages": []}
    start = time.monotonic()
    try:
        for name, command, stdout_name in commands:
            remaining = specification["wall_time_cap_seconds"] - (time.monotonic() - start)
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, 0)
            stage = {"name": name, "command": command, "exit_status": None}
            completion["stages"].append(stage)
            stage_start = time.monotonic()
            with (output / stdout_name).open("xb") as stdout, (output / f"{name}.stderr").open("xb") as stderr:
                try:
                    process = subprocess.run(command, cwd=ROOT, stdout=stdout, stderr=stderr, timeout=remaining, check=False)
                    stage["exit_status"] = process.returncode
                finally:
                    stage["elapsed_seconds"] = time.monotonic() - stage_start
            if process.returncode:
                raise RuntimeError(f"stage {name} failed with exit {process.returncode}; inspect its stderr artifact")
        verify_inputs(specification, ROOT)
        if any(digest(ROOT / name) != expected for name, expected in source_hashes.items()):
            raise RuntimeError("implementation changed during run")
        baseline_digest = digest(output / "baseline.json")
        if baseline_digest != specification["baseline_output_sha256"]:
            raise RuntimeError("milestone-1 diagnosis output changed")
        verification = json.loads((output / "verification.json").read_text())
        counts = {"published_fixture_pairs": verification["fixture_pairs"],
                  "synthetic_message_pairs": sum(f["message_pairs"] for f in verification["synthetic"]),
                  "synthetic_families": len(verification["synthetic"]), "k4_keys_searched": 0}
        completion.update(status="completed", exit_status=0, counters=counts,
                          binary_sha256=digest(binary), baseline_output_sha256=baseline_digest)
    except subprocess.TimeoutExpired as error:
        completion.update(status="timeout", error=str(error))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        completion.update(error=str(error))
    completion.update(finished_at=timestamp(), elapsed_seconds=time.monotonic() - start, peak_child_memory=peak_memory())
    completion["artifact_sha256"] = {path.name: digest(path) for path in sorted(output.iterdir()) if path.is_file()}
    write_json(output / "completion.json", completion)
    record_event({"experiment_id": specification["experiment_id"], "run_id": run_id, "status": completion["status"],
                  "at": completion["finished_at"], "completion_sha256": digest(output / "completion.json")})
    return completion


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", help="new directory beneath results/")
    args = parser.parse_args(argv)
    try:
        specification = json.loads((ROOT / "experiments/FOUNDATIONS-0001.json").read_text())
        verify_inputs(specification, ROOT)
        versions = {name: subprocess.check_output([name, "--version"], text=True, timeout=10).strip() for name in ("rustc", "cargo")}
        if versions["rustc"] != specification["rustc"]:
            raise ValueError("rustc differs from the registered compiler")
        versions.update(python=sys.version, platform=platform.platform())
        output = (ROOT / args.output).resolve()
        if output == ROOT / "results" or not output.is_relative_to((ROOT / "results").resolve()):
            raise ValueError("output must be a new directory beneath results/")
        output.mkdir(parents=True, exist_ok=False)
        completion = execute(output, specification, versions)
        print(f"{completion['status']}: {output.relative_to(ROOT)}/completion.json")
        return completion["exit_status"]
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"foundations experiment failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
