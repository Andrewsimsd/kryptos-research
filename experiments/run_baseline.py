#!/usr/bin/env python3
"""Run the registered, bounded baseline diagnosis in a new output directory.

Only the Python standard library and the pinned Cargo dependencies are needed.
Runs are sequential: this coordinator is the sole writer of registry.jsonl.
Evidence changes require a new experiment specification, never silently a rerun.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    """Create one artifact exclusively; an existing run is never overwritten."""
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")


def verify_inputs(specification, root):
    """Reject changed frozen evidence before starting an experiment."""
    for name, expected in specification["evidence_file_hashes"].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ValueError(f"evidence path escapes project: {name}")
        if digest(path) != expected:
            raise ValueError(f"frozen evidence changed: {name}; register a new experiment")


def record_event(event):
    """Append a coordinator event, retaining failed and successful runs alike."""
    with (ROOT / "experiments/registry.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, allow_nan=False) + "\n")


def peak_memory():
    """Report OS child-process high-water memory with explicit platform units."""
    try:
        import resource
    except ImportError:
        return {"value": None, "unit": None, "reason": "resource module unavailable"}
    return {"value": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            "unit": "bytes" if sys.platform == "darwin" else "KiB" if sys.platform.startswith("linux") else "platform_native",
            "scope": "OS child-process maximum RSS, including build and verification; not simultaneous total memory"}


def execute_run(specification, output, versions):
    """Preserve the initial manifest, logs, completion record and registry events."""
    run_id = str(output.relative_to(ROOT))
    inputs = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "experiments/K4-D-0001.json"]
    inputs += sorted((ROOT / "src").rglob("*.rs"))
    inputs += sorted((ROOT / "verification").glob("*.py"))
    inputs += [Path(__file__).resolve()]
    manifest = {**specification, "run_id": run_id, "started_at": timestamp(), "status": "running",
                "environment": versions, "input_sha256": {str(p.relative_to(ROOT)): digest(p) for p in inputs}}
    write_json(output / "manifest.json", manifest)
    record_event({"run_id": run_id, "experiment_id": specification["experiment_id"],
                  "status": "started", "at": manifest["started_at"]})
    start = time.monotonic()
    stages = []
    binary = ROOT / "target/debug" / ("kryptos-research.exe" if sys.platform == "win32" else "kryptos-research")
    commands = [
        ("build", ["cargo", "build", "--locked", "--offline", "--target-dir", str(ROOT / "target")], "build.stdout"),
        ("diagnose", [str(binary), "diagnose", "evidence/k4.json"], "diagnosis.json"),
        ("verify", [sys.executable, "verification/verify_baseline.py", "--report", str(output / "diagnosis.json"),
                    "--ledger", "evidence/sources.jsonl"], "verification.json"),
    ]
    completion = {"run_id": run_id, "status": "failed", "stages": stages}
    try:
        for name, command, stdout_name in commands:
            remaining = specification["search"]["wall_time_cap_seconds"] - (time.monotonic() - start)
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, 0)
            stage_start = time.monotonic()
            stage = {"stage": name, "command": command, "exit_status": None}
            stages.append(stage)
            with (output / stdout_name).open("xb") as stdout, (output / f"{name}.stderr").open("xb") as stderr:
                try:
                    process = subprocess.run(command, cwd=ROOT, stdout=stdout, stderr=stderr,
                                             timeout=remaining, check=False)
                    stage["exit_status"] = process.returncode
                finally:
                    stage["elapsed_seconds"] = time.monotonic() - stage_start
            if process.returncode:
                raise RuntimeError(f"{name} exited {process.returncode}; inspect {name}.stderr")
        # Verify evidence and code did not change between the two implementations.
        verify_inputs(specification, ROOT)
        if any(digest(ROOT / name) != expected for name, expected in manifest["input_sha256"].items()):
            raise RuntimeError("implementation inputs changed during the run")
        report = json.loads((output / "diagnosis.json").read_text(encoding="utf-8"))
        periods = report["vigenere"]["periods"]
        completion.update(status="completed", exit_status=0, binary_sha256=digest(binary),
                          counters={"family_checks": len(report["checks"]), "periods_evaluated": len(periods),
                                    "periods_rejected": sum(p["status"] == "rejected" for p in periods),
                                    "periods_surviving_necessary_test": len(report["vigenere"]["surviving_periods"]),
                                    "plaintext_candidates_searched": 0},
                          conclusion="Exact scoped contradictions only; no plaintext or historical mechanism recovered.")
    except subprocess.TimeoutExpired as error:
        completion.update(status="timeout", exit_status=1, error=str(error))
    except (OSError, ValueError, RuntimeError) as error:
        completion.update(exit_status=1, error=str(error))
    completion.update(finished_at=timestamp(), elapsed_seconds=time.monotonic() - start,
                      peak_child_memory=peak_memory())
    completion["artifact_sha256"] = {p.name: digest(p) for p in sorted(output.iterdir()) if p.is_file()}
    write_json(output / "completion.json", completion)
    record_event({"run_id": run_id, "experiment_id": specification["experiment_id"],
                  "status": completion["status"], "at": completion["finished_at"],
                  "completion_sha256": digest(output / "completion.json")})
    return completion


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", help="new directory beneath results/, relative to project root")
    args = parser.parse_args(argv)
    try:
        specification = json.loads((ROOT / "experiments/K4-D-0001.json").read_text(encoding="utf-8"))
        verify_inputs(specification, ROOT)
        versions = {name: subprocess.check_output([name, "--version"], text=True, timeout=10).strip()
                    for name in ("rustc", "cargo")}
        if versions["rustc"] != specification["toolchain"]["rustc"]:
            raise ValueError("rustc differs from registered toolchain; select the recorded version with rustup")
        versions.update(python=sys.version, platform=platform.platform())
        output = (ROOT / args.output).resolve()
        if output == ROOT / "results" or not output.is_relative_to((ROOT / "results").resolve()):
            raise ValueError("output must be a new directory beneath results/")
        output.mkdir(parents=True, exist_ok=False)
        completion = execute_run(specification, output, versions)
        print(f"{completion['status']}: {output.relative_to(ROOT)}/completion.json")
        return completion["exit_status"]
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"experiment failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
