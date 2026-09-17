#!/usr/bin/env python3
"""Run a registered fixed-size statistical experiment in a new results directory."""

import argparse
import json
import platform
import subprocess
import sys
import time

from run_baseline import ROOT, digest, peak_memory, record_event, timestamp, verify_inputs, write_json


def execute(output, spec_path, specification, versions):
    inputs = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", spec_path]
    for directory, pattern in [("src", "*.rs"), ("tests", "*.rs"), ("verification", "*.py"), ("experiments", "*.py")]:
        inputs.extend(sorted((ROOT / directory).rglob(pattern)))
    hashes = {str(path.relative_to(ROOT)): digest(path) for path in inputs}
    run_id = str(output.relative_to(ROOT))
    manifest = {**specification, "status": "running", "run_id": run_id, "started_at": timestamp(),
                "environment": versions, "implementation_sha256": hashes}
    write_json(output / "manifest.json", manifest)
    write_json(output / "request.json", specification["request"])
    record_event({"experiment_id": specification["experiment_id"], "run_id": run_id,
                  "status": "started", "at": manifest["started_at"]})
    binary = ROOT / "target/release" / ("kryptos-research.exe" if sys.platform == "win32" else "kryptos-research")
    upstream = output / "bean-statistics"
    commands = [
        ("build", ["cargo", "build", "--release", "--locked", "--offline", "--target-dir", str(ROOT / "target")], "build.stdout"),
        ("upstream-build", ["cc", "-std=gnu99", "-O2", "third_party/bean-statistics-harness.c", "-o", str(upstream)], "upstream-build.stdout"),
        ("statistics", [str(binary), "statistics", str(output / "request.json")], "statistics.json"),
        ("verify", [sys.executable, "verification/verify_statistics.py", "--report", str(output / "statistics.json"),
                    "--request", str(output / "request.json"), "--upstream-binary", str(upstream), "--output", str(output)], "verification.json"),
        ("baseline", [str(binary), "diagnose", "evidence/k4.json"], "baseline.json"),
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
        if any(digest(ROOT / name) != expected for name, expected in hashes.items()):
            raise RuntimeError("implementation changed during run")
        if digest(output / "baseline.json") != specification["baseline_output_sha256"]:
            raise RuntimeError("baseline diagnosis changed")
        result = json.loads((output / "verification.json").read_text())
        completion.update(status="completed", exit_status=0, binary_sha256=digest(binary),
                          counters={"samples": result["samples_regenerated"], "statistics": len(result["statistics"]),
                                    "upstream_texts_checked": result["upstream_texts_checked"]},
                          conclusion=result["interpretation"])
    except subprocess.TimeoutExpired as error:
        completion.update(status="timeout", error=str(error))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        completion.update(error=str(error))
    if upstream.exists():
        completion["upstream_binary_sha256"] = digest(upstream)
        upstream.unlink()
    completion.update(finished_at=timestamp(), elapsed_seconds=time.monotonic() - start, peak_child_memory=peak_memory())
    completion["artifact_sha256"] = {path.name: digest(path) for path in sorted(output.iterdir()) if path.is_file()}
    write_json(output / "completion.json", completion)
    record_event({"experiment_id": specification["experiment_id"], "run_id": run_id, "status": completion["status"],
                  "at": completion["finished_at"], "completion_sha256": digest(output / "completion.json")})
    return completion


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specification", help="registered JSON file beneath experiments/")
    parser.add_argument("output", help="new directory beneath results/")
    args = parser.parse_args(argv)
    try:
        spec_path = (ROOT / args.specification).resolve()
        if not spec_path.is_relative_to(ROOT / "experiments"):
            raise ValueError("specification must be beneath experiments/")
        specification = json.loads(spec_path.read_text())
        request = specification["request"]
        if (set(request) != {"schema_version", "samples", "seed"} or any(type(v) is not int for v in request.values())
                or request["schema_version"] != 1 or not 1 <= request["samples"] <= 10_000_000
                or not 0 <= request["seed"] < 2**64 or request["samples"] != specification["evaluation_cap"]):
            raise ValueError("invalid registered request or evaluation cap")
        verify_inputs(specification, ROOT)
        versions = {name: subprocess.check_output([name, "--version"], text=True, timeout=10).strip() for name in ("rustc", "cargo", "cc")}
        if versions["rustc"] != specification["rustc"] or versions["cc"].splitlines()[0] != specification["cc"]:
            raise ValueError("compiler differs from registered version")
        versions.update(python=sys.version, platform=platform.platform())
        output = (ROOT / args.output).resolve()
        if output == ROOT / "results" or not output.is_relative_to((ROOT / "results").resolve()):
            raise ValueError("output must be a new directory beneath results/")
        output.mkdir(parents=True, exist_ok=False)
        completion = execute(output, spec_path, specification, versions)
        print(f"{completion['status']}: {output.relative_to(ROOT)}/completion.json")
        return completion["exit_status"]
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"statistics experiment failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
