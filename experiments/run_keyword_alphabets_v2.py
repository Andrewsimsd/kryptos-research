#!/usr/bin/env python3
"""Run amended keyword calibration, current-code foundations, and K4 evaluation."""

import argparse
import json
import platform
import subprocess
import sys
import time

from run_baseline import ROOT, digest, peak_memory, record_event, timestamp, verify_inputs, write_json


def implementation_paths():
    paths = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "README.md",
             ROOT / "experiments/KEYWORD-ALPHABETS-0002.json"]
    for directory, pattern in [
        ("src", "*.rs"), ("tests", "*.rs"), ("verification", "*.py"),
        ("experiments", "*.py"), ("docs", "*.md"), ("reports", "*.md"),
    ]:
        paths.extend(sorted((ROOT / directory).rglob(pattern)))
    return paths


def execute(output, specification, versions):
    hashes = {str(path.relative_to(ROOT)): digest(path) for path in implementation_paths()}
    run_id = str(output.relative_to(ROOT))
    manifest = {**specification, "status": "running", "run_id": run_id,
                "started_at": timestamp(), "environment": versions,
                "implementation_sha256": hashes}
    write_json(output / "manifest.json", manifest)
    record_event({"experiment_id": specification["experiment_id"], "run_id": run_id,
                  "status": "started", "at": manifest["started_at"]})
    binary = ROOT / "target/release" / ("kryptos-research.exe" if sys.platform == "win32" else "kryptos-research")
    commands = [
        ("build", ["cargo", "build", "--release", "--locked", "--offline", "--target-dir", str(ROOT / "target")], "build.stdout"),
        ("foundations", [sys.executable, "verification/verify_ciphers.py", "--binary", str(binary),
                         "--fixture-output", str(output / "foundation-fixture-traces.json"),
                         "--seed", str(specification["foundations_regression"]["seed"]),
                         "--cases-per-family", str(specification["foundations_regression"]["cases_per_family"])],
         "foundation-verification.json"),
        ("calibrate", [str(binary), "keyword-calibrate", "fixtures/keyword-alphabets-request.json"], "calibration.json"),
        ("evaluate", [str(binary), "keyword-alphabets", "fixtures/keyword-alphabets-request.json",
                      str(output / "calibration.json")], "keyword-alphabets.json"),
        ("verify", [sys.executable, "verification/verify_keyword_alphabets.py", "--calibration",
                    str(output / "calibration.json"), "--report", str(output / "keyword-alphabets.json"),
                    "--request", "fixtures/keyword-alphabets-request.json"], "verification.json"),
        ("baseline", [str(binary), "diagnose", "evidence/k4.json"], "baseline.json"),
        ("primers", [str(binary), "primers", "evidence/k4.json"], "primers.json"),
        ("feasibility", [str(binary), "feasibility", "fixtures/feasibility-request.json"], "feasibility.json"),
        ("structured", [str(binary), "structured-alphabets", "fixtures/structured-alphabets-request.json"], "structured-alphabets.json"),
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
                    process = subprocess.run(command, cwd=ROOT, stdout=stdout, stderr=stderr,
                                             timeout=remaining, check=False)
                    stage["exit_status"] = process.returncode
                finally:
                    stage["elapsed_seconds"] = time.monotonic() - stage_start
            if process.returncode:
                raise RuntimeError(f"stage {name} failed with exit {process.returncode}; inspect stderr")

        verify_inputs(specification, ROOT)
        if any(digest(ROOT / name) != expected for name, expected in hashes.items()):
            raise RuntimeError("implementation or documentation changed during run")
        regressions = [
            ("baseline.json", "baseline_output_sha256"), ("primers.json", "primer_report_sha256"),
            ("feasibility.json", "feasibility_report_sha256"),
            ("structured-alphabets.json", "structured_report_sha256"),
        ]
        for name, key in regressions:
            if digest(output / name) != specification[key]:
                raise RuntimeError(f"regression output changed: {name}")
        foundations = specification["foundations_regression"]
        if digest(output / "foundation-fixture-traces.json") != foundations["fixture_traces_sha256"]:
            raise RuntimeError("current binary changed preserved known-answer fixture traces")
        if digest(output / "foundation-verification.json") != foundations["verification_sha256"]:
            raise RuntimeError("current binary changed preserved 600-case foundations verification")

        result = json.loads((output / "verification.json").read_text())
        if (result["candidate_count"] != 146_016 or result["equations_checked"] != 3_504_384
                or result["retained_cases"] != 144 or result["plaintext_recovery_cases"] != 144
                or result["reencryption_cases"] != 144 or result["full_message_recovery_cases"] != 144):
            raise RuntimeError("amended calibration or K4 coverage gate incomplete")
        operations = result["operation_counts"]
        if operations != specification["operation_accounting"]:
            raise RuntimeError("emitted operation counters differ from registered accounting")
        component_sum = sum(value for key, value in operations.items() if key != "total")
        if component_sum != operations["total"] or operations["total"] > specification["operation_cap"]:
            raise RuntimeError("operation counter sum differs or exceeds registered cap")
        completion.update(
            status="completed", exit_status=0, binary_sha256=digest(binary),
            counters={key: result[key] for key in (
                "candidate_count", "equations_checked", "survivors", "best_match_count",
                "best_model_count", "calibration_cases", "retained_cases",
                "plaintext_recovery_cases", "reencryption_cases", "full_message_recovery_cases",
                "unique_recovery_cases")},
            operation_counts=operations,
            conclusion="Amended full-message recovery gate preserves the exact zero-survivor decision for the unchanged registered family; the result was already observed before amendment.",
        )
    except subprocess.TimeoutExpired as error:
        completion.update(status="timeout", error=str(error))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        completion.update(error=str(error))
    completion.update(finished_at=timestamp(), elapsed_seconds=time.monotonic() - start,
                      peak_child_memory=peak_memory())
    completion["artifact_sha256"] = {
        path.name: digest(path) for path in sorted(output.iterdir()) if path.is_file()
    }
    write_json(output / "completion.json", completion)
    record_event({"experiment_id": specification["experiment_id"], "run_id": run_id,
                  "status": completion["status"], "at": completion["finished_at"],
                  "completion_sha256": digest(output / "completion.json")})
    return completion


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args(argv)
    try:
        specification = json.loads((ROOT / "experiments/KEYWORD-ALPHABETS-0002.json").read_text())
        verify_inputs(specification, ROOT)
        versions = {name: subprocess.check_output([name, "--version"], text=True, timeout=10).strip()
                    for name in ("rustc", "cargo")}
        if versions["rustc"] != specification["rustc"]:
            raise ValueError("rustc differs from registered compiler")
        versions.update(python=sys.version, platform=platform.platform())
        output = (ROOT / args.output).resolve()
        if output == ROOT / "results" or not output.is_relative_to((ROOT / "results").resolve()):
            raise ValueError("output must be a new directory beneath results/")
        output.mkdir(parents=True, exist_ok=False)
        completion = execute(output, specification, versions)
        print(f"{completion['status']}: {output.relative_to(ROOT)}/completion.json")
        return completion["exit_status"]
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"keyword-alphabet amendment failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
