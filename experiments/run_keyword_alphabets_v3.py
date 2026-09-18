#!/usr/bin/env python3
"""Run the corrected keyword experiment with a pre-search independent gate."""

import argparse
import json
import platform
import subprocess
import sys
import time

from run_baseline import ROOT, digest, peak_memory, record_event, timestamp, verify_inputs, write_json


CALIBRATION_OPERATIONS = 3_546_288
K4_OPERATIONS = 3_504_384
EXECUTION_OPERATIONS = 10_596_960
COMBINED_KEYWORD_OPERATIONS = 21_193_920

CALIBRATION_PROFILE = {
    "signature_equation_evaluations": 3_504_384,
    "planted_encryption_positions": 13_968,
    "planted_decryption_positions": 13_968,
    "planted_reencryption_positions": 13_968,
}

LEGACY_LOGICAL_PROFILE = {
    **CALIBRATION_PROFILE,
    "k4_equation_evaluations": K4_OPERATIONS,
    "total": 7_050_672,
}

EXECUTION_PROFILE = {
    "produced_calibration": CALIBRATION_OPERATIONS,
    "evaluation_internal_calibration_regeneration": CALIBRATION_OPERATIONS,
    "k4_equation_evaluations": K4_OPERATIONS,
    "total": EXECUTION_OPERATIONS,
}

WORKLOAD_PROFILE = {
    "primary_rust": EXECUTION_PROFILE,
    "python_pre_search_calibration_verification": {
        "operation_counts": CALIBRATION_PROFILE,
        "total": CALIBRATION_OPERATIONS,
    },
    "python_post_search_full_verification": {
        "operation_counts": LEGACY_LOGICAL_PROFILE,
        "total": LEGACY_LOGICAL_PROFILE["total"],
    },
    "combined_keyword_equation_and_position_operations": COMBINED_KEYWORD_OPERATIONS,
    "excluded_units": "builds, JSON handling, foundations and regression commands",
}


def implementation_paths():
    paths = [
        ROOT / "Cargo.toml",
        ROOT / "Cargo.lock",
        ROOT / "README.md",
        ROOT / "experiments/KEYWORD-ALPHABETS-0003.json",
    ]
    for directory, pattern in [
        ("src", "*.rs"),
        ("tests", "*.rs"),
        ("verification", "*.py"),
        ("experiments", "*.py"),
        ("docs", "*.md"),
        ("reports", "*.md"),
    ]:
        paths.extend(sorted((ROOT / directory).rglob(pattern)))
    return paths


def validate_registered_budget(specification):
    """Fail before execution when the fixed work profile exceeds its cap."""
    accounting = specification.get("execution_operation_accounting")
    if accounting != EXECUTION_PROFILE or any(type(value) is not int for value in accounting.values()):
        raise ValueError("registered execution accounting differs from the fixed work profile")
    cap = specification.get("execution_operation_cap")
    if type(cap) is not int or cap < accounting["total"]:
        raise ValueError("registered execution operation cap is below the fixed work profile")


def validate_execution(result, calibration_gate, specification):
    """Validate coverage, labels, and actual work performed by the coordinator."""
    required = {
        "calibration_cases": 144,
        "candidate_count": 146_016,
        "equations_checked": K4_OPERATIONS,
        "survivors": 0,
        "best_match_count": 7,
        "best_model_count": 7,
        "retained_cases": 144,
        "plaintext_recovery_cases": 144,
        "reencryption_cases": 144,
        "full_message_recovery_cases": 144,
        "unique_recovery_cases": 98,
    }
    if result.get("status") != "verified":
        raise RuntimeError("post-search verification status is not verified")
    if any(type(result.get(key)) is not int or result.get(key) != value for key, value in required.items()):
        raise RuntimeError("calibration or K4 coverage gate incomplete")
    calibration_counts = {
        "candidate_count": 146_016,
        "calibration_cases": 144,
        "true_model_retained_cases": 144,
        "known_true_model_roundtrip_cases": 144,
        "singleton_recovery_sets": 98,
    }
    if calibration_gate.get("status") != "verified":
        raise RuntimeError("pre-search calibration status is not verified")
    if any(
        type(calibration_gate.get(key)) is not int or calibration_gate.get(key) != value
        for key, value in calibration_counts.items()
    ):
        raise RuntimeError("independent pre-search calibration gate incomplete")
    calibration_operations = calibration_gate.get("operation_counts")
    logical_operations = result.get("operation_counts")
    if (
        calibration_operations != CALIBRATION_PROFILE
        or any(type(value) is not int for value in calibration_operations.values())
    ):
        raise RuntimeError("pre-search calibration operation profile differs")
    if (
        logical_operations != LEGACY_LOGICAL_PROFILE
        or any(type(value) is not int for value in logical_operations.values())
    ):
        raise RuntimeError("verifier logical operation profile differs")
    produced = sum(calibration_operations.values())
    regenerated = sum(CALIBRATION_PROFILE.values())
    executed = {
        "produced_calibration": produced,
        "evaluation_internal_calibration_regeneration": regenerated,
        "k4_equation_evaluations": logical_operations["k4_equation_evaluations"],
        "total": produced + regenerated + K4_OPERATIONS,
    }
    if executed != specification["execution_operation_accounting"]:
        raise RuntimeError("executed work differs from registered accounting")
    if executed["total"] > specification["execution_operation_cap"]:
        raise RuntimeError("executed work exceeds registered cap")
    return executed


def execute(output, specification, versions):
    validate_registered_budget(specification)
    hashes = {str(path.relative_to(ROOT)): digest(path) for path in implementation_paths()}
    run_id = str(output.relative_to(ROOT))
    manifest = {
        **specification,
        "status": "running",
        "run_id": run_id,
        "started_at": timestamp(),
        "environment": versions,
        "implementation_sha256": hashes,
    }
    write_json(output / "manifest.json", manifest)
    record_event(
        {
            "experiment_id": specification["experiment_id"],
            "run_id": run_id,
            "status": "started",
            "at": manifest["started_at"],
        }
    )
    binary = ROOT / "target/release" / (
        "kryptos-research.exe" if sys.platform == "win32" else "kryptos-research"
    )
    commands = [
        (
            "build",
            [
                "cargo",
                "build",
                "--release",
                "--locked",
                "--offline",
                "--target-dir",
                str(ROOT / "target"),
            ],
            "build.stdout",
        ),
        (
            "foundations",
            [
                sys.executable,
                "verification/verify_ciphers.py",
                "--binary",
                str(binary),
                "--fixture-output",
                str(output / "foundation-fixture-traces.json"),
                "--seed",
                str(specification["foundations_regression"]["seed"]),
                "--cases-per-family",
                str(specification["foundations_regression"]["cases_per_family"]),
            ],
            "foundation-verification.json",
        ),
        (
            "calibrate",
            [str(binary), "keyword-calibrate", "fixtures/keyword-alphabets-request.json"],
            "calibration.json",
        ),
        (
            "calibration-verify",
            [
                sys.executable,
                "verification/verify_keyword_calibration.py",
                "--calibration",
                str(output / "calibration.json"),
                "--request",
                "fixtures/keyword-alphabets-request.json",
            ],
            "calibration-verification.json",
        ),
        (
            "evaluate",
            [
                str(binary),
                "keyword-alphabets",
                "fixtures/keyword-alphabets-request.json",
                str(output / "calibration.json"),
            ],
            "keyword-alphabets.json",
        ),
        (
            "verify",
            [
                sys.executable,
                "verification/verify_keyword_alphabets.py",
                "--calibration",
                str(output / "calibration.json"),
                "--report",
                str(output / "keyword-alphabets.json"),
                "--request",
                "fixtures/keyword-alphabets-request.json",
            ],
            "verification.json",
        ),
        ("baseline", [str(binary), "diagnose", "evidence/k4.json"], "baseline.json"),
        ("primers", [str(binary), "primers", "evidence/k4.json"], "primers.json"),
        (
            "feasibility",
            [str(binary), "feasibility", "fixtures/feasibility-request.json"],
            "feasibility.json",
        ),
        (
            "structured",
            [
                str(binary),
                "structured-alphabets",
                "fixtures/structured-alphabets-request.json",
            ],
            "structured-alphabets.json",
        ),
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
            with (output / stdout_name).open("xb") as stdout, (
                output / f"{name}.stderr"
            ).open("xb") as stderr:
                try:
                    process = subprocess.run(
                        command,
                        cwd=ROOT,
                        stdout=stdout,
                        stderr=stderr,
                        timeout=remaining,
                        check=False,
                    )
                    stage["exit_status"] = process.returncode
                finally:
                    stage["elapsed_seconds"] = time.monotonic() - stage_start
            if process.returncode:
                raise RuntimeError(f"stage {name} failed with exit {process.returncode}; inspect stderr")

        verify_inputs(specification, ROOT)
        if any(digest(ROOT / name) != expected for name, expected in hashes.items()):
            raise RuntimeError("implementation or documentation changed during run")
        for name, key in [
            ("baseline.json", "baseline_output_sha256"),
            ("primers.json", "primer_report_sha256"),
            ("feasibility.json", "feasibility_report_sha256"),
            ("structured-alphabets.json", "structured_report_sha256"),
        ]:
            if digest(output / name) != specification[key]:
                raise RuntimeError(f"regression output changed: {name}")
        foundations = specification["foundations_regression"]
        if digest(output / "foundation-fixture-traces.json") != foundations["fixture_traces_sha256"]:
            raise RuntimeError("current binary changed preserved known-answer fixture traces")
        if digest(output / "foundation-verification.json") != foundations["verification_sha256"]:
            raise RuntimeError("current binary changed preserved foundations verification")

        result = json.loads((output / "verification.json").read_text())
        calibration_gate = json.loads((output / "calibration-verification.json").read_text())
        executed = validate_execution(result, calibration_gate, specification)
        completion.update(
            status="completed",
            exit_status=0,
            binary_sha256=digest(binary),
            counters={
                key: result[key]
                for key in (
                    "candidate_count",
                    "equations_checked",
                    "survivors",
                    "best_match_count",
                    "best_model_count",
                    "calibration_cases",
                    "retained_cases",
                    "plaintext_recovery_cases",
                    "reencryption_cases",
                    "full_message_recovery_cases",
                    "unique_recovery_cases",
                )
            },
            execution_operation_counts=executed,
            workload_accounting=WORKLOAD_PROFILE,
            conclusion=(
                "The corrected gates preserve the exact zero-survivor decision for the unchanged "
                "family. The 144 round-trips use the known planted model; 98 cases have singleton "
                "recovery sets."
            ),
        )
    except subprocess.TimeoutExpired as error:
        completion.update(status="timeout", error=str(error))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        completion.update(error=str(error))
    completion.update(
        finished_at=timestamp(),
        elapsed_seconds=time.monotonic() - start,
        peak_child_memory=peak_memory(),
    )
    completion["artifact_sha256"] = {
        path.name: digest(path) for path in sorted(output.iterdir()) if path.is_file()
    }
    write_json(output / "completion.json", completion)
    record_event(
        {
            "experiment_id": specification["experiment_id"],
            "run_id": run_id,
            "status": completion["status"],
            "at": completion["finished_at"],
            "completion_sha256": digest(output / "completion.json"),
        }
    )
    return completion


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args(argv)
    try:
        specification = json.loads((ROOT / "experiments/KEYWORD-ALPHABETS-0003.json").read_text())
        verify_inputs(specification, ROOT)
        validate_registered_budget(specification)
        versions = {
            name: subprocess.check_output([name, "--version"], text=True, timeout=10).strip()
            for name in ("rustc", "cargo")
        }
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
        print(f"keyword-alphabet correction failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
