#!/usr/bin/env python3
"""Audit preserved result, frozen-input, and registry hashes."""

import argparse
import hashlib
import json
from pathlib import Path
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def safe_project_path(root, relative, context):
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError(f"{context}: path escapes repository: {relative}")
    return path


def require_digest(path, expected, context):
    if not path.is_file():
        raise ValueError(f"{context}: missing file: {path}")
    actual = digest(path)
    if actual != expected:
        raise ValueError(f"{context}: SHA-256 mismatch for {path}: expected {expected}, got {actual}")


def audit(root):
    """Validate immutable run artifacts, registered inputs, and completion events."""
    root = root.resolve()
    completions = sorted((root / "results").glob("*/*/completion.json"))
    if not completions:
        raise ValueError(f"{root}: no completion records found")
    artifact_count = 0
    evidence_count = 0
    completion_by_run = {}
    for completion_path in completions:
        completion = read_json(completion_path)
        expected_run_id = str(completion_path.parent.relative_to(root))
        if completion.get("run_id") != expected_run_id:
            raise ValueError(f"{completion_path}: run_id does not match its directory")
        if completion.get("status") not in {"completed", "failed", "timeout", "interrupted"}:
            raise ValueError(f"{completion_path}: invalid final status")
        completion_by_run[expected_run_id] = completion
        artifacts = completion.get("artifact_sha256")
        if not isinstance(artifacts, dict):
            raise ValueError(f"{completion_path}: artifact_sha256 must be an object")
        for name, expected in artifacts.items():
            if not isinstance(name, str) or "/" in name or name in ("", ".", ".."):
                raise ValueError(f"{completion_path}: invalid artifact name: {name!r}")
            artifact_path = (completion_path.parent / name).resolve()
            if not artifact_path.is_relative_to(completion_path.parent.resolve()):
                raise ValueError(f"{completion_path}: artifact escapes run directory: {name}")
            require_digest(artifact_path, expected, str(completion_path))
            artifact_count += 1

        manifest_path = completion_path.parent / "manifest.json"
        manifest = read_json(manifest_path)
        evidence = manifest.get("evidence_file_hashes", {})
        if not isinstance(evidence, dict):
            raise ValueError(f"{manifest_path}: evidence_file_hashes must be an object")
        for relative, expected in evidence.items():
            path = safe_project_path(root, relative, str(manifest_path))
            require_digest(path, expected, str(manifest_path))
            evidence_count += 1

    specification_count = 0
    for specification_path in sorted((root / "experiments").glob("*.json")):
        specification = read_json(specification_path)
        evidence = specification.get("evidence_file_hashes", {})
        if not isinstance(evidence, dict):
            raise ValueError(f"{specification_path}: evidence_file_hashes must be an object")
        for relative, expected in evidence.items():
            path = safe_project_path(root, relative, str(specification_path))
            require_digest(path, expected, str(specification_path))
            evidence_count += 1
        specification_count += 1

    checksum_count = 0
    for checksum_path in (root / "evidence/SHA256SUMS", root / "fixtures/SHA256SUMS"):
        if not checksum_path.is_file():
            raise ValueError(f"missing checksum inventory: {checksum_path}")
        for line_number, line in enumerate(checksum_path.read_text(encoding="utf-8").splitlines(), 1):
            parts = line.split(maxsplit=1)
            if len(parts) != 2 or len(parts[0]) != 64:
                raise ValueError(f"{checksum_path}:{line_number}: malformed checksum line")
            path = safe_project_path(root, parts[1].lstrip("*"), f"{checksum_path}:{line_number}")
            require_digest(path, parts[0], f"{checksum_path}:{line_number}")
            checksum_count += 1

    registry_path = root / "experiments/registry.jsonl"
    if not registry_path.is_file():
        raise ValueError(f"missing experiment registry: {registry_path}")
    completion_events = 0
    seen_final = set()
    for line_number, line in enumerate(registry_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError(f"{registry_path}:{line_number}: expected a JSON object")
        if "completion_sha256" not in event:
            continue
        run_id = event.get("run_id")
        if not isinstance(run_id, str):
            raise ValueError(f"{registry_path}:{line_number}: completion event lacks run_id")
        if run_id in seen_final:
            raise ValueError(f"{registry_path}:{line_number}: duplicate completion event for {run_id}")
        completion_path = safe_project_path(root, f"{run_id}/completion.json", str(registry_path))
        require_digest(completion_path, event["completion_sha256"], f"{registry_path}:{line_number}")
        completion = completion_by_run.get(run_id)
        if completion is None or event.get("status") != completion["status"]:
            raise ValueError(f"{registry_path}:{line_number}: registry and completion status differ")
        seen_final.add(run_id)
        completion_events += 1
    missing_events = set(completion_by_run) - seen_final
    if missing_events:
        raise ValueError(f"{registry_path}: completion records lack final events: {sorted(missing_events)}")

    return {
        "status": "verified",
        "completion_records": len(completions),
        "artifact_hashes": artifact_count,
        "registered_input_hashes": evidence_count,
        "experiment_specifications": specification_count,
        "checksum_inventory_entries": checksum_count,
        "registry_completion_events": completion_events,
        "scope": (
            "Byte integrity and registry linkage only; historical implementation hashes describe "
            "the checkout used for each run and are not compared with the current checkout."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        print(json.dumps(audit(args.root), indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"repository audit failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
