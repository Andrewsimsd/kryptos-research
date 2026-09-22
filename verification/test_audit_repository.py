"""Tests for preserved-artifact and registry integrity auditing."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from audit_repository import audit


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


class RepositoryAuditTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        evidence = root / "evidence/input.json"
        evidence.parent.mkdir(parents=True)
        evidence.write_text("frozen\n", encoding="utf-8")
        checksum = f"{digest(evidence)}  evidence/input.json\n"
        (root / "evidence/SHA256SUMS").write_text(checksum, encoding="utf-8")
        fixtures = root / "fixtures"
        fixtures.mkdir()
        fixture = fixtures / "input.json"
        fixture.write_text("fixture\n", encoding="utf-8")
        (fixtures / "SHA256SUMS").write_text(
            f"{digest(fixture)}  fixtures/input.json\n", encoding="utf-8"
        )
        experiments = root / "experiments"
        experiments.mkdir()
        write_json(
            experiments / "TEST-0001.json",
            {"evidence_file_hashes": {"evidence/input.json": digest(evidence)}},
        )
        run = root / "results/TEST-0001/run-001"
        run.mkdir(parents=True)
        artifact = run / "report.json"
        artifact.write_text("report\n", encoding="utf-8")
        write_json(
            run / "manifest.json",
            {"evidence_file_hashes": {"evidence/input.json": digest(evidence)}},
        )
        write_json(
            run / "completion.json",
            {
                "run_id": "results/TEST-0001/run-001",
                "status": "completed",
                "artifact_sha256": {"report.json": digest(artifact)},
            },
        )
        registry = experiments / "registry.jsonl"
        registry.write_text(
            json.dumps(
                {
                    "run_id": "results/TEST-0001/run-001",
                    "status": "completed",
                    "completion_sha256": digest(run / "completion.json"),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return root, evidence, artifact

    def test_valid_repository_reports_all_hash_classes(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, _ = self.fixture(directory)
            self.assertEqual(
                audit(root),
                {
                    "status": "verified",
                    "completion_records": 1,
                    "artifact_hashes": 1,
                    "registered_input_hashes": 2,
                    "experiment_specifications": 1,
                    "checksum_inventory_entries": 2,
                    "registry_completion_events": 1,
                    "scope": (
                        "Byte integrity and registry linkage only; historical implementation hashes "
                        "describe the checkout used for each run and are not compared with the current checkout."
                    ),
                },
            )

    def test_artifact_tampering_names_the_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, artifact = self.fixture(directory)
            artifact.write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "report.json"):
                audit(root)

    def test_frozen_input_tampering_names_the_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root, evidence, _ = self.fixture(directory)
            evidence.write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "evidence/input.json"):
                audit(root)

    def test_registry_tampering_names_the_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, _ = self.fixture(directory)
            completion = root / "results/TEST-0001/run-001/completion.json"
            value = json.loads(completion.read_text())
            value["extra"] = True
            write_json(completion, value)
            with self.assertRaisesRegex(ValueError, "completion.json"):
                audit(root)

    def test_paths_cannot_escape_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, _ = self.fixture(directory)
            manifest = root / "results/TEST-0001/run-001/manifest.json"
            write_json(manifest, {"evidence_file_hashes": {"../outside": "unused"}})
            with self.assertRaisesRegex(ValueError, "escapes repository"):
                audit(root)

    def test_declared_versioned_relocation_preserves_historical_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root, evidence, _ = self.fixture(directory)
            original = evidence.read_bytes()
            relocated = root / "evidence/input-v2.json"
            relocated.write_bytes(original)
            evidence.write_text("older generation\n", encoding="utf-8")
            (root / "evidence/SHA256SUMS").write_text(
                f"{digest(evidence)}  evidence/input.json\n", encoding="utf-8"
            )
            from audit_repository import VERSIONED_EVIDENCE_RELOCATIONS

            key = ("evidence/input.json", hashlib.sha256(original).hexdigest())
            VERSIONED_EVIDENCE_RELOCATIONS[key] = "evidence/input-v2.json"
            try:
                report = audit(root)
                self.assertEqual(report["status"], "verified")
            finally:
                del VERSIONED_EVIDENCE_RELOCATIONS[key]


if __name__ == "__main__":
    unittest.main()
