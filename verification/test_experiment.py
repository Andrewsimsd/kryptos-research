"""Regression checks for frozen-input handling in the coordinator."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "run_baseline", Path(__file__).resolve().parents[1] / "experiments/run_baseline.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class FrozenInputTests(unittest.TestCase):
    def test_changed_evidence_requires_new_experiment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            evidence.write_text("original")
            specification = {"evidence_file_hashes": {"evidence.json": runner.digest(evidence)}}
            runner.verify_inputs(specification, root)
            evidence.write_text("changed")
            with self.assertRaisesRegex(ValueError, "register a new experiment"):
                runner.verify_inputs(specification, root)

    def test_existing_artifact_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            runner.write_json(path, {"original": True})
            with self.assertRaises(FileExistsError):
                runner.write_json(path, {"replacement": True})

    def test_evidence_paths_cannot_escape_project(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "escapes project"):
                runner.verify_inputs({"evidence_file_hashes": {"../outside": "unused"}}, Path(directory))


if __name__ == "__main__":
    unittest.main()
