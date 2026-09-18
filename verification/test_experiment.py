"""Regression checks for frozen-input handling in the coordinator."""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "run_baseline", Path(__file__).resolve().parents[1] / "experiments/run_baseline.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
sys.modules["run_baseline"] = runner

v3_spec = importlib.util.spec_from_file_location(
    "run_keyword_alphabets_v3",
    Path(__file__).resolve().parents[1] / "experiments/run_keyword_alphabets_v3.py",
)
v3 = importlib.util.module_from_spec(v3_spec)
v3_spec.loader.exec_module(v3)

from verify_keyword_alphabets import (  # noqa: E402 - dynamic runner import must come first
    ROOT,
    read_json,
    source_identifiers,
    verify,
)
from verify_keyword_calibration import verify_calibration  # noqa: E402


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


class KeywordExecutionAccountingTests(unittest.TestCase):
    def valid_values(self):
        result = {
            "status": "verified",
            "calibration_cases": 144,
            "candidate_count": 146_016,
            "equations_checked": 3_504_384,
            "survivors": 0,
            "best_match_count": 7,
            "best_model_count": 7,
            "retained_cases": 144,
            "plaintext_recovery_cases": 144,
            "reencryption_cases": 144,
            "full_message_recovery_cases": 144,
            "unique_recovery_cases": 98,
            "operation_counts": {
                "signature_equation_evaluations": 3_504_384,
                "planted_encryption_positions": 13_968,
                "planted_decryption_positions": 13_968,
                "planted_reencryption_positions": 13_968,
                "k4_equation_evaluations": 3_504_384,
                "total": 7_050_672,
            },
        }
        gate = {
            "status": "verified",
            "candidate_count": 146_016,
            "calibration_cases": 144,
            "true_model_retained_cases": 144,
            "known_true_model_roundtrip_cases": 144,
            "singleton_recovery_sets": 98,
            "operation_counts": {
                "signature_equation_evaluations": 3_504_384,
                "planted_encryption_positions": 13_968,
                "planted_decryption_positions": 13_968,
                "planted_reencryption_positions": 13_968,
            },
        }
        specification = {
            "execution_operation_accounting": {
                "produced_calibration": 3_546_288,
                "evaluation_internal_calibration_regeneration": 3_546_288,
                "k4_equation_evaluations": 3_504_384,
                "total": 10_596_960,
            },
            "execution_operation_cap": 10_596_960,
        }
        return result, gate, specification

    def test_actual_duplicate_calibration_work_is_counted(self):
        result, gate, specification = self.valid_values()
        self.assertEqual(v3.validate_execution(result, gate, specification)["total"], 10_596_960)

    def test_gate_failure_is_rejected(self):
        result, gate, specification = self.valid_values()
        gate["known_true_model_roundtrip_cases"] = 143
        with self.assertRaisesRegex(RuntimeError, "pre-search"):
            v3.validate_execution(result, gate, specification)

    def test_counter_tampering_is_rejected(self):
        result, gate, specification = self.valid_values()
        result["operation_counts"]["planted_decryption_positions"] -= 1
        with self.assertRaisesRegex(RuntimeError, "operation profile"):
            v3.validate_execution(result, gate, specification)

    def test_operation_cap_is_enforced(self):
        result, gate, specification = self.valid_values()
        specification["execution_operation_cap"] -= 1
        with self.assertRaisesRegex(ValueError, "cap"):
            v3.validate_registered_budget(specification)

    def test_exact_operation_cap_passes_preflight(self):
        _, _, specification = self.valid_values()
        self.assertIsNone(v3.validate_registered_budget(specification))

    def test_legacy_logical_total_tampering_is_rejected(self):
        result, gate, specification = self.valid_values()
        result["operation_counts"]["total"] -= 1
        with self.assertRaisesRegex(RuntimeError, "logical operation"):
            v3.validate_execution(result, gate, specification)

    def test_boolean_operation_count_is_rejected(self):
        result, gate, specification = self.valid_values()
        gate["operation_counts"]["planted_encryption_positions"] = True
        with self.assertRaisesRegex(RuntimeError, "operation profile"):
            v3.validate_execution(result, gate, specification)

    def test_float_operation_count_is_rejected(self):
        result, gate, specification = self.valid_values()
        result["operation_counts"]["planted_encryption_positions"] = 13_968.0
        with self.assertRaisesRegex(RuntimeError, "operation profile"):
            v3.validate_execution(result, gate, specification)

    def test_positive_survivor_is_rejected(self):
        result, gate, specification = self.valid_values()
        result["survivors"] = 1
        with self.assertRaisesRegex(RuntimeError, "coverage"):
            v3.validate_execution(result, gate, specification)

    def test_regressed_best_score_is_rejected(self):
        result, gate, specification = self.valid_values()
        result["best_match_count"] = 8
        with self.assertRaisesRegex(RuntimeError, "coverage"):
            v3.validate_execution(result, gate, specification)

    def test_unverified_stage_status_is_rejected(self):
        result, gate, specification = self.valid_values()
        for target in (result, gate):
            changed = target.copy()
            changed["status"] = "failed"
            with self.subTest(target="post" if target is result else "pre"), self.assertRaisesRegex(
                RuntimeError, "status"
            ):
                v3.validate_execution(
                    changed if target is result else result,
                    changed if target is gate else gate,
                    specification,
                )


class CompletedKeywordV3ArtifactTests(unittest.TestCase):
    def test_every_completed_v3_run_passes_semantic_and_completion_checks(self):
        runs = sorted((ROOT / "results/KEYWORD-ALPHABETS-0003").glob("run-*/completion.json"))
        self.assertGreaterEqual(len(runs), 1)
        request = read_json(ROOT / "fixtures/keyword-alphabets-request.json")
        evidence = read_json(ROOT / "evidence/k4.json")
        primers = read_json(ROOT / "results/PRIMERS-0001/run-002/primers.json")
        reference = read_json(ROOT / "evidence/reference-material.json")
        sources = source_identifiers(ROOT / "evidence/sources.jsonl")
        specification = read_json(ROOT / "experiments/KEYWORD-ALPHABETS-0003.json")
        for completion_path in runs:
            completion = read_json(completion_path)
            if completion["status"] != "completed":
                continue
            run = completion_path.parent
            with self.subTest(run=run.name):
                calibration = read_json(run / "calibration.json")
                result = verify(
                    calibration,
                    read_json(run / "keyword-alphabets.json"),
                    request,
                    evidence,
                    primers,
                    reference,
                    sources,
                )
                gate = verify_calibration(
                    calibration, request, evidence, primers, reference, sources
                )
                primary = v3.validate_execution(result, gate, specification)
                self.assertEqual(completion["exit_status"], 0)
                self.assertEqual(completion["execution_operation_counts"], primary)
                for key, value in completion["counters"].items():
                    self.assertEqual(result[key], value)
                workload = completion.get("workload_accounting")
                if workload is None:
                    self.assertEqual(run.name, "run-001")
                else:
                    self.assertEqual(workload, v3.WORKLOAD_PROFILE)
                    self.assertEqual(
                        workload["combined_keyword_equation_and_position_operations"],
                        21_193_920,
                    )


if __name__ == "__main__":
    unittest.main()
