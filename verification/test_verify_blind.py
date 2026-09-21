"""Boundary and adversarial checks for the synthetic blind recovery path."""

import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
from blind_attack import attack, canonical_id, encrypt  # noqa: E402
from run_blind import ROOT, make_cases  # noqa: E402
from run_blind_v2 import HashRng, apply_final_wall_cap, require_within_wall_cap  # noqa: E402
from verify_blind import regenerate_v2, verify, verify_registration  # noqa: E402


class BlindAttackTests(unittest.TestCase):
    def test_planted_reverse_reflect_model_survives(self):
        plaintext = "EASTNORTHEAST"
        case = {"id": "manual", "ciphertext": encrypt(plaintext, "reverse", "reflect", "BZ"),
                "clues": [{"position": i, "letter": p} for i, p in enumerate(plaintext)], "budget": 8}
        result = attack(case)
        self.assertEqual(result["status"], "complete")
        self.assertIn(canonical_id("reverse", "reflect", "BZ"),
                      [row["model_id"] for row in result["survivors"]])

    def test_variant_sign_and_constant_period_canonicalization(self):
        self.assertEqual(canonical_id("identity", "add", "CC"), "identity:add:1:C")
        self.assertEqual(encrypt("ABC", "identity", "add", "C"), "CDE")

    def test_empty_and_unconstrained_inputs_are_unknown(self):
        for cipher in ("", "A", "AB"):
            with self.subTest(cipher=cipher):
                result = attack({"id": "empty", "ciphertext": cipher, "clues": [], "budget": 8})
                self.assertEqual(result["status"], "unknown")

    def test_same_duplicate_crib_is_accepted_conflict_rejected(self):
        base = {"id": "dup", "ciphertext": "BC", "clues": [{"position": 0, "letter": "A"}], "budget": 8}
        repeated = {**base, "clues": base["clues"] * 2}
        self.assertEqual(attack(base)["survivors"], attack(repeated)["survivors"])
        repeated["clues"] = base["clues"] + [{"position": 0, "letter": "Z"}]
        with self.assertRaises(ValueError):
            attack(repeated)

    def test_invalid_inputs_and_budget_are_explicit(self):
        for change in ({"ciphertext": "a"}, {"clues": [{"position": 2, "letter": "A"}]},
                       {"budget": -1}, {"budget": True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                attack({"id": "invalid", "ciphertext": "AB", "clues": [], "budget": 8} | change)
        limited = attack({"id": "limited", "ciphertext": "A", "clues": [], "budget": 0})
        self.assertEqual((limited["status"], limited["checks"]), ("unknown", 0))
        almost_complete = attack({"id": "limited", "ciphertext": "A", "clues": [], "budget": 7})
        self.assertEqual((almost_complete["status"], almost_complete["checks"]), ("unknown", 7))

    def test_final_wall_time_boundary(self):
        self.assertEqual(require_within_wall_cap(10, 5, clock=lambda: 15), 5)
        with self.assertRaises(Exception) as captured:
            require_within_wall_cap(10, 5, clock=lambda: 15.001)
        self.assertEqual(captured.exception.__class__.__name__, "TimeoutExpired")
        completed = {"status": "completed", "exit_status": 0, "targets_pass": True,
                     "artifact_sha256": {"manifest.json": "0" * 64}}
        timed = apply_final_wall_cap(completed, 10, 5, clock=lambda: 15.001)
        self.assertEqual((timed["status"], timed["exit_status"]), ("timeout", 1))
        self.assertNotIn("targets_pass", timed)

    def test_frozen_manifest_rejects_target_seed_and_cohort_tampering(self):
        spec = json.loads((ROOT / "experiments/BLIND-0002.json").read_text())
        old_hashes = json.loads((ROOT / "results/BLIND-0002/run-002/manifest.json").read_text())["implementation_sha256"]
        manifest = {**spec, "status": "running", "run_id": "results/BLIND-0002/test",
                    "started_at": "test", "environment": {},
                    "implementation_sha256": old_hashes}
        verify_registration(manifest)
        for field, value in (("targets", {**spec["targets"], "top_one_minimum": 0}),
                             ("seed_commitment_sha256", "0" * 64),
                             ("positive_random", 0)):
            altered = {**manifest, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_registration(altered)
        altered_hash = {**manifest, "implementation_sha256": {"verification/verify_blind.py": "0" * 64}}
        with self.assertRaises(ValueError):
            verify_registration(altered_hash)

    def test_critical_implementation_path_cannot_be_removed(self):
        manifest = json.loads((ROOT / "results/BLIND-0003/run-001/manifest.json").read_text())
        verify_registration(manifest)
        reduced = dict(manifest["implementation_sha256"])
        reduced.pop("experiments/blind_attack.py")
        with self.assertRaises(ValueError):
            verify_registration({**manifest, "implementation_sha256": reduced})

    def test_preserved_historical_runs_remain_auditable(self):
        for run in ("BLIND-0002/run-002", "BLIND-0003/run-001"):
            with self.subTest(run=run):
                self.assertEqual(verify(ROOT / "results" / run)["status"], "verified")

    def test_controller_is_deterministic_and_public_omits_truth(self):
        spec = json.loads((ROOT / "experiments/BLIND-0001.json").read_text())
        first = make_cases(spec)
        self.assertEqual(first, make_cases(spec))
        self.assertEqual(len(first[0]), 300)
        self.assertTrue(all(set(case) == {"id", "ciphertext", "clues", "budget"} for case in first[0]))
        self.assertTrue(all(case["status"] == "complete" for case in map(attack, first[0])))

    def test_independent_verifier_catches_fabricated_candidate(self):
        spec = json.loads((ROOT / "experiments/BLIND-0001.json").read_text())
        public, private = make_cases(spec)
        answers = [attack(case) for case in public]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "manifest.json").write_text(json.dumps(spec))
            for name, data in (("public-cases", public), ("controller-private", private),
                               ("attacker-output", answers)):
                (directory / f"{name}.jsonl").write_text("".join(json.dumps(row) + "\n" for row in data))
            with mock.patch("verify_blind.verify_registration"):
                self.assertEqual(verify(directory)["status"], "verified")
            answers[0]["survivors"].append({"model_id": "fake", "plaintext": "A" * 97})
            (directory / "attacker-output.jsonl").write_text("".join(json.dumps(row) + "\n" for row in answers))
            with self.assertRaises(ValueError):
                verify(directory)
            answers[0]["survivors"].pop()
            answers[0]["status"] = "unknown"
            answers[0]["checks"] = 7
            (directory / "attacker-output.jsonl").write_text("".join(json.dumps(row) + "\n" for row in answers))
            self.assertFalse(verify(directory)["targets_pass"])

    def test_hidden_seed_regeneration_and_truth_tampering(self):
        spec = json.loads((ROOT / "experiments/BLIND-0002.json").read_text())
        seed = bytes(range(32))
        spec["seed_commitment_sha256"] = hashlib.sha256(seed).hexdigest()
        public, private = make_cases(spec, HashRng(seed))
        self.assertEqual((public, private), regenerate_v2(spec, seed))
        answers = [attack(case) for case in public]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "manifest.json").write_text(json.dumps(spec))
            (directory / "seed-reveal.json").write_text(json.dumps({"seed_hex": seed.hex(),
                "commitment_sha256": spec["seed_commitment_sha256"], "revealed_after_attacker_exit": True}))

            def save(name, data):
                (directory / f"{name}.jsonl").write_text("".join(json.dumps(row) + "\n" for row in data))

            save("public-cases", public)
            save("controller-private", private)
            save("attacker-output", answers)
            with mock.patch("verify_blind.verify_registration"):
                self.assertEqual(verify(directory)["status"], "verified")
            for field, changed in (("kind", "tamper"), ("plaintext", "Z" * 97),
                                   ("true_model_id", "fake")):
                altered = [dict(row) for row in private]
                altered[0][field] = changed
                save("controller-private", altered)
                with mock.patch("verify_blind.verify_registration"), self.subTest(field=field), self.assertRaises(ValueError):
                    verify(directory)
            save("controller-private", private)
            altered_public = [dict(row) for row in public]
            altered_public[0]["ciphertext"] = "Z" + public[0]["ciphertext"][1:]
            save("public-cases", altered_public)
            with mock.patch("verify_blind.verify_registration"), self.assertRaises(ValueError):
                verify(directory)


if __name__ == "__main__":
    unittest.main()
