"""Deterministic synthetic and mutation tests for the independent verifier."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from verify_baseline import (
    VerificationError, derive_baseline, verify_period_witness, verify_report,
    verify_witness, validate_evidence, read_json, verify_ledger,
)


def synthetic_report():
    """Manually specified tiny example exercising all rejection families."""
    positions = [
        {"index_zero_based": 0, "position_one_based": 1, "plaintext": "A", "ciphertext": "A", "vigenere_key_value": 0},
        {"index_zero_based": 1, "position_one_based": 2, "plaintext": "A", "ciphertext": "B", "vigenere_key_value": 1},
        {"index_zero_based": 2, "position_one_based": 3, "plaintext": "B", "ciphertext": "B", "vigenere_key_value": 0},
    ]
    checks = [
        {"family": "pure_transposition", "witness": {"kind": "letter_deficit", "letter": "A", "available": 1, "required": 2, "positions_zero_based": [0, 1]}},
        {"family": "fixed_monoalphabetic_encryption", "witness": {"kind": "mapping_conflict", "direction": "encryption", "first": positions[0], "second": positions[1]}},
        {"family": "fixed_monoalphabetic_decryption", "witness": {"kind": "mapping_conflict", "direction": "decryption", "first": positions[1], "second": positions[2]}},
        {"family": "no_self_encryption", "witness": {"kind": "fixed_point", "position": positions[0]}},
    ]
    for check in checks:
        check.update(status="rejected", assumptions=["Synthetic direct alignment."])
    return {
        "schema_version": 1,
        "evidence_id": "synthetic",
        "ciphertext_length": 3,
        "known_plaintext_count": 3,
        "letter_counts": {letter: {"A": 1, "B": 2}.get(letter, 0) for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
        "ic": {"numerator": 2, "denominator": 6, "value": 1 / 3},
        "positions": positions,
        "checks": checks,
        "vigenere": {
            "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "equation": "c_i = p_i + k_(i mod t) (mod 26)",
            "surviving_periods": [2, 3],
            "periods": [
                {"period": 1, "status": "rejected", "constrained_slots": 1, "unconstrained_slots": 0, "witness": {"kind": "period_conflict", "residue": 0, "first": positions[0], "second": positions[1]}},
                {"period": 2, "status": "necessary_condition_passed", "constrained_slots": 2, "unconstrained_slots": 0, "witness": None},
                {"period": 3, "status": "necessary_condition_passed", "constrained_slots": 3, "unconstrained_slots": 0, "witness": None},
            ],
        },
    }


class BaselineTests(unittest.TestCase):
    def test_manual_three_letter_example(self):
        result = derive_baseline("ABB", {0: "A", 1: "A", 2: "B"})
        self.assertEqual(
            (result["transposition_deficits"], result["encryption_conflicts"],
             result["decryption_conflicts"], result["fixed_points"], result["surviving_periods"]),
            ([{"letter": "A", "required": 2, "available": 1}], [[0, 1]], [[1, 2]], [0, 2], [2, 3]),
        )

    def test_standard_vigenere_example(self):
        result = derive_baseline("LXFOPVEFRNHR", dict(enumerate("ATTACKATDAWN")))
        self.assertEqual(result["surviving_periods"], [5, 10, 12])

    def test_vigenere_modular_subtraction_wraps(self):
        result = derive_baseline("A", {0: "Z"})
        self.assertEqual(result["positions"][0]["vigenere_key_value"], 1)

    def test_no_anchors_leave_all_slots_unconstrained(self):
        result = derive_baseline("ABC", {})
        self.assertEqual(
            [(p["compatible"], p["constrained_slots"], p["unconstrained_slots"]) for p in result["periods"]],
            [(True, 0, 1), (True, 0, 2), (True, 0, 3)],
        )

    def test_exact_ic_for_repeated_letters(self):
        self.assertEqual(derive_baseline("AABB", {})["ic"], {"numerator": 4, "denominator": 12, "value": 1 / 3})

    def test_single_symbol_ic_is_undefined(self):
        self.assertEqual(derive_baseline("A", {})["ic"], {"numerator": 0, "denominator": 0, "value": None})

    def test_invalid_core_inputs_are_rejected(self):
        for cipher, known in (("", {}), ("a", {}), ("Å", {}), ("AB", {2: "A"}),
                              ("AB", {-1: "A"}), ("AB", {True: "A"}), ("AB", {0: "AA"}),
                              ("AB", {0: "a"}), ("AB", [])):
            with self.subTest(cipher=cipher, known=known), self.assertRaises(VerificationError):
                derive_baseline(cipher, known)


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.ciphertext = "ABB"
        self.known = {0: "A", 1: "A", 2: "B"}
        self.evidence = {"evidence_id": "synthetic", "ciphertext": self.ciphertext}
        self.derived = derive_baseline(self.ciphertext, self.known)
        self.report = synthetic_report()

    def check_report(self, report):
        verify_report(report, self.evidence, self.known, self.derived)

    def test_manual_report_is_valid(self):
        self.assertIsNone(self.check_report(self.report))

    def test_each_original_family_certificate_is_valid(self):
        for check in self.report["checks"]:
            with self.subTest(family=check["family"]):
                self.assertIsNone(verify_witness(check["family"], check["witness"], self.ciphertext, self.known))

    def test_inflated_transposition_deficit_is_rejected(self):
        witness = self.report["checks"][0]["witness"]
        witness["required"] += 1
        with self.assertRaisesRegex(VerificationError, "required multiplicity"):
            self.check_report(self.report)

    def test_false_transposition_deficit_is_rejected(self):
        witness = {"kind": "letter_deficit", "letter": "B", "available": 2, "required": 1, "positions_zero_based": [2]}
        with self.assertRaisesRegex(VerificationError, "does not reject"):
            verify_witness("pure_transposition", witness, self.ciphertext, self.known)

    def test_mapping_witness_with_wrong_direction_is_rejected(self):
        self.report["checks"][1]["witness"]["direction"] = "decryption"
        with self.assertRaisesRegex(VerificationError, "direction"):
            self.check_report(self.report)

    def test_mapping_witness_without_conflicting_outputs_is_rejected(self):
        witness = self.report["checks"][1]["witness"]
        witness["second"] = deepcopy(witness["first"])
        with self.assertRaisesRegex(VerificationError, "conflicting images"):
            self.check_report(self.report)

    def test_false_fixed_point_is_rejected(self):
        self.report["checks"][3]["witness"]["position"] = self.report["positions"][1]
        with self.assertRaisesRegex(VerificationError, "not a fixed point"):
            self.check_report(self.report)

    def test_out_of_range_certificate_position_is_rejected(self):
        witness = deepcopy(self.report["checks"][3]["witness"])
        witness["position"]["index_zero_based"] = 3
        with self.assertRaisesRegex(VerificationError, "not anchored"):
            verify_witness("no_self_encryption", witness, self.ciphertext, self.known)

    def test_corrupted_redundant_position_fields_are_rejected(self):
        for field, value in (("position_one_based", 2), ("plaintext", "Z"),
                             ("ciphertext", "Z"), ("vigenere_key_value", 1)):
            witness = deepcopy(self.report["checks"][3]["witness"])
            witness["position"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(VerificationError, "does not match"):
                verify_witness("no_self_encryption", witness, self.ciphertext, self.known)

    def test_forged_period_conflict_is_rejected(self):
        witness = deepcopy(self.report["vigenere"]["periods"][0]["witness"])
        witness["second"] = self.report["positions"][2]
        with self.assertRaisesRegex(VerificationError, "shifts do not conflict"):
            verify_period_witness(1, witness, self.ciphertext, self.known)

    def test_period_witness_with_different_residues_is_rejected(self):
        witness = self.report["vigenere"]["periods"][0]["witness"]
        with self.assertRaisesRegex(VerificationError, "claimed residue"):
            verify_period_witness(2, witness, self.ciphertext, self.known)

    def test_invalid_period_is_rejected(self):
        for period in (0, -1, True):
            with self.subTest(period=period), self.assertRaises(VerificationError):
                verify_period_witness(period, {}, self.ciphertext, self.known)

    def test_missing_period_is_rejected(self):
        self.report["vigenere"]["periods"].pop()
        with self.assertRaisesRegex(VerificationError, "period coverage"):
            self.check_report(self.report)

    def test_false_period_survivor_is_rejected(self):
        self.report["vigenere"]["surviving_periods"].insert(0, 1)
        with self.assertRaisesRegex(VerificationError, "surviving periods"):
            self.check_report(self.report)

    def test_mutated_aggregate_fields_are_rejected(self):
        mutations = [
            lambda r: r.update(ciphertext_length=4),
            lambda r: r.update(known_plaintext_count=2),
            lambda r: r["letter_counts"].update(A=0),
            lambda r: r["ic"].update(numerator=3),
            lambda r: r["ic"].update(denominator=3),
            lambda r: r["ic"].update(value=float("nan")),
            lambda r: r["positions"].pop(),
            lambda r: r["checks"][0].update(status="necessary_condition_passed"),
            lambda r: r["checks"][0].update(witness=None),
            lambda r: r["checks"].pop(),
            lambda r: r["vigenere"]["periods"][1].update(unconstrained_slots=1),
            lambda r: r["vigenere"]["periods"][1].update(witness={}),
        ]
        for offset, mutate in enumerate(mutations):
            report = deepcopy(self.report)
            mutate(report)
            with self.subTest(mutation=offset), self.assertRaises(VerificationError):
                self.check_report(report)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.evidence = read_json(self.root / "evidence/k4.json")

    def test_baseline_has_24_distinct_anchored_positions(self):
        self.assertEqual(sorted(validate_evidence(self.evidence)), list(range(21, 34)) + list(range(63, 74)))

    def test_transcription_disagreement_is_rejected(self):
        self.evidence["transcriptions"][1]["ciphertext"] = "A" * 97
        with self.assertRaisesRegex(VerificationError, "transcription disagrees"):
            validate_evidence(self.evidence)

    def test_invalid_range_types_and_boundaries_are_rejected(self):
        for field, value in [("start", True), ("start", -1), ("start", 97), ("end", 21), ("end", 10 ** 100)]:
            evidence = deepcopy(self.evidence)
            evidence["anchors"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(VerificationError):
                validate_evidence(evidence)

    def test_punctuation_and_unicode_are_not_normalized(self):
        for suffix in ["?", " ", "é", "a"]:
            self.evidence["ciphertext"] = "A" * 96 + suffix
            with self.subTest(suffix=suffix), self.assertRaises(VerificationError):
                validate_evidence(self.evidence)

    def test_overlapping_anchors_are_rejected(self):
        anchor = deepcopy(self.evidence["anchors"][0])
        anchor["id"] = "duplicate-range"
        self.evidence["anchors"].append(anchor)
        with self.assertRaisesRegex(VerificationError, "overlapping"):
            validate_evidence(self.evidence)

    def test_json_loader_rejects_duplicate_fields_and_nonfinite_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for text in ['{"a": 1, "a": 2}', '{"a": NaN}', '{"a": Infinity}', '{']:
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(ValueError):
                    read_json(path)

    def test_all_project_source_and_claim_references_resolve(self):
        counts = verify_ledger(self.root / "evidence/sources.jsonl", self.evidence, self.root)
        self.assertGreater(counts["sources"], 0)

    def test_missing_source_is_detected(self):
        self.evidence["source_ids"].append("MISSING")
        with self.assertRaisesRegex(VerificationError, "unresolved source ID"):
            verify_ledger(self.root / "evidence/sources.jsonl", self.evidence, self.root)

    def test_duplicate_source_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "sources.jsonl"
            line = (self.root / "evidence/sources.jsonl").read_text().splitlines()[0]
            ledger.write_text(line + "\n" + line + "\n")
            with self.assertRaisesRegex(VerificationError, "duplicate or invalid source ID"):
                verify_ledger(ledger, self.evidence, self.root)

    def test_changed_local_source_hash_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "snapshot.txt").write_text("changed")
            record = json.loads((self.root / "evidence/sources.jsonl").read_text().splitlines()[0])
            record.update(content_hash="0" * 64, local_path="snapshot.txt")
            ledger = root / "sources.jsonl"
            ledger.write_text(json.dumps(record) + "\n")
            with self.assertRaisesRegex(VerificationError, "source hash differs"):
                verify_ledger(ledger, self.evidence, root)


if __name__ == "__main__":
    unittest.main()
