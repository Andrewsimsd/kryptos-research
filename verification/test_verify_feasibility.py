"""Independent component packing and tampered-witness regression checks."""

from copy import deepcopy
import unittest

from verify_feasibility import (ROOT, check_witness, components, read_json,
                                search_components, verify)
from verify_primers import expand


def edge_list(plain, cipher):
    return [(i, p, c) for i, (p, c) in enumerate(zip(plain, cipher))]


class FeasibilityCoreTests(unittest.TestCase):
    def test_cycles_and_same_alphabet_collisions_are_local_contradictions(self):
        for plain, cipher, key in [("AA", "BB", [0, 1]), ("AB", "CC", [0, 0]),
                                   ("AA", "BC", [0, 0]), ("AABB", "CDCD", [0, 1, 2, 4])]:
            self.assertIsNone(components(edge_list(plain, cipher), key))

    def test_independent_components_are_packed_on_both_sides(self):
        parts = components(edge_list("AB", "BC"), [1, 1])
        status, offsets, states = search_components(parts, 100)
        self.assertEqual((status, offsets, states), ("feasible", {0: 0, 1: 1}, 3))

    def test_global_impossibility_and_budget_are_distinct(self):
        plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        cipher = "A" * 13 + "B" * 13
        key = [(-2 * i) % 26 for i in range(13)] + [(-i) % 26 for i in range(13)]
        parts = components(edge_list(plain, cipher), key)
        self.assertEqual(search_components(parts, 100)[0], "infeasible")
        self.assertEqual(search_components(parts, 1)[0], "budget_exhausted")

    def test_planted_affine_alphabets_are_feasible(self):
        for multiplier in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
            plain = "".join(chr(65 + i % 26) for i in range(97))
            key = [i % 10 for i in range(97)]
            cipher = "".join(chr(90 - ((i % 26) * multiplier + 25 + k) % 26) for i, k in enumerate(key))
            self.assertEqual(search_components(components(edge_list(plain, cipher), key), 10000)[0], "feasible")


class PreservedFeasibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run = ROOT / "results/FEASIBILITY-0001/run-001"
        cls.report = read_json(run / "feasibility.json")
        cls.request = read_json(ROOT / "fixtures/feasibility-request.json")
        cls.evidence = read_json(ROOT / "evidence/k4.json")
        cls.primers = read_json(ROOT / "results/PRIMERS-0001/run-002/primers.json")

    def test_all_registered_primers_have_independently_verified_witnesses(self):
        result = verify(self.report, self.request, self.evidence, self.primers)
        self.assertEqual((result["primers_checked"], result["feasible"], result["infeasible"], result["unresolved"]), (39, 39, 0, 0))

    def test_alphabet_key_equation_and_component_tampering_are_detected(self):
        paths = [("alphabet",), ("key",), ("equation",), ("component",), ("primer",), ("budget",)]
        for (kind,) in paths:
            altered = deepcopy(self.report)
            record = altered["results"][0]
            if kind == "alphabet":
                alphabet = record["report"]["decision"]["plaintext_alphabet"]
                record["report"]["decision"]["plaintext_alphabet"] = alphabet[1] + alphabet[0] + alphabet[2:]
            elif kind == "key": record["expanded_key"] = "0" + record["expanded_key"][1:]
            elif kind == "equation": record["crib_equations"][0]["key"] ^= 1
            elif kind == "component": record["report"]["components"][0]["plaintext"][0]["index"] ^= 1
            elif kind == "primer": record["primer"] = "00001"
            else: altered["attempt_limit"] -= 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                verify(altered, self.request, self.evidence, self.primers)

    def test_incomplete_and_false_infeasible_records_are_not_accepted_as_proofs(self):
        incomplete = deepcopy(self.report)
        result = incomplete["results"][0]
        result["report"]["decision"] = {"status": "budget_exhausted"}
        result["report"]["attempted_offsets"] = incomplete["attempt_limit"]
        result["crib_equations"] = []
        counts = verify(incomplete, self.request, self.evidence, self.primers)
        self.assertEqual(counts["unresolved"], 1)

        false_proof = deepcopy(self.report)
        result = false_proof["results"][0]
        result["report"]["decision"] = {
            "status": "infeasible",
            "reason": "invented",
        }
        result["report"]["attempted_offsets"] = false_proof["attempt_limit"]
        result["crib_equations"] = []
        with self.assertRaises(ValueError):
            verify(false_proof, self.request, self.evidence, self.primers)

    def test_direct_witness_rejects_nonpermutations(self):
        record = self.report["results"][0]
        decision = deepcopy(record["report"]["decision"])
        decision["plaintext_alphabet"] = "A" * 26
        key = expand(record["primer"])[:97]
        known = {i: p for anchor in self.evidence["anchors"] for i, p in enumerate(anchor["plaintext"], anchor["start"])}
        edges = [(i, p, self.evidence["ciphertext"][i]) for i, p in sorted(known.items())]
        with self.assertRaises(ValueError):
            check_witness(decision, record["report"]["components"], edges, key, record["crib_equations"])


if __name__ == "__main__":
    unittest.main()
