"""Independent graph, certificate soundness, and tampered artifact checks."""

from copy import deepcopy
import unittest

from verify_baseline import read_json
from verify_primers import (ROOT, adjacency, edges_from_evidence, expand, graph_consistent,
                            pair_conditions, parse_upstream, validate_relation, verify)


def edges(plain, cipher):
    return [(i, "p" + p, "c" + c) for i, (p, c) in enumerate(zip(plain, cipher))]


def relation(equal, coefficients):
    return {"equal_zero": equal, "terms": [{"position": i, "coefficient": c} for i, c in coefficients]}


class PrimerReferenceTests(unittest.TestCase):
    def test_aca_prefix_and_leading_zero_primer(self):
        self.assertEqual(expand("23452")[:10], [2, 3, 4, 5, 2, 5, 7, 9, 7, 7])
        self.assertEqual(expand("00001")[:10], [0, 0, 0, 0, 1, 0, 0, 0, 1, 1])

    def test_invalid_primers_are_rejected(self):
        for primer in ["", "1234", "123456", "1234a", "１２３４５"]:
            with self.subTest(primer=primer), self.assertRaises(ValueError):
                expand(primer)

    def test_cycles_use_letter_modulus_twenty_six(self):
        graph = adjacency(edges("AABB", "CDCD"))
        self.assertTrue(graph_consistent(graph, [25, 0, 0, 1]))
        self.assertFalse(graph_consistent(graph, [0, 1, 2, 4]))

    def test_local_injectivity_and_independent_component_offsets(self):
        self.assertFalse(graph_consistent(adjacency(edges("AB", "CC")), [0, 0]))
        self.assertTrue(graph_consistent(adjacency(edges("AB", "CD")), [0, 0]))
        self.assertTrue(graph_consistent({}, []))

    def test_planted_permutations_pass(self):
        for multiplier in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
            for shift in [0, 1, 13, 25]:
                key = expand(f"{shift % 10}{multiplier % 10}091")[:97]
                plain = "".join(chr(65 + i % 26) for i in range(97))
                cipher = "".join(chr(90 - (i * multiplier + shift + digit) % 26) for i, digit in enumerate(key))
                self.assertTrue(graph_consistent(adjacency(edges(plain, cipher)), key))

    def test_simple_pairs_distinguish_equal_and_distinct_letters(self):
        self.assertEqual(pair_conditions(edges("AAB", "CCD")), [(0, 1, True)])

    def test_certificate_algebra_accepts_cycles_and_alphabet_differences(self):
        observed = edges("AABB", "CDCD")
        validate_relation(relation(True, [(0, 1), (1, -1), (2, -1), (3, 1)]), observed)
        validate_relation(relation(False, [(0, 1), (1, -1)]), observed)

    def test_certificate_rejects_wrong_sign_unrelated_letters_and_noncanonical_terms(self):
        observed = edges("AABB", "CDCD")
        for item in [relation(True, [(0, 1), (1, 1), (2, -1), (3, 1)]),
                     relation(False, [(0, 1), (3, -1)]),
                     relation(False, [(1, -1), (0, 1)]),
                     relation(False, [(0, 0)]), relation(False, []),
                     relation(False, [(True, 1)]), relation(False, [(0, True)])]:
            with self.subTest(item=item), self.assertRaises(ValueError):
                validate_relation(item, observed)

    def test_upstream_parser_rejects_bad_expansion_and_duplicate_rows(self):
        key = expand("00001")
        row = f"1 {len(set(key[:97]))} {''.join(map(str, key))}\n"
        self.assertEqual(parse_upstream(row)[0]["primer"], "00001")
        for text in [row + row, "1 2 00001", "0 1 " + "0" * 98]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_upstream(text)


class PreservedPrimerArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Frozen first run is a regression fixture; never rewritten by tests.
        run = ROOT / "results/PRIMERS-0001/run-001"
        cls.report = read_json(run / "primers.json")
        cls.upstream = (run / "upstream.txt").read_text()
        cls.edges = edges_from_evidence(ROOT / "evidence/k4.json")

    def test_complete_coverage_and_all_certificates_match_reference(self):
        result = verify(self.report, self.edges, self.upstream)
        self.assertEqual((result["simple_survivors"], result["graph_survivors"],
                          result["exact_upstream_match"], result["rejections_verified"]), (1040, 39, True, 99960))

    def test_missing_duplicate_wrong_group_and_false_survivor_are_detected(self):
        for kind in ["missing", "duplicate", "wrong_group", "false_survivor"]:
            altered = deepcopy(self.report)
            groups = altered["rejected_by_relation"]
            if kind == "missing":
                groups[0].pop()
            elif kind == "duplicate":
                groups[0].append(groups[0][-1])
            elif kind == "wrong_group":
                groups[1].append(groups[0].pop())
                groups[1].sort()
            else:
                number = groups[0].pop(0)
                key = expand(f"{number:05d}")
                altered["survivors"].append({"primer": f"{number:05d}", "expanded_key": "".join(map(str, key)), "distinct_digits": len(set(key[:97]))})
                altered["survivors"].sort(key=lambda record: record["primer"])
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                verify(altered, self.edges, self.upstream)

    def test_counts_evidence_types_and_relation_tampering_are_detected(self):
        for field, value in [("examined", 100000), ("simple_survivors", 1039),
                             ("schema_version", True), ("evidence_id", "OTHER")]:
            altered = deepcopy(self.report)
            altered[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify(altered, self.edges, self.upstream)
        altered = deepcopy(self.report)
        altered["constraints"]["relations"][0]["terms"][0]["coefficient"] = 2
        with self.assertRaises(ValueError):
            verify(altered, self.edges, self.upstream)

    def test_upstream_difference_is_reported_without_concealing_valid_certificates(self):
        result = verify(self.report, self.edges, "\n".join(self.upstream.splitlines()[1:]))
        self.assertEqual((result["exact_upstream_match"], result["only_graph"]), (False, ["10319"]))


if __name__ == "__main__":
    unittest.main()
