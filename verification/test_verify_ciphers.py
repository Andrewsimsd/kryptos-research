"""Known answers, pinned randomness, and tampered-trace regression checks."""

from copy import deepcopy
import unittest

from verify_baseline import VerificationError, read_json
from verify_ciphers import (AZ, ROOT, XorShift32, fixture_requests, gromark_parameters,
                            reference_case, reference_stage, route_sources,
                            synthetic_requests, verify_batch, verify_known_answers)


def repeating(equation="vigenere", keyword="LEMON"):
    return {"family": "repeating", "plaintext_alphabet": AZ, "ciphertext_alphabet": AZ,
            "key_alphabet": AZ, "keyword": keyword, "equation": equation, "offset": 0}


class ReferenceCipherTests(unittest.TestCase):
    def test_classic_vigenere_known_answer(self):
        self.assertEqual(reference_stage("ATTACKATDAWN", repeating(), "encrypt")[1]["text"], "LXFOPVEFRNHR")

    def test_manual_beaufort_and_variant_answers(self):
        for equation, expected in [("beaufort", "DL"), ("variant_beaufort", "XP")]:
            with self.subTest(equation=equation):
                self.assertEqual(reference_stage("ZU", repeating(equation, "CF"), "encrypt")[1]["text"], expected)

    def test_aca_gromark_alphabet_and_numeric_stream(self):
        alphabet, digits = gromark_parameters("ENIGMA", [2, 3, 4, 5, 2], 10)
        self.assertEqual((alphabet, digits), ("AJRXEBKSYGFPVIDOUMHQWNCLTZ", [2,3,4,5,2,5,7,9,7,7]))

    def test_manual_ragged_map(self):
        self.assertEqual(route_sources(7, [2, 0, 1], False), [2,5,0,3,6,1,4])

    def test_published_fixtures_match_separate_reference_equations(self):
        fixtures = read_json(ROOT / "fixtures/known-answers.json")
        request = fixture_requests(fixtures)
        report = {"schema_version": 1, "cases": [reference_case(c) for c in request["cases"]]}
        self.assertIsNone(verify_known_answers(fixtures, report))

    def test_pinned_generator_sequence(self):
        rng = XorShift32(1)
        self.assertEqual([rng.next() for _ in range(5)], [270369, 67634689, 2647435461, 307599695, 2398689233])

    def test_seed_reproducibility_includes_shuffles_offsets_and_text(self):
        self.assertEqual(synthetic_requests("compound", 10, XorShift32(42)),
                         synthetic_requests("compound", 10, XorShift32(42)))

    def test_zero_and_out_of_range_seeds_are_errors(self):
        for seed in [0, -1, 2**32, True]:
            with self.subTest(seed=seed), self.assertRaises(VerificationError):
                XorShift32(seed)

    def test_invalid_keys_alphabets_primers_and_routes_are_errors(self):
        for invalid in [repeating(keyword=""), repeating(keyword="lower")]:
            with self.assertRaises(VerificationError):
                reference_stage("A", invalid, "encrypt")
        with self.assertRaises(VerificationError):
            gromark_parameters("A", [10, 0, 0, 0, 0], 1)
        for order in [[], [0, 0], [2]]:
            with self.subTest(order=order), self.assertRaises(VerificationError):
                route_sources(3, order, False)


class TamperTests(unittest.TestCase):
    def setUp(self):
        self.request = {"schema_version": 1, "cases": [{"id": "manual", "input": "ATTACKATDAWN",
                         "direction": "encrypt", "stages": [repeating()]}]}
        self.report = {"schema_version": 1, "cases": [reference_case(self.request["cases"][0])]}

    def test_each_numeric_and_position_trace_field_is_checked(self):
        for field, value in [("input_index", 1), ("output_index", 1), ("input", "Z"), ("output", "Z"),
                             ("input_value", False), ("key_value", 0), ("output_value", 0)]:
            report = deepcopy(self.report)
            report["cases"][0]["stages"][0]["trace"][0][field] = value
            with self.subTest(field=field), self.assertRaises(VerificationError):
                verify_batch(self.request, report)

    def test_changed_output_identifier_direction_or_missing_stage_is_rejected(self):
        mutations = [lambda r: r["cases"][0].update(output="A"),
                     lambda r: r["cases"][0].update(id="wrong"),
                     lambda r: r["cases"][0].update(direction="decrypt"),
                     lambda r: r["cases"][0]["stages"].clear(),
                     lambda r: r["cases"][0]["canonical_encryption_stages"].clear()]
        for mutate in mutations:
            report = deepcopy(self.report)
            mutate(report)
            with self.assertRaises(VerificationError):
                verify_batch(self.request, report)


if __name__ == "__main__":
    unittest.main()
