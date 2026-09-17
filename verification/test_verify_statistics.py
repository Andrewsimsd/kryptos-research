"""Statistical conventions, sampling, uncertainty and corruption checks."""

from copy import deepcopy
import unittest

from verify_statistics import (ROOT, Model, SplitMix64, compare, minor, read_json,
                               reference, summarize, validate_request, wilson)


class StatisticsTests(unittest.TestCase):
    def setUp(self):
        self.model = Model(read_json(ROOT / "evidence/k4.json"))

    def test_published_observed_values_and_explicit_adjacent_pairs(self):
        self.assertEqual(self.model.measure(self.model.original), [11, 21, 47, 10, 6])
        self.assertEqual([i for i in range(96) if self.model.original[i] == self.model.original[i + 1]], [18, 25, 32, 42, 46, 67])

    def test_triples_count_one_repeated_type_but_overlapping_doubles(self):
        self.assertEqual(self.model.measure([0] * 97)[2:], [0, 13, 96])
        self.assertEqual(self.model.measure([0] * 97)[0], 1)

    def test_minor_distance_boundaries(self):
        self.assertEqual([minor(0, 25), minor(0, 13), minor(4, 4)], [1, 13, 0])

    def test_generator_fixed_vector(self):
        rng = SplitMix64(0)
        self.assertEqual([rng.next() for _ in range(3)], [0xe220a8397b1dcdaf, 0x6e789e6aa1b965f4, 0x06c45d188009454f])

    def test_shuffle_preserves_multiset_including_short_inputs(self):
        rng = SplitMix64(2**64 - 1)
        for original in [[], [1], [0, 1], self.model.original]:
            self.assertEqual(sorted(rng.shuffle(original)), sorted(original))

    def test_wilson_boundary_and_known_half_interval(self):
        self.assertEqual(wilson(0, 10)[0], 0)
        self.assertGreater(wilson(0, 10)[1], 0)
        self.assertEqual(wilson(10, 10)[1], 1)
        self.assertAlmostEqual(wilson(50, 100)[0], 0.4038315303659956)
        for r, n in [(-1, 10), (11, 10), (0, 0), (True, 10)]:
            with self.assertRaises(ValueError): wilson(r, n)

    def test_invalid_requests_rejected(self):
        for key, value in [("schema_version", 2), ("seed", -1), ("seed", 2**64), ("samples", 0), ("samples", 10_000_001), ("samples", True)]:
            request = {"schema_version": 1, "samples": 10, "seed": 0, key: value}
            with self.assertRaises(ValueError): validate_request(request)

    def test_exact_reports_detect_tampering_and_boolean_counts(self):
        request = {"schema_version": 1, "samples": 20, "seed": 0}
        report, texts, values = reference(request, self.model)
        self.assertEqual((len(texts), len(values)), (21, 21))
        compare(report, reference(request, self.model)[0])
        for field, value in [("rng_draws", 1), ("rng_final_state", 0), ("observed", [True] * 5)]:
            altered = deepcopy(report); altered[field] = value
            with self.assertRaises(ValueError): compare(altered, report)
        altered = deepcopy(report); altered["histograms"][0][0] += 1
        with self.assertRaises(ValueError): compare(altered, report)

    def test_inclusive_tails_plus_one_and_correction(self):
        report = {"request": {"samples": 10}, "observed": [1] * 5, "histograms": [[2, 3, 5]] * 5}
        rows = summarize(report)
        self.assertEqual([row["exceedances"] for row in rows], [8, 5, 5, 8, 8])
        self.assertEqual(rows[1]["estimate_plus_one"], 6 / 11)
        self.assertEqual(rows[1]["bonferroni_five"], 1)
        report["observed"] = [3, -1, -1, 3, 3]
        self.assertTrue(all(row["estimate_plus_one"] > 0 for row in summarize(report)))
        report["histograms"][0] = [9]
        with self.assertRaises(ValueError): summarize(report)


if __name__ == "__main__":
    unittest.main()
