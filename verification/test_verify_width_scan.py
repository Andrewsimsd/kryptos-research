"""Exact ordering, calibrated selection, and corruption checks."""

from copy import deepcopy
import unittest

from verify_width_scan import (ROOT, calibration_tables, compare, counts, empty_histograms,
                               read_json, reference, score_compare, summarize, validate_request, winner)


class WidthScanTests(unittest.TestCase):
    def test_count_conventions_and_boundaries(self):
        self.assertEqual(counts("A" * 97), [1] * 48)
        self.assertEqual((len(empty_histograms()[0]), len(empty_histograms()[-1])), (49, 25))
        self.assertEqual(counts("".join(chr(65 + i % 26) for i in range(97)))[47], 23)

    def test_exact_score_comparison_signs_and_scaled_ties(self):
        for a, b, expected in [((1, 1), (2, 4), 0), ((-1, 1), (-2, 4), 0),
                               ((-2, 1), (-1, 1), -1), ((0, 1), (-1, 1), 1),
                               ((1, 2), (1, 1), -1), ((0, 2), (0, 1), 0)]:
            self.assertEqual(score_compare(a, b), expected)
        self.assertEqual(winner([0] * 48, [[1]] * 48), 0)

    def test_calibration_accounts_for_different_width_distributions(self):
        histograms = [[1, 2, 1]] + [[0, 1, 2, 1]] * 47
        sums, squares, variances, scores, ranks = calibration_tables(histograms, 4)
        self.assertEqual(sums[:2], [4, 8])
        self.assertEqual(score_compare(scores[0][2], scores[1][3]), 0)
        self.assertEqual(ranks[0][2], ranks[1][3])
        with self.assertRaises(ValueError): calibration_tables([[4, 0]] * 48, 4)

    def test_request_domains_and_seeds(self):
        request = {"schema_version": 1, "calibration_samples": 100, "samples": 20, "calibration_seed": 0, "seed": 1}
        validate_request(request)
        for field, value in [("calibration_samples", 1), ("samples", 0), ("samples", 1_000_001),
                             ("seed", 0), ("seed", -1), ("seed", 2**64), ("samples", True)]:
            altered = {**request, field: value}
            with self.assertRaises(ValueError): validate_request(altered)

    def test_complete_reconstruction_detects_tampering_and_maxima_cover_trials(self):
        request = {"schema_version": 1, "calibration_samples": 100, "samples": 20, "calibration_seed": 0, "seed": 1}
        result = reference(read_json(ROOT / "evidence/k4.json"), request)
        self.assertEqual(sum(map(sum, result["maxima_histograms"])), 20)
        self.assertTrue(all(sum(h) == 20 for h in result["evaluation"]["histograms"]))
        summary = summarize(result)
        self.assertTrue(all(row["maximum_adjusted_tail"]["exceedances"] >= row["local_tail"]["exceedances"] for row in summary["widths"]))
        for field, value in [("selected_width", 0), ("global_exceedances", True), ("observed", [0] * 48)]:
            altered = deepcopy(result); altered[field] = value
            with self.assertRaises(ValueError): compare(altered, result)
        altered = deepcopy(result); altered["maxima_histograms"][0][0] += 1
        with self.assertRaises(ValueError): compare(altered, result)


if __name__ == "__main__":
    unittest.main()
