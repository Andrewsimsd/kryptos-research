"""Independent keyword-domain, calibration, survivor and tamper tests."""

from copy import deepcopy
import unittest

from verify_keyword_alphabets import (
    ROOT, AZ, aca_transposed, base_orders, calibration_reference, decode, decrypt, encrypt,
    deduplicate, encode, keyword_fill, k4_reference, read_json,
    signature, source_identifiers, validate_evidence, validate_request, verify,
)


class KeywordConstructionTests(unittest.TestCase):
    def test_six_forward_orders_are_exact(self):
        expected = [
            "KRYPTOSABCDEFGHIJLMNQUVWXZ", "KAHUOFNPDLXRBIVSGQTEMZYCJW",
            "PALIMSETBCDFGHJKNOQRUVWXYZ", "ACOZEJWIFRLDQMGUPBNYSHVTKX",
            "ABSCIDEFGHJKLMNOPQRTUVWXYZ", "ADJOUZBEKPVCGMRXIHNTYSFLQW",
        ]
        actual = []
        for keyword in ("KRYPTOS", "PALIMPSEST", "ABSCISSA"):
            actual.extend((keyword_fill(keyword), aca_transposed(keyword)))
        self.assertEqual(actual, expected)

    def test_deduplication_ragged_columns_and_invalid_keywords(self):
        self.assertEqual(deduplicate("ABSCISSA"), "ABSCI")
        self.assertEqual(aca_transposed("ENIGMA"), "AJRXEBKSYGFPVIDOUMHQWNCLTZ")
        for keyword in ("", "lower", "A?"):
            with self.subTest(keyword=keyword), self.assertRaises(ValueError):
                aca_transposed(keyword)

    def test_candidate_index_boundaries(self):
        for index in (0, 25, 26, 146_015):
            self.assertEqual(encode(*decode(index)), index)
        for index in (-1, 146_016, True):
                with self.subTest(index=index), self.assertRaises(ValueError): decode(index)

    def test_inverse_roundtrip_boundaries_and_wrong_transform(self):
        plain = keyword_fill("KRYPTOS")
        cipher = aca_transposed("ABSCISSA")[25:] + aca_transposed("ABSCISSA")[:25]
        for length in (0, 1, 97):
            plaintext = (AZ * 4)[:length]
            key = [index % 10 for index in range(length)]
            ciphertext = encrypt(plaintext, key, plain, cipher)
            self.assertEqual(decrypt(ciphertext, key, plain, cipher), plaintext)
        plaintext, key = "A" * 97, [0] * 97
        ciphertext = encrypt(plaintext, key, plain, cipher)
        self.assertNotEqual(decrypt(ciphertext, [1] * 97, plain, cipher), plaintext)
        tampered = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        self.assertNotEqual(decrypt(tampered, key, plain, cipher), plaintext)
        with self.assertRaises(ValueError): decrypt("A", [], plain, cipher)


RUN = ROOT / "results/KEYWORD-ALPHABETS-0002/run-001"


@unittest.skipUnless(RUN.exists(), "registered production artifact has not been created")
class PreservedKeywordAlphabetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.calibration = read_json(RUN / "calibration.json")
        cls.report = read_json(RUN / "keyword-alphabets.json")
        cls.request = read_json(ROOT / "fixtures/keyword-alphabets-request.json")
        cls.evidence = read_json(ROOT / "evidence/k4.json")
        cls.primers = read_json(ROOT / "results/PRIMERS-0001/run-002/primers.json")
        cls.reference = read_json(ROOT / "evidence/reference-material.json")
        cls.sources = source_identifiers(ROOT / "evidence/sources.jsonl")

    def check(self, calibration=None, report=None, request=None):
        return verify(calibration or self.calibration, report or self.report, request or self.request,
                      self.evidence, self.primers, self.reference, self.sources)

    def test_complete_calibration_and_k4_search_are_verified(self):
        result = self.check()
        self.assertEqual((result["candidate_count"], result["equations_checked"], result["survivors"]),
                         (146_016, 3_504_384, 0))
        self.assertEqual(result["operation_counts"]["total"], 7_050_672)

    def test_compact_k4_and_calibration_tampering_are_rejected(self):
        for kind in ("count", "mismatch", "histogram", "encoding", "calibration-set", "calibration-bool"):
            calibration, report = deepcopy(self.calibration), deepcopy(self.report)
            if kind == "count": report["match_counts"][0] += 1
            elif kind == "mismatch": report["first_mismatch_crib_indices"][0] += 1
            elif kind == "histogram": report["match_histogram"]["0"] += 1
            elif kind == "encoding": report["candidate_index_encoding"] += "x"
            elif kind == "calibration-set": calibration["cases"][0]["recovered_candidate_indices"] = []
            else: calibration["cases"][0]["case_index"] = False
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.check(calibration, report)

    def test_request_and_provenance_tampering_are_rejected(self):
        for field in ("keyword", "source", "rotation", "seed"):
            request = deepcopy(self.request)
            if field == "keyword": request["keywords"][0]["keyword"] = "ENIGMA"
            elif field == "source": request["keywords"][1]["source_id"] = "S210"
            elif field == "rotation": request["ciphertext_rotations"][1] = True
            else: request["calibration"]["seed"] = True
            with self.subTest(field=field), self.assertRaises(ValueError): self.check(request=request)


class SyntheticKeywordSurvivorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.request = read_json(ROOT / "fixtures/keyword-alphabets-request.json")
        cls.primers = read_json(ROOT / "results/PRIMERS-0001/run-002/primers.json")
        cls.reference = read_json(ROOT / "evidence/reference-material.json")
        cls.sources = source_identifiers(ROOT / "evidence/sources.jsonl")
        cls.evidence = deepcopy(read_json(ROOT / "evidence/k4.json"))
        cls.evidence["evidence_id"] = "KEYWORD-ALPHABETS-PLANTED"
        orders = validate_request(cls.request, cls.primers, cls.reference, cls.sources)
        known = validate_evidence(cls.evidence)
        calibration, keys = calibration_reference(cls.request, cls.evidence, known, orders)
        predicted = {position: letter for (position, _), letter in zip(sorted(known.items()),
                     signature(known, keys[0], orders[0][1], orders[0][1]))}
        ciphertext = list(cls.evidence["ciphertext"])
        for position, letter in predicted.items(): ciphertext[position] = letter
        ciphertext = "".join(ciphertext)
        cls.evidence["ciphertext"] = ciphertext
        cls.evidence["physical_lines"] = [ciphertext[:4], ciphertext[4:35], ciphertext[35:66], ciphertext[66:]]
        for anchor in cls.evidence["anchors"]:
            anchor["ciphertext"] = ciphertext[anchor["start"]:anchor["end"]]
        for transcription in cls.evidence["transcriptions"]:
            transcription["ciphertext"] = ciphertext
            transcription["physical_lines"] = cls.evidence["physical_lines"]
        known = validate_evidence(cls.evidence)
        cls.calibration = calibration
        cls.report, _ = k4_reference(cls.request, cls.evidence, known, orders, keys)

    def test_full_survivor_trace_is_accepted(self):
        result = verify(self.calibration, self.report, self.request, self.evidence,
                        self.primers, self.reference, self.sources)
        survivor = next(entry for entry in self.report["survivors"] if entry["candidate_index"] == 0)
        self.assertGreater(result["survivors"], 0)
        self.assertEqual((len(survivor["expanded_key"]), len(survivor["equations"])), (97, 24))

    def test_survivor_trace_tampering_is_rejected(self):
        report = deepcopy(self.report)
        report["survivors"][0]["equations"][0]["required_residue"] ^= 1
        with self.assertRaises(ValueError):
            verify(self.calibration, report, self.request, self.evidence,
                   self.primers, self.reference, self.sources)


if __name__ == "__main__": unittest.main()
