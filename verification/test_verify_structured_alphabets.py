"""Independent structured-alphabet enumeration and tamper checks."""

from copy import deepcopy
import unittest

from verify_structured_alphabets import (
    ROOT, AZ, CONSTRUCTIONS, candidate_identity, equation_trace, read_json,
    rotate_left, verify,
)
from verify_primers import expand


class StructuredAlphabetCoreTests(unittest.TestCase):
    def test_left_rotation_direction_and_wrap(self):
        self.assertEqual(rotate_left(AZ, 27), "BCDEFGHIJKLMNOPQRSTUVWXYZA")

    def test_planted_trace_matches_all_equations(self):
        trace = equation_trace(AZ, AZ, "BCD", {0: "A", 1: "A", 2: "A"}, [1, 2, 3])
        self.assertTrue(all(row["observed_residue"] == row["required_residue"] for row in trace))

    def test_common_rotation_preserves_residues(self):
        known = {0: "A", 1: "Z"}
        first = equation_trace(AZ, AZ[::-1], "ZA", known, [3, 7])
        second = equation_trace(rotate_left(AZ, 9), rotate_left(AZ[::-1], 9), "ZA", known, [3, 7])
        self.assertEqual(
            [row["observed_residue"] for row in first],
            [row["observed_residue"] for row in second],
        )


RUN = ROOT / "results/STRUCTURED-ALPHABETS-0001/run-002"


@unittest.skipUnless(RUN.exists(), "registered production artifact has not been created")
class PreservedStructuredAlphabetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = read_json(RUN / "structured-alphabets.json")
        cls.request = read_json(ROOT / "fixtures/structured-alphabets-request.json")
        cls.evidence = read_json(ROOT / "evidence/k4.json")
        cls.primers = read_json(ROOT / "results/PRIMERS-0001/run-002/primers.json")

    def test_complete_registered_domain_is_independently_verified(self):
        result = verify(self.report, self.request, self.evidence, self.primers)
        self.assertEqual((result["models_checked"], result["equations_checked"]), (16_224, 389_376))

    def test_rejection_and_aggregate_tampering_are_detected(self):
        for kind in ("id", "primer", "rotation", "match", "position", "index", "key", "histogram", "coverage"):
            altered = deepcopy(self.report)
            record = altered["rejections"][0]
            if kind == "id": record["id"] += "x"
            elif kind == "primer": record["primer"] = "00001"
            elif kind == "rotation": record["ciphertext_rotation"] = 25
            elif kind == "match": record["match_count"] += 1
            elif kind == "position": record["first_mismatch"]["position"] += 1
            elif kind == "index": record["first_mismatch"]["plaintext_index"] ^= 1
            elif kind == "key": record["first_mismatch"]["key"] ^= 1
            elif kind == "histogram": altered["match_histogram"]["0"] += 1
            else: altered["models_evaluated"] -= 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                verify(altered, self.request, self.evidence, self.primers)

    def test_request_domain_tampering_is_detected(self):
        for field in ("primers", "constructions", "alphabet_pairs", "ciphertext_rotations", "key_offset"):
            altered = deepcopy(self.request)
            if field == "key_offset": altered[field] = 1
            else: altered[field] = altered[field][:-1]
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify(self.report, altered, self.evidence, self.primers)

    def test_boolean_numeric_type_confusion_is_rejected(self):
        cases = []
        altered_request = deepcopy(self.request)
        altered_request["ciphertext_rotations"][1] = True
        cases.append(("request rotation", self.report, altered_request))

        for name, path, value in [
            ("rejection rotation", ("rejections", 0, "ciphertext_rotation"), False),
            ("match count", ("rejections", 0, "match_count"), False),
            ("position", ("rejections", 0, "first_mismatch", "position"), True),
            ("plaintext index", ("rejections", 0, "first_mismatch", "plaintext_index"), False),
            ("ciphertext index", ("rejections", 0, "first_mismatch", "ciphertext_index"), True),
            ("key", ("rejections", 0, "first_mismatch", "key"), True),
            ("observed residue", ("rejections", 0, "first_mismatch", "observed_residue"), True),
            ("histogram count", ("match_histogram", "0"), True),
            ("model aggregate", ("models_evaluated",), True),
            ("equation aggregate", ("equation_evaluations",), True),
        ]:
            altered = deepcopy(self.report)
            target = altered
            for component in path[:-1]: target = target[component]
            target[path[-1]] = value
            cases.append((name, altered, self.request))

        altered = deepcopy(self.report)
        altered["rejections"][1248]["first_mismatch"]["required_residue"] = False
        cases.append(("required residue", altered, self.request))
        for name, report, request in cases:
            with self.subTest(field=name), self.assertRaises(ValueError):
                verify(report, request, self.evidence, self.primers)


class SyntheticStructuredAlphabetBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.request = read_json(ROOT / "fixtures/structured-alphabets-request.json")
        cls.primers = read_json(ROOT / "results/PRIMERS-0001/run-002/primers.json")
        cls.evidence = deepcopy(read_json(ROOT / "evidence/k4.json"))
        cls.evidence["evidence_id"] = "STRUCTURED-ALPHABETS-PLANTED"
        key = expand(cls.request["primers"][0])[:97]
        ciphertext = ["X"] * 97
        for anchor in cls.evidence["anchors"]:
            for offset, letter in enumerate(anchor["plaintext"]):
                position = anchor["start"] + offset
                ciphertext[position] = AZ[(AZ.index(letter) + key[position]) % 26]
            anchor["ciphertext"] = "".join(ciphertext[anchor["start"]:anchor["end"]])
        ciphertext = "".join(ciphertext)
        lines = [ciphertext[:4], ciphertext[4:35], ciphertext[35:66], ciphertext[66:]]
        cls.evidence["ciphertext"] = ciphertext
        cls.evidence["physical_lines"] = lines
        for transcription in cls.evidence["transcriptions"]:
            transcription["ciphertext"] = ciphertext
            transcription["physical_lines"] = lines
        cls.report = cls.reference_report(key)

    @classmethod
    def reference_report(cls, planted_key):
        known = {
            position: letter
            for anchor in cls.evidence["anchors"]
            for position, letter in enumerate(anchor["plaintext"], anchor["start"])
        }
        orders = {entry["id"]: entry["order"] for entry in CONSTRUCTIONS}
        rejections, survivors, histogram = [], [], {}
        for primer in cls.request["primers"]:
            key = planted_key if primer == cls.request["primers"][0] else expand(primer)[:97]
            for pair in cls.request["alphabet_pairs"]:
                for rotation in cls.request["ciphertext_rotations"]:
                    identity = candidate_identity(primer, pair, rotation)
                    plain = orders[pair["plaintext"]]
                    cipher = rotate_left(orders[pair["ciphertext"]], rotation)
                    equations = equation_trace(plain, cipher, cls.evidence["ciphertext"], known, key)
                    mismatches = [row for row in equations if row["observed_residue"] != row["required_residue"]]
                    matches = 24 - len(mismatches)
                    histogram[str(matches)] = histogram.get(str(matches), 0) + 1
                    if mismatches:
                        rejections.append({**identity, "match_count": matches, "first_mismatch": mismatches[0]})
                    else:
                        survivors.append({
                            **identity,
                            "expanded_key": "".join(map(str, key)),
                            "plaintext_alphabet": plain,
                            "ciphertext_alphabet": cipher,
                            "equations": equations,
                        })
        return {
            "schema_version": 1,
            "evidence_id": cls.evidence["evidence_id"],
            "models_evaluated": 16_224,
            "equation_evaluations": 389_376,
            "match_histogram": dict(sorted(histogram.items(), key=lambda item: int(item[0]))),
            "rejections": rejections,
            "survivors": survivors,
        }

    def test_planted_full_batch_survivor_is_independently_accepted(self):
        result = verify(self.report, self.request, self.evidence, self.primers)
        survivor = next(
            record for record in self.report["survivors"]
            if record["id"] == "10319:az-forward:az-forward:00"
        )
        self.assertGreater(result["survivors"], 0)
        self.assertEqual((len(survivor["expanded_key"]), len(survivor["equations"])), (97, 24))

    def test_boolean_survivor_equation_is_rejected(self):
        altered = deepcopy(self.report)
        altered["survivors"][0]["equations"][0]["required_residue"] = True
        with self.assertRaises(ValueError):
            verify(altered, self.request, self.evidence, self.primers)


if __name__ == "__main__":
    unittest.main()
