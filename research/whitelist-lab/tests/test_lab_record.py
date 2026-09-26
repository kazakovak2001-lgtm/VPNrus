"""B-WL6 - lab record validator tests (python3 -m unittest discover -s research/whitelist-lab/tests)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import lab_record  # noqa: E402


def _record(**overrides):
    base = {
        "operator": "Operator A", "region": "Region 1", "date": "2026-09-25", "networkType": "LTE",
        "transport": "VLESS_REALITY_XHTTP", "endpointType": "DIRECT_FOREIGN", "result": "EARLY_DROP",
        "classification": "POSSIBLE_EARLY_DROP", "confidence": "LOW",
    }
    base.update(overrides)
    return base


class LabRecordTests(unittest.TestCase):
    def test_a_minimal_record_is_valid(self):
        self.assertEqual(lab_record.validate(_record()), [])

    def test_schema_is_closed(self):
        self.assertTrue(lab_record.validate(_record(serverIp="x")))

    def test_every_required_field_is_enforced(self):
        for name in lab_record.REQUIRED:
            record = _record()
            del record[name]
            self.assertTrue(lab_record.validate(record), name)

    def test_results_are_tied_to_a_concrete_date(self):
        self.assertTrue(lab_record.validate(_record(date="last week")))

    def test_classification_vocabulary_never_exceeds_possible_claims(self):
        self.assertTrue(lab_record.validate(_record(classification="WHITELIST_CONFIRMED")))
        self.assertTrue(lab_record.validate(_record(classification="DPI_BLOCKED")))

    def test_high_confidence_requires_reproduction(self):
        self.assertTrue(lab_record.validate(_record(confidence="HIGH")))
        self.assertEqual(lab_record.validate(_record(confidence="HIGH", repetitions=3)), [])

    def test_privacy_rejects_ips_uuids_urls_and_key_blobs(self):
        leaks = (
            "endpoint 203.0.113.9", "fe80:0:0:0:0:0:0:1", "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "see https://example.net/x", "A" * 43,
        )
        for leak in leaks:
            self.assertTrue(lab_record.validate(_record(notes=leak)), leak)

    def test_the_example_file_is_valid(self):
        path = os.path.join(os.path.dirname(__file__), "..", "records", "EXAMPLE.template.json")
        self.assertEqual(lab_record.main([path]), 0)


if __name__ == "__main__":
    unittest.main()
