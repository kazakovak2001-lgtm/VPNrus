import copy
import unittest

from record_validator import canonical_json, validate


def valid_record():
    return {
        "schemaVersion": 1, "observationId": "b54-cz-wifi-001", "evidenceClass": "FIELD_MEASURED",
        "claimScope": "REAL_NETWORK", "result": "PASS_END_TO_END", "timestampUtc": "2026-09-21T10:00:00Z",
        "build": {"gitCommit": "0123456789abcdef", "versionName": "0.1-field"},
        "device": {"model": "TEST_DEVICE", "androidVersion": "14", "apiLevel": 34, "abi": "arm64-v8a"},
        "network": {"type": "WIFI", "countryCode": "CZ", "operator": "NOT_TESTED", "accessTechnology": "UNKNOWN", "roaming": False, "ipv4Available": True, "ipv6Available": False, "validatedInternet": True, "rawRestrictionClass": "OPEN", "stabilizedRestrictionClass": "OPEN"},
        "scenario": {"name": "BASELINE", "restrictedContext": "NONE"},
        "path": {"gatewaySelectionMode": "FORCED", "routingMode": "FULL_TUNNEL", "gatewayEndpointId": "frankfurt", "transport": "AMNEZIA_WG"},
        "proof": {"level": "L2_DATA_PLANE", "connectionEstablished": True, "handshakeDurationMillis": 100, "dnsRoundTrip": True, "tcpRoundTrip": True, "udpRoundTrip": False, "exitProof": "MATCHED", "serverCorrelation": "NOT_TESTED", "cleanup": "PASSED"},
        "limitations": ["Fixture only; never a field result."],
    }


class RecordValidatorTest(unittest.TestCase):
    def assertRejected(self, record, phrase): self.assertTrue(any(phrase in e for e in validate(record)), validate(record))
    def test_valid_field_measured(self): self.assertEqual([], validate(valid_record()))
    def test_missing_timestamp(self):
        r = valid_record(); r.pop("timestampUtc"); self.assertRejected(r, "timestampUtc")
    def test_missing_network(self):
        r = valid_record(); r.pop("network"); self.assertRejected(r, "network")
    def test_connection_only_cannot_claim_end_to_end(self):
        r = valid_record(); r["result"] = "PASS_CONNECTION_ONLY"; self.assertRejected(r, "cannot carry")
    def test_simulation_cannot_claim_field(self):
        r = valid_record(); r["evidenceClass"] = "SIMULATED"; self.assertRejected(r, "SIMULATED")
    def test_russia_requires_real_context(self):
        r = valid_record(); r["scenario"]["restrictedContext"] = "RUSSIA_FIELD"; self.assertRejected(r, "RUSSIA_FIELD")
    def test_pending_transport_cannot_claim_production_validation(self):
        r = valid_record(); r["path"]["transport"] = "HYSTERIA2"; self.assertRejected(r, "HYSTERIA2")
    def test_secret_shaped_value_rejected(self):
        r = valid_record(); r["limitations"] = ["password=do-not-commit"]; self.assertRejected(r, "repository-unsafe")
    def test_observations_stay_separate(self):
        one, two = valid_record(), copy.deepcopy(valid_record()); two["observationId"] = "b54-cz-wifi-002"
        self.assertNotEqual(canonical_json(one), canonical_json(two))
    def test_serialization_is_deterministic(self):
        r = valid_record(); self.assertEqual(canonical_json(r), canonical_json(dict(reversed(list(r.items())))))
    def test_unknown_and_not_tested_are_explicit(self):
        r = valid_record(); r["network"]["accessTechnology"] = "UNKNOWN"; r["proof"]["serverCorrelation"] = "NOT_TESTED"
        self.assertEqual([], validate(r))
    def test_end_to_end_requires_data_plane(self):
        r = valid_record(); r["proof"].update(dnsRoundTrip=False, tcpRoundTrip=False, udpRoundTrip=False); self.assertRejected(r, "data-plane")


if __name__ == "__main__": unittest.main()
