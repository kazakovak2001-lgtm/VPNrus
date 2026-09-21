import copy
import unittest

from record_validator import RESTRICTIONS, TRANSPORTS, canonical_json, validate


def valid_record():
    return {
        "schemaVersion": 1, "observationId": "b54-cz-wifi-001", "evidenceClass": "FIELD_MEASURED",
        "claimScope": "REAL_NETWORK", "result": "PASS_END_TO_END", "timestampUtc": "2026-09-21T10:00:00Z",
        "build": {"gitCommit": "0123456789abcdef", "versionName": "0.1-field"},
        "device": {"model": "TEST_DEVICE", "androidVersion": "14", "apiLevel": 34, "abi": "arm64-v8a"},
        "network": {"type": "WIFI", "countryCode": "CZ", "operator": "NOT_TESTED", "accessTechnology": "UNKNOWN", "roaming": False, "ipv4Available": True, "ipv6Available": False, "validatedInternet": True, "rawRestrictionClass": "NO_RESTRICTION_OBSERVED", "stabilizedRestrictionClass": "NO_RESTRICTION_OBSERVED"},
        "scenario": {"name": "BASELINE", "restrictedContext": "NONE"},
        "path": {"gatewaySelectionMode": "MANUAL_MANAGED", "routingMode": "FULL_VPN", "gatewayEndpointId": "frankfurt", "transport": "AMNEZIA_WG"},
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

    def test_simulation_cannot_claim_pass_end_to_end(self):
        r = valid_record(); r["evidenceClass"] = "SIMULATED"; r.pop("claimScope")
        self.assertRejected(r, "PASS_END_TO_END real-network claim requires FIELD_MEASURED evidence")

    def test_russia_requires_real_context(self):
        r = valid_record(); r["scenario"]["restrictedContext"] = "RUSSIA_FIELD"; self.assertRejected(r, "RUSSIA_FIELD")

    def test_observations_stay_separate(self):
        one, two = valid_record(), copy.deepcopy(valid_record()); two["observationId"] = "b54-cz-wifi-002"
        self.assertNotEqual(canonical_json(one), canonical_json(two))

    def test_serialization_is_deterministic(self):
        r = valid_record(); self.assertEqual(canonical_json(r), canonical_json(dict(reversed(list(r.items())))))

    def test_unknown_and_not_tested_are_explicit(self):
        r = valid_record(); r["network"]["accessTechnology"] = "UNKNOWN"; r["proof"]["serverCorrelation"] = "NOT_TESTED"
        self.assertEqual([], validate(r))

    def test_end_to_end_requires_data_plane(self):
        r = valid_record(); r["proof"].update(dnsRoundTrip=False, tcpRoundTrip=False, udpRoundTrip=False)
        self.assertRejected(r, "data-plane")

    # 1. every real RestrictionClass value accepted
    def test_all_restriction_classes_accepted(self):
        for value in RESTRICTIONS:
            r = valid_record(); r["network"]["rawRestrictionClass"] = value; r["network"]["stabilizedRestrictionClass"] = value
            self.assertNotIn("invalid network.rawRestrictionClass", " ".join(validate(r)), value)
            self.assertNotIn("invalid network.stabilizedRestrictionClass", " ".join(validate(r)), value)

    # 2. obsolete invented restriction names rejected
    def test_obsolete_restriction_names_rejected(self):
        for obsolete in ("OPEN", "UDP_RESTRICTED", "TCP_ONLY", "HARD_WHITELIST_SUSPECTED"):
            r = valid_record(); r["network"]["rawRestrictionClass"] = obsolete
            self.assertRejected(r, "invalid network.rawRestrictionClass")

    # 3. TLS_TCP accepted
    def test_tls_tcp_transport_accepted(self):
        r = valid_record(); r["path"]["transport"] = "TLS_TCP"
        self.assertNotIn("invalid path.transport", " ".join(validate(r)))

    # 4. XRAY_XHTTP accepted
    def test_xray_xhttp_transport_accepted(self):
        r = valid_record(); r["path"]["transport"] = "XRAY_XHTTP"
        self.assertNotIn("invalid path.transport", " ".join(validate(r)))

    # 5. XRAY_CDN_XHTTP rejected
    def test_xray_cdn_xhttp_rejected(self):
        r = valid_record(); r["path"]["transport"] = "XRAY_CDN_XHTTP"; self.assertRejected(r, "invalid path.transport")

    # 6. current real transport enum parity
    def test_transport_enum_parity(self):
        self.assertEqual(TRANSPORTS, {"AMNEZIA_WG", "XRAY_REALITY", "QUIC", "TLS_TCP", "XRAY_XHTTP", "SHADOWSOCKS_2022"})

    # 7. DNS-only cannot produce PASS_END_TO_END (covered above by test_end_to_end_requires_data_plane too)
    def test_dns_only_cannot_pass_end_to_end(self):
        r = valid_record(); r["proof"].update(dnsRoundTrip=True, tcpRoundTrip=False, udpRoundTrip=False)
        self.assertRejected(r, "DNS alone is not sufficient")

    # 8. TCP application proof can satisfy data-plane requirement
    def test_tcp_application_proof_satisfies_data_plane(self):
        r = valid_record(); r["proof"].update(dnsRoundTrip=False, tcpRoundTrip=True, udpRoundTrip=False)
        self.assertEqual([], validate(r))

    # 9. UDP application proof can satisfy it where valid
    def test_udp_application_proof_satisfies_data_plane(self):
        r = valid_record(); r["proof"].update(dnsRoundTrip=False, tcpRoundTrip=False, udpRoundTrip=True)
        self.assertEqual([], validate(r))

    # 10. exit mismatch cannot pass
    def test_exit_mismatch_cannot_pass(self):
        r = valid_record(); r["proof"]["exitProof"] = "MISMATCHED"; self.assertRejected(r, "exit mismatch")

    # 11. simulated result cannot claim field evidence (see also test_simulation_cannot_claim_field/pass)
    def test_simulated_cannot_claim_field_evidence(self):
        r = valid_record(); r["evidenceClass"] = "SIMULATED"
        self.assertRejected(r, "FIELD_MEASURED")

    # 12. POSSIBLE_HARD_WHITELIST does not itself prove a hard-whitelist field context
    def test_possible_hard_whitelist_does_not_confirm_russia_field(self):
        r = valid_record()
        r["network"]["rawRestrictionClass"] = "POSSIBLE_HARD_WHITELIST"
        r["network"]["stabilizedRestrictionClass"] = "POSSIBLE_HARD_WHITELIST"
        r["evidenceClass"] = "SIMULATED"; r.pop("claimScope")
        r["scenario"]["restrictedContext"] = "RUSSIA_FIELD"
        self.assertRejected(r, "RUSSIA_FIELD requires FIELD_MEASURED RU evidence with a real operator")

    # 13. pending Hysteria cannot claim production field validation
    def test_pending_hysteria_cannot_claim_production_field_validation(self):
        r = valid_record()
        r["path"].pop("transport"); r["path"]["pendingTransportKind"] = "HYSTERIA2"
        r["evidenceClass"] = "LAB_MEASURED"; r.pop("claimScope"); r["result"] = "NOT_TESTED"
        self.assertEqual([], validate(r))
        field_claim = copy.deepcopy(r); field_claim["evidenceClass"] = "FIELD_MEASURED"
        self.assertRejected(field_claim, "never FIELD_MEASURED")
        pass_claim = copy.deepcopy(r); pass_claim["result"] = "PASS_END_TO_END"
        self.assertRejected(pass_claim, "cannot claim production field validation")

    def test_pending_transport_and_real_transport_are_mutually_exclusive(self):
        r = valid_record(); r["path"]["pendingTransportKind"] = "HYSTERIA2"
        self.assertRejected(r, "mutually exclusive")

    # 14. deterministic serialization remains stable (see test_serialization_is_deterministic)

    # 15. secret-shaped metadata remains rejected
    def test_secret_shaped_value_rejected(self):
        r = valid_record(); r["limitations"] = ["password=do-not-commit"]; self.assertRejected(r, "repository-unsafe")

    def test_invalid_gateway_selection_mode_rejected(self):
        r = valid_record(); r["path"]["gatewaySelectionMode"] = "FORCED"; self.assertRejected(r, "invalid path.gatewaySelectionMode")

    def test_invalid_routing_mode_rejected(self):
        r = valid_record(); r["path"]["routingMode"] = "FULL_TUNNEL"; self.assertRejected(r, "invalid path.routingMode")


if __name__ == "__main__": unittest.main()
