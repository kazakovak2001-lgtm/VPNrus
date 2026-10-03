"""B57 review fix (HIGH-1 / MEDIUM-1) - gateway self-connect admission scope.

Xray connect confirmation and the relayed-session watchdog dial the
gateway's own /v1/manifest through the gateway's own Xray exit, so nginx
reports the gateway itself as the client. With AppConfig.
gateway_self_addresses configured, those requests use their own scope
instead of one ordinary per-client bucket shared by every user.
"""
import base64
import dataclasses
import os
import re
import sys
import tempfile
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
_REPO_DIR = os.path.abspath(os.path.join(_GATEWAY_DIR, ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import admission
from api import client_identity
from api import config as config_module
from _fixtures import RunningServer, make_app_config, write_fake_manifest_artifact, write_fake_provision_script
from _http import get_manifest

GATEWAY_IP = "203.0.113.1"
USER_IP = "198.51.100.7"
PER_CLIENT_BOOT = admission.PER_CLIENT_LIMITS[admission.CLASS_BOOTSTRAP]
SELF_CAP = admission.SELF_SCOPE_LIMITS[admission.CLASS_BOOTSTRAP]


def nginx(ip, edge="public-443", **extra):
    headers = {"X-Real-IP": ip, "X-Pocvpn-Edge": edge}
    headers.update(extra)
    return headers


class _ServerCase(unittest.TestCase):
    SELF_ADDRESSES = frozenset({client_identity.parse_address(GATEWAY_IP)})

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = make_app_config(
            self._tmp.name, write_fake_provision_script(self._tmp.name),
            manifest_path=write_fake_manifest_artifact(self._tmp.name),
        )
        self.server = RunningServer(dataclasses.replace(base, gateway_self_addresses=self.SELF_ADDRESSES))
        self.addCleanup(self.server.close)

    def manifest(self, headers):
        return get_manifest(self.server.port, extra_headers=headers)[0]


class SelfConnectOverHttpTests(_ServerCase):
    def test_self_connects_beyond_the_user_bucket_still_succeed(self):
        statuses = [self.manifest(nginx(GATEWAY_IP)) for _ in range(PER_CLIENT_BOOT + 5)]
        self.assertEqual([200] * (PER_CLIENT_BOOT + 5), statuses)

    def test_many_self_connects_leave_users_their_bootstrap_budget(self):
        statuses = [self.manifest(nginx(GATEWAY_IP)) for _ in range(SELF_CAP + 5)]
        self.assertEqual([200] * SELF_CAP + [429] * 5, statuses)
        user = [self.manifest(nginx(USER_IP)) for _ in range(PER_CLIENT_BOOT)]
        self.assertEqual([200] * PER_CLIENT_BOOT, user)
        # Only the user's own key exists: the self-connects created none.
        self.assertEqual(1, self.server.srv.admission.per_client_limiters[admission.CLASS_BOOTSTRAP].size())

    def test_self_scope_and_staging_edge_are_separate(self):
        for _ in range(SELF_CAP):
            self.manifest(nginx(GATEWAY_IP))
        self.assertEqual(429, self.manifest(nginx(GATEWAY_IP)))
        self.assertEqual(200, self.manifest(nginx(GATEWAY_IP, edge="cp-loopback")))
        self.assertEqual(200, self.manifest(nginx(USER_IP, edge="cp-loopback")))


class SpoofingTests(_ServerCase):
    def test_a_client_header_cannot_claim_the_self_scope(self):
        # No request header grants the self scope: a public client sending
        # an "X-Pocvpn-Source: gateway-self"-style marker (or a forged edge)
        # stays in its own ordinary per-client bucket.
        forged = nginx(USER_IP, **{"X-Pocvpn-Source": "gateway-self"})
        statuses = [self.manifest(forged) for _ in range(PER_CLIENT_BOOT + 1)]
        self.assertEqual([200] * PER_CLIENT_BOOT + [429], statuses)

    def test_forged_edge_value_does_not_reach_the_self_scope(self):
        forged = nginx(USER_IP, edge="gateway-self")
        statuses = [self.manifest(forged) for _ in range(PER_CLIENT_BOOT + 1)]
        self.assertEqual(429, statuses[-1])

    def test_self_scope_requires_the_exact_server_controlled_address(self):
        statuses = [self.manifest(nginx("203.0.113.2")) for _ in range(PER_CLIENT_BOOT + 1)]
        self.assertEqual(429, statuses[-1])


class UnconfiguredSelfTests(_ServerCase):
    SELF_ADDRESSES = frozenset()

    def test_without_configuration_the_gateway_is_an_ordinary_client(self):
        statuses = [self.manifest(nginx(GATEWAY_IP)) for _ in range(PER_CLIENT_BOOT + 1)]
        self.assertEqual([200] * PER_CLIENT_BOOT + [429], statuses)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        script = os.path.join(self._tmp.name, "provision-peer.sh")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env bash\nexit 0\n")
        self.env = {
            "POCVPN_API_ENDPOINT_HOST": GATEWAY_IP,
            "POCVPN_API_ENDPOINT_PORT": "51820",
            "POCVPN_API_GATEWAY_PUBLIC_KEY": base64.b64encode(b"\x02" * 32).decode("ascii"),
            "POCVPN_API_GATEWAY_TUNNEL_IP": "10.77.0.1",
            "POCVPN_API_TOKEN_STORE_PATH": os.path.join(self._tmp.name, "enrollment-tokens.json"),
            "POCVPN_API_PROVISION_SCRIPT_PATH": script,
            "POCVPN_API_SUBPROCESS_TIMEOUT_SECONDS": "5",
            "POCVPN_API_API_PORT": "8443",
        }

    def load(self, value=None):
        env = dict(self.env)
        if value is not None:
            env["POCVPN_API_GATEWAY_SELF_ADDRESSES"] = value
        return config_module.load_config(env=env)

    def test_default_is_no_self_scope(self):
        self.assertEqual(frozenset(), self.load().gateway_self_addresses)
        # endpoint_host is NOT implicitly a self address.
        self.assertNotIn(client_identity.parse_address(GATEWAY_IP), self.load().gateway_self_addresses)

    def test_parses_and_normalizes_a_list(self):
        cfg = self.load(" 203.0.113.1 , 10.0.0.5,2001:db8::1,::ffff:198.51.100.9 ,")
        self.assertEqual(
            {client_identity.parse_address(a) for a in ("203.0.113.1", "10.0.0.5", "2001:db8::1", "198.51.100.9")},
            set(cfg.gateway_self_addresses),
        )

    def test_rejects_invalid_and_ambiguous_addresses(self):
        for value in ("not-an-ip", "203.0.113.0/24", "127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "fe80::1%eth0"):
            with self.subTest(value=value):
                with self.assertRaises(config_module.ConfigError):
                    self.load(value)


class WatchdogPathFixtureTests(unittest.TestCase):
    """Static source fixture (no device): the relayed-session watchdog and
    the connect confirmation dial /v1/manifest, never /v1/relay-health -
    that is why the self scope is a bootstrap-class scope."""

    SOURCE = os.path.join(
        _REPO_DIR, "android", "app", "src", "main", "java", "net", "pocvpn", "client", "vpn", "xray",
        "XrayCoreController.kt",
    )

    def _function_body(self, text, name):
        start = re.search(rf"private (suspend )?fun {name}\(", text).start()
        nxt = re.search(r"\n    (private |internal |override )?(suspend )?fun ", text[start + 1:])
        return text[start:start + 1 + nxt.start()] if nxt else text[start:]

    def test_watchdog_and_confirmation_use_the_manifest_path(self):
        with open(self.SOURCE, encoding="utf-8") as handle:
            text = handle.read()
        watchdog = self._function_body(text, "startRelayHealthWatchdog")
        self.assertIn('"https://$exitProbeHost/v1/manifest"', watchdog)
        self.assertNotIn("relay-health", watchdog)
        confirm = self._function_body(text, "confirmRemoteConnectivity")
        self.assertIn('"https://$serverHost/v1/manifest"', confirm)
        self.assertIn('"https://${context.exitProbeHost}/v1/manifest"', confirm)
        self.assertNotIn("relay-health", confirm)


class DocumentationTruthTests(unittest.TestCase):
    """MEDIUM-1: no document may claim a guaranteed activation reserve."""

    FILES = (
        os.path.join(_GATEWAY_DIR, "api", "admission.py"),
        os.path.join(_GATEWAY_DIR, "DEPLOYMENT.md"),
        os.path.join(_REPO_DIR, "docs", "ROADMAP.md"),
        os.path.join(_REPO_DIR, "docs", "B57_5E_STAGING_VERIFICATION.md"),
        os.path.join(_REPO_DIR, "PROJECT_ARCHITECTURE.md"),
    )
    FORBIDDEN = (
        "cannot take the activation reserve",
        "can never take the activation",
        "always keeps a reserve",
        "activation reserve of 20",
    )

    def test_no_guaranteed_reserve_claim(self):
        for path in self.FILES:
            with open(path, encoding="utf-8") as handle:
                text = " ".join(handle.read().split()).lower()
            for phrase in self.FORBIDDEN:
                with self.subTest(path=os.path.basename(path), phrase=phrase):
                    self.assertNotIn(phrase, text)

    def test_admission_states_the_real_invariant(self):
        doc = " ".join((admission.__doc__ or "").split())
        self.assertIn("does NOT guarantee activation any reserved number of global requests", doc)
        self.assertIn("not aligned with the global window", doc)


if __name__ == "__main__":
    unittest.main()
