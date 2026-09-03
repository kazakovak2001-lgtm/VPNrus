"""B31 - static content assertions over this repository's own TRACKED
deployment artifacts (nginx edge templates, env-file templates) for the
first real ingress deployment (Stockholm INGRESS -> Germany EXIT). These
are plain text files, not importable Python, so this module reads them
directly and asserts on their content - the same "prove the tracked
artifact is actually correct" discipline every other gateway test applies
to code, applied here to config/deployment templates instead. Never starts
nginx, never touches a real host - purely static.
"""
import os
import re
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

_EDGE_DIR = os.path.join(_GATEWAY_DIR, "edge")
_CONFIG_DIR = os.path.join(_GATEWAY_DIR, "config")

_NGINX_GERMANY = os.path.join(_EDGE_DIR, "nginx-pocvpn.conf")
_NGINX_STOCKHOLM = os.path.join(_EDGE_DIR, "nginx-pocvpn-stockholm.conf")
_API_ENV_EXAMPLE = os.path.join(_CONFIG_DIR, "api.env.example")
_INGRESS_ENV_EXAMPLE = os.path.join(_CONFIG_DIR, "ingress.env.example")

# B31 - a secret VALUE is anything that looks like real key/uuid/token
# material - never something this suite should find inside a tracked,
# committed template (every real field in these templates is a blank
# default or an explicit REPLACE_WITH_* placeholder, by this repository's
# own long-standing convention - see api.env.example's/ingress.env.example's
# own "contains NO real secrets" header).
_SUSPICIOUS_SECRET_REGEX = re.compile(
    r"(?i)(BEGIN [A-Z ]*PRIVATE KEY|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


class GermanyNginxExposesRelayHealthTests(unittest.TestCase):
    def setUp(self):
        self.conf = _read(_NGINX_GERMANY)

    def test_exact_relay_health_location_present(self):
        self.assertIn("location = /v1/relay-health {", self.conf)

    def test_relay_health_is_get_only(self):
        block = self.conf.split("location = /v1/relay-health {", 1)[1].split("\n    }", 1)[0]
        self.assertIn("limit_except GET", block)
        self.assertNotIn("limit_except POST", block)

    def test_relay_health_proxies_to_loopback_8443_never_publicly(self):
        block = self.conf.split("location = /v1/relay-health {", 1)[1].split("\n    }", 1)[0]
        self.assertIn("proxy_pass http://127.0.0.1:8443;", block)

    def test_no_wildcard_prefix_location_added(self):
        # Every location in this file must be an EXACT match (`location =`)
        # or the two pre-existing structural ones (ACME webroot prefix,
        # catch-all `/`) - never a new prefix location that could shadow an
        # unrelated path.
        locations = re.findall(r"location\s+(=?\s*\S+)\s*\{", self.conf)
        for loc in locations:
            if loc in ("/", "/.well-known/acme-challenge/"):
                continue
            self.assertTrue(loc.startswith("="), f"unexpected non-exact location: {loc!r}")

    def test_existing_production_routes_still_present(self):
        for route in ("/v1/peers", "/v1/activate", "/v1/xray-profile", "/v1/manifest"):
            self.assertIn(f"location = {route} {{", self.conf)

    def test_backend_8443_never_directly_listened_on_by_nginx(self):
        # nginx must never itself `listen 8443` - only ever proxy_pass TO
        # loopback:8443, which is a completely different exposure (nginx's
        # own `listen` directives stay 80/443 only).
        listens = re.findall(r"^\s*listen\s+([^\s;]+)", self.conf, re.MULTILINE)
        self.assertTrue(all(not port.endswith("8443") for port in listens), listens)

    def test_no_secret_shaped_value_in_tracked_template(self):
        self.assertIsNone(_SUSPICIOUS_SECRET_REGEX.search(self.conf))


class StockholmNginxExposesIngressProfileTests(unittest.TestCase):
    def setUp(self):
        self.conf = _read(_NGINX_STOCKHOLM)

    def test_exact_ingress_profile_location_present(self):
        self.assertIn("location = /v1/ingress-profile {", self.conf)

    def test_ingress_profile_is_post_only(self):
        block = self.conf.split("location = /v1/ingress-profile {", 1)[1].split("\n    }", 1)[0]
        self.assertIn("limit_except POST", block)
        self.assertNotIn("limit_except GET", block)

    def test_ingress_profile_proxies_to_ITS_OWN_loopback_8444_never_the_exit_roles_8443(self):
        # The exact bug this test guards against: pointing the ingress
        # role's own route at the EXISTING exit-role's pocvpn-api.service
        # (8443) instead of the ingress role's SEPARATE process (8444) -
        # that would silently 503 forever (the exit-role process's own
        # ingress_config is always None) rather than actually working.
        block = self.conf.split("location = /v1/ingress-profile {", 1)[1].split("\n    }", 1)[0]
        self.assertIn("proxy_pass http://127.0.0.1:8444;", block)
        self.assertNotIn("127.0.0.1:8443", block)

    def test_no_wildcard_prefix_location_added(self):
        locations = re.findall(r"location\s+(=?\s*\S+)\s*\{", self.conf)
        for loc in locations:
            if loc in ("/", "/.well-known/acme-challenge/"):
                continue
            self.assertTrue(loc.startswith("="), f"unexpected non-exact location: {loc!r}")

    def test_existing_production_routes_still_present(self):
        for route in ("/v1/peers", "/v1/activate", "/v1/xray-profile", "/v1/manifest"):
            self.assertIn(f"location = {route} {{", self.conf)

    def test_backend_ports_never_directly_listened_on_by_nginx(self):
        listens = re.findall(r"^\s*listen\s+([^\s;]+)", self.conf, re.MULTILINE)
        self.assertTrue(all(not (port.endswith("8443") or port.endswith("8444")) for port in listens), listens)

    def test_reality_transport_never_proxied_through_nginx(self):
        # The client-facing REALITY inbound (port 2093) is a raw Xray TCP
        # listener, never an nginx-fronted route - no `listen`/`proxy_pass`
        # DIRECTIVE in this file may reference it (an explanatory comment
        # mentioning the port, as this file's own header does, is fine).
        directives = re.findall(r"^\s*(?:listen|proxy_pass)\s+.*$", self.conf, re.MULTILINE)
        for directive in directives:
            self.assertNotIn("2093", directive, directive)

    def test_no_secret_shaped_value_in_tracked_template(self):
        self.assertIsNone(_SUSPICIOUS_SECRET_REGEX.search(self.conf))


class IngressEnvExampleTests(unittest.TestCase):
    def setUp(self):
        self.env = _read(_INGRESS_ENV_EXAMPLE)

    def _value_of(self, key):
        match = re.search(rf"^{re.escape(key)}=(\S*)", self.env, re.MULTILINE)
        self.assertIsNotNone(match, f"{key} not found in ingress.env.example")
        return match.group(1)

    def test_reality_listener_port_is_the_approved_2093(self):
        self.assertEqual("2093", self._value_of("NOVA_INGRESS_SERVER_PORT"))

    def test_api_port_differs_from_the_existing_exit_roles_8443(self):
        api_port = self._value_of("POCVPN_API_API_PORT")
        self.assertNotEqual("8443", api_port)
        self.assertEqual("8444", api_port)

    def test_reality_port_and_api_port_do_not_collide_with_each_other_or_with_known_exit_ports(self):
        used_ports = {
            self._value_of("NOVA_INGRESS_SERVER_PORT"),
            self._value_of("POCVPN_API_API_PORT"),
            "2053",  # existing Stockholm EXIT-role REALITY
            "2083",  # existing Stockholm EXIT-role TLS_TCP
            "8443",  # existing Stockholm EXIT-role pocvpn-api.service
        }
        # 5 distinct values expected - any collision above would have
        # collapsed this set to fewer than 5 entries.
        self.assertEqual(5, len(used_ports), used_ports)

    def test_no_secret_shaped_value_in_tracked_template(self):
        self.assertIsNone(_SUSPICIOUS_SECRET_REGEX.search(self.env))

    def test_every_secret_field_is_a_file_path_placeholder_never_inline(self):
        # Task D/H's own "no REALITY private key / upstream uuid / probe
        # secret inline in this file, ever" - re-asserted here against the
        # ACTUAL tracked template content, not merely by convention.
        for key in (
            "NOVA_INGRESS_REALITY_PRIVATE_KEY_FILE",
            "NOVA_INGRESS_UPSTREAM_UUID_FILE",
            "NOVA_INGRESS_PROBE_HMAC_SECRET_FILE",
        ):
            value = self._value_of(key)
            self.assertTrue(value.startswith("/"), f"{key}={value!r} is not an absolute file path")


class ApiEnvExampleRelayFieldsTests(unittest.TestCase):
    def setUp(self):
        self.env = _read(_API_ENV_EXAMPLE)

    def test_static_relay_clients_file_field_present_and_blank_by_default(self):
        match = re.search(r"^POCVPN_API_STATIC_RELAY_CLIENTS_FILE=(\S*)$", self.env, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual("", match.group(1))

    def test_relay_probe_hmac_secret_file_field_present_and_blank_by_default(self):
        match = re.search(r"^POCVPN_API_RELAY_PROBE_HMAC_SECRET_FILE=(\S*)$", self.env, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual("", match.group(1))

    def test_relay_fields_documented_as_file_paths_never_inline_secrets(self):
        # Both fields are FILE PATHS per config.py's own AppConfig docs -
        # the template must never show a real-looking value on the right
        # side of either key (blank is correct; anything non-blank here
        # would mean a real value leaked into a tracked file).
        for key in ("POCVPN_API_STATIC_RELAY_CLIENTS_FILE", "POCVPN_API_RELAY_PROBE_HMAC_SECRET_FILE"):
            match = re.search(rf"^{key}=(.*)$", self.env, re.MULTILINE)
            self.assertEqual("", match.group(1).strip())

    def test_no_secret_shaped_value_in_tracked_template(self):
        self.assertIsNone(_SUSPICIOUS_SECRET_REGEX.search(self.env))


if __name__ == "__main__":
    unittest.main()
