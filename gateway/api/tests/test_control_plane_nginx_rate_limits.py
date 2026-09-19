"""B56-3 - static safety contract for Level 1 edge rate/concurrency limiting
on the two UNAUTHENTICATED pre-activation routes, /v1/activate and
/v1/manifest, across BOTH production control-plane vhosts (Germany/Oracle,
Stockholm/AWS). Purely static: never starts nginx, never touches a real
host - same discipline as test_edge_deployment_config.py and
test_cdn_origin_nginx_template.py.

This is Level 1 abuse damping only (docs/RESILIENT_BOOTSTRAP_ACTIVATION_ARCHITECTURE.md
section 22) - NOT volumetric/network DDoS protection, NOT a censorship or
hard-whitelist bypass, and independent of B56-2's imported-manifest path.
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

_NGINX_GERMANY = os.path.join(_EDGE_DIR, "nginx-pocvpn.conf")
_NGINX_STOCKHOLM = os.path.join(_EDGE_DIR, "nginx-pocvpn-stockholm.conf")
_NGINX_BOOTSTRAP = os.path.join(_EDGE_DIR, "nginx-pocvpn-bootstrap.conf")
_NGINX_CDN_ORIGIN = os.path.join(_EDGE_DIR, "nginx-pocvpn-cdn-origin-stockholm.conf")

_EXPECTED_ACTIVATE_RATE = "rate=30r/m"
_EXPECTED_MANIFEST_RATE = "rate=120r/m"
_EXPECTED_ACTIVATE_BURST = "burst=20"
_EXPECTED_MANIFEST_BURST = "burst=60"
_EXPECTED_CONN_LIMIT = "20"
_EXPECTED_STATUS = "429"

# Routes B56-3 must NOT touch - a `limit_req`/`limit_conn` directive must
# never appear inside any of these locations' own block.
_UNRELATED_ROUTES = ("/v1/peers", "/v1/xray-profile", "/v1/relay-health", "/v1/ingress-profile")


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _location_block(conf_text, route):
    """Extracts one exact-match `location = <route> { ... }` block's body (same slicing convention as test_edge_deployment_config.py)."""
    marker = f"location = {route} {{"
    if marker not in conf_text:
        return None
    return conf_text.split(marker, 1)[1].split("\n    }", 1)[0]


def _top_level_zone_declarations(conf_text):
    """Everything OUTSIDE any `server { ... }` block - i.e. what a file included from http {} contributes directly to http context. Mirrors this file's own `map` directive already living at this level (nginx-pocvpn-stockholm.conf). Only matches an ACTUAL `server {` directive at the start of a line (ignoring leading whitespace) - never a mention of the word inside a comment/string, such as this test file's own docs sentences about server {} placement."""
    return re.sub(r"^[ \t]*server\s*\{.*", "", conf_text, count=1, flags=re.DOTALL | re.MULTILINE)


class _ControlPlaneRateLimitAssertions:
    """Mixin sharing assertions across both vhosts - avoids duplicating each check twice while still running once per file via two concrete TestCase subclasses (real files, not a shared fixture)."""

    conf_path = None

    @classmethod
    def setUpClass(cls):
        cls.conf = _read(cls.conf_path)
        cls.top_level = _top_level_zone_declarations(cls.conf)

    # --- zones exist, and live in http context (outside any server {}) ---

    def test_activate_rate_zone_declared_at_top_level(self):
        self.assertIn("limit_req_zone $binary_remote_addr zone=pocvpn_activate_rl:10m rate=30r/m;", self.top_level)

    def test_manifest_rate_zone_declared_at_top_level(self):
        self.assertIn("limit_req_zone $binary_remote_addr zone=pocvpn_manifest_rl:10m rate=120r/m;", self.top_level)

    def test_concurrency_zone_declared_at_top_level(self):
        self.assertIn("limit_conn_zone $binary_remote_addr zone=pocvpn_bootstrap_conn:10m;", self.top_level)

    def test_zone_declarations_are_not_duplicated_inside_any_server_block(self):
        # The zone directives must be declared exactly once each, at the
        # http-context level extracted above - never re-declared (which
        # nginx would refuse) inside a server {} block.
        for zone_directive in (
            "limit_req_zone $binary_remote_addr zone=pocvpn_activate_rl",
            "limit_req_zone $binary_remote_addr zone=pocvpn_manifest_rl",
            "limit_conn_zone $binary_remote_addr zone=pocvpn_bootstrap_conn",
        ):
            self.assertEqual(1, self.conf.count(zone_directive), zone_directive)

    # --- key is non-secret ---

    def test_zone_key_is_binary_remote_addr_never_a_secret_or_header(self):
        for zone_directive_prefix in ("limit_req_zone ", "limit_conn_zone "):
            for line in self.top_level.splitlines():
                if line.strip().startswith(zone_directive_prefix):
                    self.assertIn("$binary_remote_addr", line)
                    self.assertNotIn("$http_authorization", line)
                    self.assertNotIn("$http_", line)
                    self.assertNotIn("$request_body", line)
                    self.assertNotIn("$arg_", line)

    # --- /v1/activate ---

    def test_activate_has_the_activation_request_rate_limit_applied(self):
        block = _location_block(self.conf, "/v1/activate")
        self.assertIsNotNone(block, "location = /v1/activate not found")
        self.assertIn(f"limit_req zone=pocvpn_activate_rl {_EXPECTED_ACTIVATE_BURST} nodelay;", block)

    def test_activate_has_the_concurrency_limit_applied(self):
        block = _location_block(self.conf, "/v1/activate")
        self.assertIn(f"limit_conn pocvpn_bootstrap_conn {_EXPECTED_CONN_LIMIT};", block)

    def test_activate_remains_post_only(self):
        block = _location_block(self.conf, "/v1/activate")
        self.assertIn("limit_except POST", block)
        self.assertNotIn("limit_except GET", block)

    def test_activate_still_proxies_to_existing_loopback_upstream(self):
        block = _location_block(self.conf, "/v1/activate")
        self.assertIn("proxy_pass http://127.0.0.1:8443;", block)

    # --- /v1/manifest ---

    def test_manifest_has_the_manifest_request_rate_limit_applied(self):
        block = _location_block(self.conf, "/v1/manifest")
        self.assertIsNotNone(block, "location = /v1/manifest not found")
        self.assertIn(f"limit_req zone=pocvpn_manifest_rl {_EXPECTED_MANIFEST_BURST} nodelay;", block)

    def test_manifest_has_the_concurrency_limit_applied(self):
        block = _location_block(self.conf, "/v1/manifest")
        self.assertIn(f"limit_conn pocvpn_bootstrap_conn {_EXPECTED_CONN_LIMIT};", block)

    def test_manifest_remains_get_only(self):
        block = _location_block(self.conf, "/v1/manifest")
        self.assertIn("limit_except GET", block)
        self.assertNotIn("limit_except POST", block)

    def test_manifest_still_proxies_to_existing_loopback_upstream(self):
        block = _location_block(self.conf, "/v1/manifest")
        self.assertIn("proxy_pass http://127.0.0.1:8443;", block)

    # --- explicit, non-default rejection status ---

    def test_rate_limit_rejection_status_is_429_for_both_mechanisms(self):
        self.assertIn(f"limit_req_status {_EXPECTED_STATUS};", self.conf)
        self.assertIn(f"limit_conn_status {_EXPECTED_STATUS};", self.conf)

    # --- unrelated routes did not accidentally acquire these limits ---

    def test_unrelated_routes_have_no_limit_req_or_limit_conn_directive(self):
        for route in _UNRELATED_ROUTES:
            block = _location_block(self.conf, route)
            if block is None:
                continue  # e.g. /v1/ingress-profile only exists on Stockholm
            self.assertNotIn("limit_req ", block, f"{route} unexpectedly acquired limit_req")
            self.assertNotIn("limit_conn ", block, f"{route} unexpectedly acquired limit_conn")

    # --- server_tokens / existing safety invariants untouched ---

    def test_server_tokens_off_unchanged(self):
        self.assertIn("server_tokens off;", self.conf)

    def test_no_credential_or_token_shaped_header_added_to_access_log_config(self):
        self.assertNotIn("$http_authorization", self.conf)


class GermanyControlPlaneRateLimitTests(_ControlPlaneRateLimitAssertions, unittest.TestCase):
    conf_path = _NGINX_GERMANY


class StockholmControlPlaneRateLimitTests(_ControlPlaneRateLimitAssertions, unittest.TestCase):
    conf_path = _NGINX_STOCKHOLM


class GermanyStockholmParityTests(unittest.TestCase):
    """Explicit parity proof - Germany and Stockholm must carry IDENTICAL B56-3 values; no gateway may silently end up with weaker protection."""

    @classmethod
    def setUpClass(cls):
        cls.germany = _read(_NGINX_GERMANY)
        cls.stockholm = _read(_NGINX_STOCKHOLM)

    def test_zone_declarations_are_byte_for_byte_identical(self):
        for zone_directive in (
            "limit_req_zone $binary_remote_addr zone=pocvpn_activate_rl:10m rate=30r/m;",
            "limit_req_zone $binary_remote_addr zone=pocvpn_manifest_rl:10m rate=120r/m;",
            "limit_conn_zone $binary_remote_addr zone=pocvpn_bootstrap_conn:10m;",
        ):
            self.assertIn(zone_directive, self.germany)
            self.assertIn(zone_directive, self.stockholm)

    def test_activate_limit_directives_are_byte_for_byte_identical(self):
        germany_block = _location_block(self.germany, "/v1/activate")
        stockholm_block = _location_block(self.stockholm, "/v1/activate")
        for directive in (
            f"limit_req zone=pocvpn_activate_rl {_EXPECTED_ACTIVATE_BURST} nodelay;",
            f"limit_conn pocvpn_bootstrap_conn {_EXPECTED_CONN_LIMIT};",
        ):
            self.assertIn(directive, germany_block)
            self.assertIn(directive, stockholm_block)

    def test_manifest_limit_directives_are_byte_for_byte_identical(self):
        germany_block = _location_block(self.germany, "/v1/manifest")
        stockholm_block = _location_block(self.stockholm, "/v1/manifest")
        for directive in (
            f"limit_req zone=pocvpn_manifest_rl {_EXPECTED_MANIFEST_BURST} nodelay;",
            f"limit_conn pocvpn_bootstrap_conn {_EXPECTED_CONN_LIMIT};",
        ):
            self.assertIn(directive, germany_block)
            self.assertIn(directive, stockholm_block)

    def test_rejection_status_is_identical_on_both_gateways(self):
        for conf in (self.germany, self.stockholm):
            self.assertIn(f"limit_req_status {_EXPECTED_STATUS};", conf)
            self.assertIn(f"limit_conn_status {_EXPECTED_STATUS};", conf)


class UntouchedConfigsTests(unittest.TestCase):
    """Proves the two explicitly out-of-scope edge configs acquired NO B56-3 directive at all."""

    def test_acme_bootstrap_config_has_no_rate_or_concurrency_limiting(self):
        text = _read(_NGINX_BOOTSTRAP)
        for token in ("limit_req", "limit_conn", "pocvpn_activate_rl", "pocvpn_manifest_rl", "pocvpn_bootstrap_conn"):
            self.assertNotIn(token, text)

    def test_cdn_xhttp_origin_config_has_no_rate_or_concurrency_limiting(self):
        text = _read(_NGINX_CDN_ORIGIN)
        for token in ("limit_req", "limit_conn", "pocvpn_activate_rl", "pocvpn_manifest_rl", "pocvpn_bootstrap_conn"):
            self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
