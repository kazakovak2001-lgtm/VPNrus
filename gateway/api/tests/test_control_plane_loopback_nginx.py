"""B57-5A - static safety contract for the pocvpn-cp-loopback nginx
templates (future Cloudflare -> cloudflared -> 127.0.0.1:8081 control-plane
edge). Purely static: never starts nginx, never touches a real host - same
discipline as test_control_plane_nginx_rate_limits.py.

Contract (docs/B57_5A_CONTROL_PLANE_LOOPBACK.md):
  C1 nginx decides Cache-Control; upstream caching headers are hidden.
  C2 `public, max-age=300` only for anonymous GET /v1/manifest + 2xx.
  C3 Cloudflare Cache Rule is secondary (not configured in these files).
  C4 every Cache-Control uses `add_header ... always`.
"""
import os
import re
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_EDGE_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", "..", "edge"))

_FRANKFURT = os.path.join(_EDGE_DIR, "nginx-pocvpn-cp-loopback-frankfurt.conf")
_STOCKHOLM = os.path.join(_EDGE_DIR, "nginx-pocvpn-cp-loopback-stockholm.conf")
_EXISTING_VHOSTS = (
    "nginx-pocvpn.conf",
    "nginx-pocvpn-stockholm.conf",
    "nginx-pocvpn-bootstrap.conf",
    "nginx-pocvpn-cdn-origin-frankfurt.conf",
    "nginx-pocvpn-cdn-origin-stockholm.conf",
    "nginx-pocvpn-cdn-origin.conf.example",
)

_PRIVATE = "private, no-store"
_PUBLIC = "public, max-age=300"
_HIDDEN_HEADERS = (
    "Cache-Control",
    "Expires",
    "Pragma",
    "CDN-Cache-Control",
    "Cloudflare-CDN-Cache-Control",
    "Surrogate-Control",
)
_NEVER_ROUTED = ("/v1/field-enroll", "/v1/peers", "/v1/relay-health")


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _active(text):
    """Config with every comment stripped - only directives nginx would actually parse."""
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _block_after(text, marker):
    """Body of the `{ ... }` block that opens at `marker`, found by brace matching."""
    start = text.index(marker) + len(marker)
    depth = 1
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i]
    raise AssertionError(f"unterminated block after {marker!r}")


def _http_level(active):
    """Everything outside the server {} block (http-context directives)."""
    before, after = active.split("\nserver {", 1)
    body = _block_after("server {" + after, "server {")
    return before + ("server {" + after).replace("server {" + body + "}", "", 1)


def _locations(active):
    server = _block_after(active, "\nserver {")
    return {
        m.group(1): _block_after(server, m.group(0))
        for m in re.finditer(r"location\s+(?:=\s+)?(\S+)\s*\{", server)
    }


def _server_level(active):
    """Server-block directives outside every location {} block."""
    server = _block_after(active, "\nserver {")
    for m in reversed(list(re.finditer(r"location\s+(?:=\s+)?\S+\s*\{", server))):
        body = _block_after(server, m.group(0))
        server = server.replace(m.group(0) + body + "}", "", 1)
    return server


def _manifest_map(active):
    """Parses the manifest cache map into (default, [(regex, value)])."""
    m = re.search(
        r'map\s+"\$request_method:\$pocvpn_cp_auth:\$status"\s+\$pocvpn_cp_manifest_cache_control\s*\{(.*?)\}',
        active,
        re.S,
    )
    assert m, "manifest cache map missing"
    default, rules = None, []
    for key, value in re.findall(r'^\s*("[^"]*"|\S+)\s+"([^"]*)"\s*;', m.group(1), re.M):
        key = key.strip('"')
        if key == "default":
            default = value
        else:
            assert key.startswith("~"), f"non-regex map key {key!r}"
            rules.append((key[1:], value))
    return default, rules


def _simulate_manifest(active, method, auth, status):
    default, rules = _manifest_map(active)
    key = f"{method}:{1 if auth else 0}:{status}"
    for pattern, value in rules:
        if re.search(pattern, key):
            return value
    return default


class _LoopbackAssertions:
    conf_path = None
    expected_routes = None

    @classmethod
    def setUpClass(cls):
        cls.raw = _read(cls.conf_path)
        cls.active = _active(cls.raw)
        cls.http = _http_level(cls.active)
        cls.locs = _locations(cls.active)

    # --- listener ---

    def test_listener_is_loopback_8081_only(self):
        self.assertEqual(["127.0.0.1:8081 default_server"], re.findall(r"listen\s+([^;]+);", self.active))

    def test_no_wildcard_or_ipv6_listener(self):
        for bad in ("0.0.0.0", "[::]", "listen 8081", "listen *:"):
            self.assertNotIn(bad, self.active)

    def test_single_server_block(self):
        self.assertEqual(1, len(re.findall(r"^server\s*\{", self.active, re.M)))

    # --- routes ---

    def test_exact_route_set(self):
        self.assertEqual(sorted(self.expected_routes + ["/"]), sorted(self.locs))

    def test_never_routed_paths_absent(self):
        for route in _NEVER_ROUTED:
            self.assertNotIn(route, self.active, route)

    def test_catch_all_is_404(self):
        self.assertRegex(self.locs["/"], r"return\s+404;")
        self.assertNotIn("proxy_pass", self.locs["/"])

    def test_manifest_is_get_only_and_others_post_only(self):
        for route in self.expected_routes:
            expected = "GET" if route == "/v1/manifest" else "POST"
            self.assertRegex(self.locs[route], rf"limit_except {expected}\s*\{{\s*deny all;\s*\}}", route)

    def test_upstreams(self):
        for route in self.expected_routes:
            upstream = re.findall(r"proxy_pass\s+([^;]+);", self.locs[route])
            if route == "/v1/ingress-profile":
                self.assertEqual(["http://$pocvpn_ingress_profile_backend"], upstream)
            else:
                self.assertEqual(["http://127.0.0.1:8443"], upstream, route)

    # --- C1: upstream caching headers hidden in every proxied location ---

    def test_every_proxied_location_hides_upstream_caching_headers(self):
        for route in self.expected_routes:
            for header in _HIDDEN_HEADERS:
                self.assertIn(f"proxy_hide_header {header};", self.locs[route], (route, header))

    # --- C4: add_header always, in every location (no inheritance reliance) ---

    def test_every_location_sets_cache_control_always(self):
        for route, body in self.locs.items():
            headers = re.findall(r"add_header\s+Cache-Control\s+(.+?)\s+always;", body)
            self.assertEqual(1, len(headers), route)
            self.assertEqual(1, body.count("add_header"), route)

    def test_no_add_header_without_always(self):
        for line in re.findall(r"add_header[^;]*;", self.active):
            self.assertTrue(line.endswith(" always;"), line)

    # --- C2: cache decision ---

    def test_authorization_detection_map(self):
        self.assertRegex(
            self.http,
            r'map \$http_authorization \$pocvpn_cp_auth \{\s*""\s+0;\s*default\s+1;\s*\}',
        )

    def test_manifest_uses_cache_map_and_everything_else_is_private(self):
        for route, body in self.locs.items():
            value = re.search(r"add_header\s+Cache-Control\s+(.+?)\s+always;", body).group(1)
            if route == "/v1/manifest":
                self.assertEqual("$pocvpn_cp_manifest_cache_control", value)
            else:
                self.assertEqual(f'"{_PRIVATE}"', value, route)

    def test_public_value_appears_only_in_manifest_map(self):
        self.assertEqual(1, self.active.count(_PUBLIC))
        self.assertNotIn("public", _block_after(self.active, "\nserver {"))

    def test_manifest_map_default_is_private(self):
        self.assertEqual(_PRIVATE, _manifest_map(self.active)[0])

    def test_anonymous_get_2xx_is_public(self):
        for status in (200, 203, 204, 206, 299):
            self.assertEqual(_PUBLIC, _simulate_manifest(self.active, "GET", False, status), status)

    def test_authorization_is_private(self):
        for status in (200, 204, 404, 500):
            self.assertEqual(_PRIVATE, _simulate_manifest(self.active, "GET", True, status), status)

    def test_non_get_methods_are_private(self):
        for method in ("POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"):
            for auth in (False, True):
                self.assertEqual(_PRIVATE, _simulate_manifest(self.active, method, auth, 200), (method, auth))

    def test_non_2xx_is_private(self):
        for status in (100, 301, 304, 400, 401, 403, 404, 413, 429, 499, 500, 502, 503, 504, 2000, 20, ""):
            self.assertEqual(_PRIVATE, _simulate_manifest(self.active, "GET", False, status), status)

    def test_map_regex_is_anchored(self):
        for pattern, _ in _manifest_map(self.active)[1]:
            self.assertTrue(pattern.startswith("^") and pattern.endswith("$"), pattern)

    # --- rate limiting ---

    def test_rate_limit_zones(self):
        zones = re.findall(r"limit_req_zone\s+\$binary_remote_addr\s+zone=(\w+):10m\s+rate=(\w+/m);", self.http)
        self.assertEqual(
            {("pocvpn_cp_manifest_rl", "120r/m"), ("pocvpn_cp_activate_rl", "30r/m"), ("pocvpn_cp_profile_rl", "30r/m")},
            set(zones),
        )
        self.assertIn("limit_conn_zone $binary_remote_addr zone=pocvpn_cp_conn:10m;", self.http)

    def test_zone_names_unique_and_namespaced(self):
        names = re.findall(r"zone=(\w+):", self.active)
        self.assertEqual(len(names), len(set(names)))
        for name in names:
            self.assertTrue(name.startswith("pocvpn_cp_"), name)

    def test_each_proxied_route_is_rate_limited(self):
        expected_zone = {"/v1/manifest": ("pocvpn_cp_manifest_rl", 60), "/v1/activate": ("pocvpn_cp_activate_rl", 20)}
        for route in self.expected_routes:
            zone, burst = expected_zone.get(route, ("pocvpn_cp_profile_rl", 20))
            self.assertIn(f"limit_req zone={zone} burst={burst} nodelay;", self.locs[route], route)
            self.assertIn("limit_conn pocvpn_cp_conn 20;", self.locs[route], route)

    def test_limit_status_429(self):
        self.assertIn("limit_req_status  429;", self.active)
        self.assertIn("limit_conn_status 429;", self.active)

    # --- no duplicate definitions ---

    def test_no_duplicate_map_or_log_format(self):
        targets = re.findall(r"^map\s+\S+\s+(\$\w+)", self.active, re.M)
        self.assertEqual(["$pocvpn_cp_auth", "$pocvpn_cp_manifest_cache_control"], targets)
        self.assertEqual(["pocvpn_cp_log"], re.findall(r"log_format\s+(\w+)", self.active))

    def test_ingress_backend_map_never_redefined(self):
        self.assertNotRegex(self.active, r"map\s+\S+\s+\$pocvpn_ingress_profile_backend")

    # --- real IP ---

    def test_real_ip_trusts_loopback_only(self):
        self.assertEqual(["127.0.0.1"], re.findall(r"set_real_ip_from\s+([^;]+);", self.active))
        self.assertEqual(["CF-Connecting-IP"], re.findall(r"real_ip_header\s+([^;]+);", self.active))
        self.assertEqual(["off"], re.findall(r"real_ip_recursive\s+([^;]+);", self.active))

    # --- proxy hardening ---

    def test_proxy_hardening_in_every_proxied_location(self):
        for route in self.expected_routes:
            body = self.locs[route]
            for directive in (
                "proxy_http_version 1.1;",
                "proxy_set_header Host $host;",
                "proxy_set_header X-Real-IP $remote_addr;",
                "proxy_set_header X-Forwarded-For $remote_addr;",
                'proxy_set_header Connection "";',
                "proxy_redirect off;",
                "proxy_connect_timeout 5s;",
                "proxy_send_timeout 10s;",
            ):
                self.assertIn(directive, body, (route, directive))
            self.assertRegex(body, r"proxy_read_timeout (10|20)s;")
        self.assertNotIn("$proxy_add_x_forwarded_for", self.active)

    def test_server_hardening(self):
        self.assertIn("server_tokens off;", self.active)
        self.assertIn("client_max_body_size 2k;", self.active)
        for forbidden in ("root ", "alias ", "autoindex", "proxy_cache", "proxy_ignore_headers"):
            self.assertNotIn(forbidden, self.active)

    # --- logging ---

    def test_log_format_has_no_sensitive_fields(self):
        fmt = re.search(r"log_format\s+pocvpn_cp_log[^;]*;", self.active).group(0)
        # Allow-list: any other variable ($request, $request_uri, $args,
        # $http_authorization, $request_body, ...) fails this test.
        self.assertEqual(
            {"$time_iso8601", "$host", "$request_method", "$uri", "$status", "$body_bytes_sent", "$request_time"},
            set(re.findall(r"\$\w+", fmt)),
        )

    def test_access_log_uses_safe_format(self):
        self.assertEqual(
            ["/var/log/nginx/pocvpn-cp-loopback-access.log pocvpn_cp_log"],
            re.findall(r"access_log\s+([^;]+);", self.active),
        )

    # --- B57-5D: server-level C4 + HTTPS enforcement ---

    def test_server_level_cache_control_is_private_always(self):
        server = _server_level(self.active)
        self.assertEqual(
            ['add_header Cache-Control "private, no-store" always;'],
            re.findall(r"add_header[^;]*;", server),
        )

    def test_server_level_has_no_public_cache_control(self):
        self.assertNotIn("public", _server_level(self.active))

    def test_every_location_overrides_server_level_header(self):
        # nginx inherits server-level add_header only into a location that
        # declares none; every location must declare its own Cache-Control.
        for route, body in self.locs.items():
            self.assertRegex(body, r"add_header\s+Cache-Control\s+\S", route)

    def test_https_enforcement_exactly_once_at_server_level(self):
        server = _server_level(self.active)
        self.assertEqual(1, len(re.findall(r"\bif\s*\(", self.active)))
        self.assertEqual(1, len(re.findall(r"\bif\s*\(", server)))
        for route, body in self.locs.items():
            self.assertNotIn("x_forwarded_proto", body, route)

    def test_https_enforcement_compares_exactly_https_and_returns_403(self):
        server = _server_level(self.active)
        m = re.search(r"\bif\s*\((.*?)\)\s*\{(.*?)\}", server, re.S)
        self.assertIsNotNone(m)
        self.assertEqual('$http_x_forwarded_proto != "https"', m.group(1).strip())
        self.assertEqual("return 403;", " ".join(m.group(2).split()))

    def test_enforcement_precedes_every_location(self):
        server = _block_after(self.active, "\nserver {")
        self.assertLess(server.index("if ("), server.index("location"))
        self.assertLess(server.index("add_header"), server.index("location"))

    def test_no_redirects(self):
        self.assertNotRegex(self.active, r"\breturn\s+30[1278]\b")
        self.assertNotRegex(self.active, r"\brewrite\b")
        self.assertEqual({"403", "404"}, set(re.findall(r"\breturn\s+(\d+)", self.active)))

    # --- no production identifiers or secrets ---

    def test_only_loopback_ip_literals(self):
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", self.raw):
            self.assertTrue(ip.startswith("127.") or ip == "0.0.0.0", ip)

    def test_no_hostnames_tunnel_ids_or_secrets(self):
        lowered = self.raw.lower()
        for needle in (
            "cfargotunnel", "trycloudflare", "tunnelsecret", "tunnel_secret", "accounttag", "account_id",
            "credentials-file", "credentials.json", "cert.pem", "api_token", "cf_api", "x-auth-key",
            "cp-t0", "b57-t0", "nova-b57", "ssl_certificate", "letsencrypt", "bearer ",
        ):
            self.assertNotIn(needle, lowered, needle)
        self.assertNotRegex(self.raw, r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
        self.assertNotRegex(self.raw, r"\b[0-9a-f]{32}\b")
        self.assertNotRegex(self.raw, r"\b[A-Za-z0-9_\-]{40,}\b")
        self.assertNotRegex(lowered, r"\b[a-z0-9-]+\.(?:com|net|org|io|dev|app|ru|se|de|cloud|xyz)\b")
        self.assertNotRegex(self.raw, r"server_name\s+(?!_;)")


class FrankfurtLoopbackTests(_LoopbackAssertions, unittest.TestCase):
    conf_path = _FRANKFURT
    expected_routes = ["/v1/manifest", "/v1/activate", "/v1/xray-profile"]

    def test_no_stockholm_only_routes(self):
        self.assertNotIn("/v1/hysteria-profile", self.active)
        self.assertNotIn("/v1/ingress-profile", self.active)
        self.assertNotIn("$pocvpn_ingress_profile_backend", self.active)


class StockholmLoopbackTests(_LoopbackAssertions, unittest.TestCase):
    conf_path = _STOCKHOLM
    expected_routes = [
        "/v1/manifest", "/v1/activate", "/v1/xray-profile", "/v1/hysteria-profile", "/v1/ingress-profile",
    ]

    def test_ingress_map_is_defined_by_existing_vhost(self):
        # The loopback file relies on the existing Stockholm vhost's map; if
        # that definition ever disappears, this include would fail nginx -t.
        existing = _active(_read(os.path.join(_EDGE_DIR, "nginx-pocvpn-stockholm.conf")))
        self.assertEqual(1, len(re.findall(r"map\s+\S+\s+\$pocvpn_ingress_profile_backend", existing)))


class CrossFileTests(unittest.TestCase):
    def test_variants_share_http_level_definitions_so_only_one_may_be_loaded(self):
        fr = _http_level(_active(_read(_FRANKFURT)))
        st = _http_level(_active(_read(_STOCKHOLM)))
        self.assertEqual(fr.strip(), st.strip())

    def test_variants_differ_only_by_stockholm_routes(self):
        fr = _locations(_active(_read(_FRANKFURT)))
        st = _locations(_active(_read(_STOCKHOLM)))
        for route, body in fr.items():
            self.assertEqual(body, st[route], route)
        self.assertEqual({"/v1/hysteria-profile", "/v1/ingress-profile"}, set(st) - set(fr))

    def test_existing_vhosts_untouched_by_loopback_namespace(self):
        for name in _EXISTING_VHOSTS:
            text = _read(os.path.join(_EDGE_DIR, name))
            for needle in ("pocvpn_cp_", "8081", "pocvpn-cp-loopback", "CF-Connecting-IP"):
                self.assertNotIn(needle, text, (name, needle))

    def test_loopback_names_do_not_collide_with_existing_vhosts(self):
        existing = "".join(_active(_read(os.path.join(_EDGE_DIR, n))) for n in _EXISTING_VHOSTS)
        existing_zones = set(re.findall(r"zone=(\w+):", existing))
        existing_maps = set(re.findall(r"^map\s+\S+\s+(\$\w+)", existing, re.M))
        loop = _active(_read(_FRANKFURT)) + _active(_read(_STOCKHOLM))
        self.assertFalse(existing_zones & set(re.findall(r"zone=(\w+):", loop)))
        self.assertFalse(existing_maps & set(re.findall(r"^map\s+\S+\s+(\$\w+)", loop, re.M)))


if __name__ == "__main__":
    unittest.main()
