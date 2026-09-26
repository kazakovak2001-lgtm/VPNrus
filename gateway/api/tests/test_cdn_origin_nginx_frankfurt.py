"""Static safety contract for the B59 Frankfurt CDN origin nginx config.

Purely static text checks - no nginx invocation, no production/network
access. Mirrors test_cdn_origin_nginx_template.py's checks, adapted for the
concrete Frankfurt file (real hostname/backend instead of placeholders).
"""
from pathlib import Path
import re
import unittest


_ROOT = Path(__file__).resolve().parents[2]
_CONFIG = _ROOT / "edge" / "nginx-pocvpn-cdn-origin-frankfurt.conf"

_CLOUDFLARE_CIDRS = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)


class FrankfurtCdnOriginNginxConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = _CONFIG.read_text(encoding="utf-8")

    # -- Identity ----------------------------------------------------
    def test_server_name_is_the_decided_frankfurt_identity(self):
        self.assertIn("server_name edge.aknova.pp.ua;", self.text)

    # -- XHTTP path ----------------------------------------------------
    def test_xhttp_path_uses_trailing_slash_prefix_match(self):
        self.assertIn("location ^~ /nova-xhttp/", self.text)
        self.assertNotIn("location ^~ /nova-xhttp \n", self.text)
        self.assertNotIn("location ^~ /nova-xhttp {", self.text)
        self.assertNotIn("location ^~ /nova-xhttp\n", self.text)

    # -- Backend ----------------------------------------------------
    def test_only_dedicated_prefix_proxies_to_loopback_xray_2099(self):
        self.assertEqual(1, self.text.count("proxy_pass http://127.0.0.1:2099;"))

    def test_backend_is_never_a_public_address(self):
        forbidden = (
            "152.70.43.1",
            "16.170.208.231",
            "proxy_pass http://edge.aknova.pp.ua",
        )
        for value in forbidden:
            self.assertNotIn(value, self.text)

    def test_xray_backend_port_is_never_a_public_nginx_listener(self):
        self.assertNotRegex(self.text, re.compile(r"listen\s+(?:\[::\]:|0\.0\.0\.0:)?2099\b"))

    # -- Methods ----------------------------------------------------
    def test_first_slice_allows_only_get_and_post(self):
        self.assertRegex(
            self.text,
            re.compile(r"limit_except GET POST\s*\{\s*deny all;\s*\}", re.MULTILINE),
        )
        for forbidden_method in ("PUT", "DELETE", "PATCH"):
            self.assertNotIn(f"limit_except {forbidden_method}", self.text)

    # -- Cloudflare boundary ----------------------------------------------------
    def test_cloudflare_allowlist_matches_stockholm_repository_precedent(self):
        for cidr in _CLOUDFLARE_CIDRS:
            self.assertIn(f"allow {cidr};", self.text)

    def test_xhttp_location_is_fail_closed(self):
        self.assertRegex(
            self.text,
            re.compile(
                r"allow 2c0f:f248::/32;\s*deny all;",
                re.MULTILINE,
            ),
        )

    def test_documents_allowlist_must_be_reverified_before_deploy(self):
        self.assertIn("re-verified against Cloudflare's current published ranges", self.text)

    # -- Host header ----------------------------------------------------
    def test_host_header_is_fixed_operator_controlled(self):
        self.assertIn("proxy_set_header Host edge.aknova.pp.ua;", self.text)
        self.assertNotIn("proxy_set_header Host $host;", self.text)

    # -- Buffering ----------------------------------------------------
    def test_buffering_is_disabled(self):
        self.assertIn("proxy_buffering off;", self.text)
        self.assertIn("proxy_request_buffering off;", self.text)

    # -- Cache ----------------------------------------------------
    def test_cache_is_disabled(self):
        for directive in (
            "proxy_cache off;",
            "proxy_no_cache 1;",
            "proxy_cache_bypass 1;",
            'add_header Cache-Control "no-store" always;',
        ):
            self.assertIn(directive, self.text)

    # -- TLS ----------------------------------------------------
    def test_tls_protocols_are_1_2_and_1_3_only(self):
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", self.text)

    def test_tls_references_frankfurt_origin_ca_filesystem_paths(self):
        self.assertIn(
            "ssl_certificate     /etc/nginx/cloudflare-origin/aknova-origin.pem;",
            self.text,
        )
        self.assertIn(
            "ssl_certificate_key /etc/nginx/cloudflare-origin/aknova-origin.key;",
            self.text,
        )

    def test_no_private_key_material_embedded_in_repo_file(self):
        self.assertNotIn("BEGIN PRIVATE KEY", self.text)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", self.text)
        self.assertNotIn("BEGIN EC PRIVATE KEY", self.text)

    # -- HTTP/2 / nginx version compatibility ----------------------------------------------------
    def test_no_standalone_http2_directive_requiring_newer_nginx(self):
        code_lines = [
            line for line in self.text.splitlines() if not line.strip().startswith("#")
        ]
        code_text = "\n".join(code_lines)
        self.assertNotIn("http2 on;", code_text)
        self.assertNotRegex(code_text, re.compile(r"listen\s+443\s+ssl\s+http2"))

    def test_listen_directive_is_the_1_24_0_compatible_form(self):
        self.assertIn("listen 443 ssl;", self.text)

    # -- Timeouts ----------------------------------------------------
    def test_timeouts_match_stockholm_proven_values(self):
        self.assertIn("proxy_connect_timeout 5s;", self.text)
        self.assertIn("proxy_send_timeout 60s;", self.text)
        self.assertIn("proxy_read_timeout 10m;", self.text)

    # -- Body size ----------------------------------------------------
    def test_client_max_body_size_matches_stockholm_precedent(self):
        self.assertIn("client_max_body_size 1m;", self.text)

    # -- Client IP headers ----------------------------------------------------
    def test_no_client_ip_headers_added_beyond_stockholm_precedent(self):
        self.assertNotIn("X-Real-IP", self.text)
        self.assertNotIn("X-Forwarded-For", self.text)

    # -- Server-level hardening ----------------------------------------------------
    def test_server_tokens_disabled(self):
        self.assertIn("server_tokens off;", self.text)

    def test_connection_header_matches_stockholm_pattern(self):
        self.assertIn('proxy_set_header Connection "";', self.text)


if __name__ == "__main__":
    unittest.main()
