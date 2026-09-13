"""Static safety contract for the B35 CDN origin nginx template."""
from pathlib import Path
import re
import unittest


_ROOT = Path(__file__).resolve().parents[2]
_TEMPLATE = _ROOT / "edge" / "nginx-pocvpn-cdn-origin.conf.example"


class CdnOriginNginxTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = _TEMPLATE.read_text(encoding="utf-8")

    def test_template_cannot_be_deployed_without_operator_values(self):
        for placeholder in (
            "REPLACE_WITH_ORIGIN_TLS_SERVER_NAME",
            "REPLACE_WITH_ORIGIN_CERTIFICATE_FILE",
            "REPLACE_WITH_ORIGIN_PRIVATE_KEY_FILE",
            "REPLACE_WITH_ORIGIN_HOST_HEADER",
            "REPLACE_WITH_CDN_SOURCE_CIDR",
        ):
            self.assertIn(placeholder, self.text)

    def test_only_dedicated_prefix_proxies_to_loopback_xray(self):
        self.assertIn("location ^~ /nova-xhttp/", self.text)
        self.assertEqual(1, self.text.count("proxy_pass http://127.0.0.1:2100;"))
        self.assertRegex(
            self.text,
            re.compile(r"location /\s*\{\s*try_files \$uri \$uri/ =404;\s*\}", re.MULTILINE),
        )

    def test_xray_backend_port_is_never_a_public_nginx_listener(self):
        self.assertNotRegex(self.text, re.compile(r"listen\s+(?:\[::\]:|0\.0\.0\.0:)?2100\b"))
        self.assertNotIn("listen 2100", self.text)

    def test_xhttp_origin_is_fail_closed_to_cdn_source_networks(self):
        self.assertIn(
            "allow REPLACE_WITH_CDN_SOURCE_CIDR;",
            self.text,
        )
        self.assertRegex(
            self.text,
            re.compile(
                r"allow REPLACE_WITH_CDN_SOURCE_CIDR;\s*deny all;",
                re.MULTILINE,
            ),
        )

    def test_first_slice_allows_only_packet_up_http_methods(self):
        self.assertRegex(
            self.text,
            re.compile(r"limit_except GET POST\s*\{\s*deny all;\s*\}", re.MULTILINE),
        )

    def test_cache_and_buffering_are_disabled(self):
        for directive in (
            "proxy_cache off;",
            "proxy_no_cache 1;",
            "proxy_cache_bypass 1;",
            "proxy_request_buffering off;",
            "proxy_buffering off;",
            'add_header Cache-Control "no-store" always;',
        ):
            self.assertIn(directive, self.text)

    def test_backend_host_is_fixed_operator_input_not_request_host(self):
        self.assertIn(
            "proxy_set_header Host REPLACE_WITH_ORIGIN_HOST_HEADER;",
            self.text,
        )
        self.assertNotIn("proxy_set_header Host $host;", self.text)
        self.assertNotIn("proxy_set_header Host $http_host;", self.text)

    def test_template_does_not_forward_client_ip_headers_to_xray(self):
        for header in ("X-Forwarded-For", "X-Real-IP", "Forwarded"):
            self.assertNotIn(f"proxy_set_header {header}", self.text)


if __name__ == "__main__":
    unittest.main()
