"""B35 CDN origin deployment-preflight regression tests."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


_GATEWAY = Path(__file__).resolve().parents[2]
_TOOL = _GATEWAY / "tools" / "cdn_origin_preflight.py"

VALID_ENV = """\
NOVA_INGRESS_KIND=cdn_fronted
NOVA_INGRESS_XHTTP_CLIENT_HOST=edge.example.net
NOVA_INGRESS_XHTTP_CLIENT_PORT=443
NOVA_INGRESS_XHTTP_SERVER_PORT=2100
NOVA_INGRESS_XHTTP_HOST=origin-backend.example.net
NOVA_INGRESS_XHTTP_PATH=/nova-xhttp/
NOVA_INGRESS_XHTTP_MODE=packet-up
NOVA_INGRESS_XHTTP_MAX_EACH_POST_BYTES=524288
NOVA_INGRESS_XHTTP_PADDING_PLACEMENT=header
NOVA_INGRESS_XHTTP_PADDING_MIN_BYTES=100
NOVA_INGRESS_XHTTP_PADDING_MAX_BYTES=1000
"""

VALID_NGINX = """\
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name origin.example.net;

    ssl_certificate /etc/ssl/origin/fullchain.pem;
    ssl_certificate_key /etc/ssl/origin/privkey.pem;

    location / {
        try_files $uri $uri/ =404;
    }

    location ^~ /nova-xhttp/ {
        allow 8.8.8.0/24;
        allow 2606:4700::/32;
        deny all;

        limit_except GET POST {
            deny all;
        }

        proxy_pass http://127.0.0.1:2100;
        proxy_http_version 1.1;
        proxy_set_header Host origin-backend.example.net;
        proxy_set_header Connection "";

        proxy_cache off;
        proxy_no_cache 1;
        proxy_cache_bypass 1;
        add_header Cache-Control "no-store" always;
        proxy_request_buffering off;
        proxy_buffering off;

        client_max_body_size 1m;
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 10m;
    }
}
"""


class CdnOriginPreflightTests(unittest.TestCase):
    def _run(self, env_text=VALID_ENV, nginx_text=VALID_NGINX):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_path = root / "ingress.env"
            nginx_path = root / "cdn-origin.conf"
            env_path.write_text(env_text, encoding="utf-8")
            nginx_path.write_text(nginx_text, encoding="utf-8")
            return subprocess.run(
                [
                    sys.executable,
                    str(_TOOL),
                    "--env-file",
                    str(env_path),
                    "--nginx-config",
                    str(nginx_path),
                    "--static-only",
                ],
                cwd=str(_GATEWAY),
                text=True,
                capture_output=True,
                check=False,
            )

    def test_valid_static_contract_passes(self):
        result = self._run()
        self.assertEqual(0, result.returncode, msg=result.stdout + result.stderr)
        self.assertIn("CDN ORIGIN PREFLIGHT: PASS", result.stdout)

    def test_unreplaced_placeholder_fails_closed(self):
        nginx = VALID_NGINX.replace(
            "origin.example.net",
            "REPLACE_WITH_ORIGIN_TLS_SERVER_NAME",
            1,
        )
        result = self._run(nginx_text=nginx)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("no unreplaced REPLACE_WITH_ placeholders", result.stdout)

    def test_backend_host_must_match_ingress_xhttp_host(self):
        nginx = VALID_NGINX.replace(
            "proxy_set_header Host origin-backend.example.net;",
            "proxy_set_header Host wrong.example.net;",
        )
        result = self._run(nginx_text=nginx)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("fixed backend Host matches NOVA_INGRESS_XHTTP_HOST", result.stdout)

    def test_location_path_must_match_ingress_xhttp_path(self):
        nginx = VALID_NGINX.replace("location ^~ /nova-xhttp/", "location ^~ /wrong/")
        result = self._run(nginx_text=nginx)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("dedicated XHTTP location exists exactly once", result.stdout)

    def test_source_boundary_requires_global_cidrs(self):
        nginx = VALID_NGINX.replace("allow 8.8.8.0/24;", "allow 10.0.0.0/8;")
        result = self._run(nginx_text=nginx)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("CDN source allows are explicit global CIDRs", result.stdout)

    def test_nested_limit_except_deny_does_not_replace_source_deny(self):
        nginx = VALID_NGINX.replace("        deny all;\n\n        limit_except GET POST", "        limit_except GET POST", 1)
        result = self._run(nginx_text=nginx)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("CDN allow list terminates with deny all", result.stdout)

    def test_xray_backend_must_be_loopback_and_match_configured_port(self):
        nginx = VALID_NGINX.replace(
            "proxy_pass http://127.0.0.1:2100;",
            "proxy_pass http://0.0.0.0:2100;",
        )
        result = self._run(nginx_text=nginx)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Xray proxy is pinned to configured loopback backend", result.stdout)

    def test_client_body_ceiling_cannot_be_smaller_than_xray_packet_ceiling(self):
        env_text = VALID_ENV.replace(
            "NOVA_INGRESS_XHTTP_MAX_EACH_POST_BYTES=524288",
            "NOVA_INGRESS_XHTTP_MAX_EACH_POST_BYTES=2097152",
        )
        result = self._run(env_text=env_text)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("nginx body ceiling covers Xray packet ceiling", result.stdout)

    def test_wrong_ingress_kind_and_wrong_mode_fail(self):
        env_text = VALID_ENV.replace(
            "NOVA_INGRESS_KIND=cdn_fronted",
            "NOVA_INGRESS_KIND=direct_ip",
        ).replace(
            "NOVA_INGRESS_XHTTP_MODE=packet-up",
            "NOVA_INGRESS_XHTTP_MODE=stream-up",
        )
        result = self._run(env_text=env_text)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("ingress kind is cdn_fronted", result.stdout)
        self.assertIn("first executable XHTTP mode is packet-up", result.stdout)

    def test_client_ip_forwarding_headers_are_rejected(self):
        nginx = VALID_NGINX.replace(
            'proxy_set_header Connection "";',
            'proxy_set_header Connection "";\n'
            '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
        )
        result = self._run(nginx_text=nginx)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("client IP forwarding headers are absent", result.stdout)

    def test_satisfy_any_is_rejected(self):
        nginx = VALID_NGINX.replace(
            "allow 8.8.8.0/24;",
            "satisfy any;\n        allow 8.8.8.0/24;",
        )
        result = self._run(nginx_text=nginx)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("satisfy-any bypass is absent", result.stdout)


if __name__ == "__main__":
    unittest.main()
