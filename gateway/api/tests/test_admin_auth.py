"""Unit tests for AdminAuthenticator + admin endpoint integration (B8B1D M3).

Covers:
  - admin_auth.AdminAuthenticator: secret-file validation, session lifecycle,
    HMAC password check, CSRF token handling, brute-force rate limiting via
    AuthFailureLimiter.
  - handler.py admin endpoints: /admin/login, /admin/logout, /admin/session,
    /admin/status — through a real RunningServer on an ephemeral port.

Tests use deterministic FakeClock for rate-limit assertions; cookie parsing
and session lifecycle are exercised against the live handler via _http helpers.
"""

import json
import os
import sys
import tempfile
import time
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api import config as config_module
from api import admin_auth
from api.auth_ratelimit import AuthFailureLimiter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_secret_file(tmp_dir, name="admin-secret.bin", content=b"x" * 32):
    path = os.path.join(tmp_dir, name)
    with open(path, "wb") as handle:
        handle.write(content)
    return path


class FakeClock:
    """Deterministic monotonic clock for rate-limit tests."""

    def __init__(self, start=0.0):
        self._now = start

    def __call__(self):
        return self._now

    def advance(self, seconds):
        self._now += seconds


# ---------------------------------------------------------------------------
# admin_auth tests
# ---------------------------------------------------------------------------

class AdminAuthenticatorConfigTests(unittest.TestCase):
    """Secret-file loading, validation, and fail-closed behaviour."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_blank_secret_raises(self):
        with self.assertRaises(admin_auth.ConfigError) as ctx:
            admin_auth.AdminAuthenticator("")
        self.assertIn("not configured", str(ctx.exception).lower())

    def test_missing_file_raises(self):
        with self.assertRaises(admin_auth.ConfigError):
            admin_auth.AdminAuthenticator(os.path.join(self._tmp.name, "nope.bin"))

    def test_relative_path_raises(self):
        path = os.path.join(self._tmp.name, "rel.bin")
        with open(path, "wb") as f:
            f.write(b"\xab" * 32)
        # Save cwd and switch to tmp so relative path is truly relative.
        orig = os.getcwd()
        try:
            os.chdir(self._tmp.name)
            with self.assertRaises(ValueError) as ctx:
                admin_auth.AdminAuthenticator("rel.bin")
            self.assertIn("absolute", str(ctx.exception).lower())
        finally:
            os.chdir(orig)

    def test_wrong_length_raises(self):
        for length in (31, 33, 64, 0):
            path = _write_secret_file(self._tmp.name, content=b"\xab" * length)
            with self.assertRaises(admin_auth.ConfigError) as ctx:
                admin_auth.AdminAuthenticator(path)
            self.assertIn("32 bytes", str(ctx.exception))

    def test_valid_secret_loads(self):
        path = _write_secret_file(self._tmp.name)
        auth = admin_auth.AdminAuthenticator(path)
        self.assertIsNotNone(auth)
        # Internal invariant: _secret_hash is non-empty bytes.
        self.assertEqual(len(auth._secret_hash), 32)


class AdminAuthenticatorSessionTests(unittest.TestCase):
    """Password verify, session create/validate/invalidate, CSRF."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.secret_path = _write_secret_file(self._tmp.name)
        self.clock = FakeClock(start=1000.0)
        # AdminAuthenticator's session clock and limiter both use
        # time.monotonic - patch only that.
        self._real_mono = time.monotonic
        import time as time_module
        time_module.monotonic = self.clock
        self.addCleanup(lambda: setattr(time_module, "monotonic", self._real_mono))

    def _make_auth(self):
        return admin_auth.AdminAuthenticator(self.secret_path)

    def test_correct_password_creates_session(self):
        auth = self._make_auth()
        ok, data, err = auth.verify_password_and_create_session("x" * 32, "1.2.3.4")
        self.assertTrue(ok)
        self.assertIsNone(err)
        sid, csrf = data
        self.assertIsInstance(sid, str)
        self.assertIsInstance(csrf, str)
        info = auth.get_session_info(sid)
        self.assertIsNotNone(info)
        self.assertEqual(info["csrf_token"], csrf)

    def test_wrong_password_fails(self):
        auth = self._make_auth()
        ok, data, err = auth.verify_password_and_create_session("wrong", "1.2.3.4")
        self.assertFalse(ok)
        self.assertEqual(err, "unauthorized")
        self.assertIsNone(data)

    def test_csrf_validation_rejects_mismatch(self):
        auth = self._make_auth()
        ok, (sid, csrf), _ = auth.verify_password_and_create_session("x" * 32, "1.2.3.4")
        self.assertTrue(ok)
        valid, info = auth.validate_session_and_csrf(sid, csrf + "-wrong")
        self.assertFalse(valid)
        # Must still return session_data (so caller can log/audit without leaking token).
        self.assertIsNotNone(info)

    def test_csrf_validation_accepts_match(self):
        auth = self._make_auth()
        ok, (sid, csrf), _ = auth.verify_password_and_create_session("x" * 32, "1.2.3.4")
        valid, info = auth.validate_session_and_csrf(sid, csrf)
        self.assertTrue(valid)
        self.assertIsNotNone(info)

    def test_csrf_optional_on_session_check(self):
        auth = self._make_auth()
        ok, (sid, _csrf), _ = auth.verify_password_and_create_session("x" * 32, "1.2.3.4")
        valid, info = auth.validate_session_and_csrf(sid)
        self.assertTrue(valid)
        self.assertIsNotNone(info)

    def test_invalidate_session(self):
        auth = self._make_auth()
        ok, (sid, _csrf), _ = auth.verify_password_and_create_session("x" * 32, "1.2.3.4")
        self.assertTrue(ok)
        self.assertTrue(auth.invalidate_session(sid))
        valid, info = auth.validate_session_and_csrf(sid)
        self.assertFalse(valid)
        self.assertIsNone(info)

    def test_invalid_session_rejected(self):
        auth = self._make_auth()
        valid, info = auth.validate_session_and_csrf("nonexistent")
        self.assertFalse(valid)
        self.assertIsNone(info)

    def test_session_expires(self):
        auth = self._make_auth()
        ok, (sid, _csrf), _ = auth.verify_password_and_create_session("x" * 32, "1.2.3.4")
        self.assertTrue(ok)
        # Expire at created_at + 28800.
        self.clock.advance(28800.0)
        valid, info = auth.validate_session_and_csrf(sid)
        self.assertFalse(valid)
        self.assertIsNone(info)

    def test_get_rate_limit_info(self):
        auth = self._make_auth()
        info = auth.get_rate_limit_info()
        self.assertIn("sessions", info)
        self.assertIn("per_source_windows", info)


class AdminAuthRateLimitTests(unittest.TestCase):
    """Brute-force protection via AuthFailureLimiter."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.secret_path = _write_secret_file(self._tmp.name)
        self.clock = FakeClock(start=2000.0)
        import time as time_module
        self._real_mono = time_module.monotonic
        time_module.monotonic = self.clock
        self.addCleanup(lambda: setattr(time_module, "monotonic", self._real_mono))

    def _make_auth(self):
        return admin_auth.AdminAuthenticator(self.secret_path)

    def test_source_rate_limit_blocks_after_threshold(self):
        auth = self._make_auth()
        # per_source_max=10 by construction; fail 10 times, 11th is blocked.
        for i in range(10):
            ok, _, err = auth.verify_password_and_create_session("wrong", "1.2.3.4")
            self.assertFalse(ok)
            self.assertEqual(err, "unauthorized")
        ok, _, err = auth.verify_password_and_create_session("wrong", "1.2.3.4")
        self.assertFalse(ok)
        self.assertTrue(err.startswith("rate_limited"))

    def test_successful_login_resets_account_failures(self):
        auth = self._make_auth()
        # 29 failures spread over sources (per-source max is 10), so the
        # shared "admin" account (max 30) is one failure from lockout.
        for i in range(29):
            auth.verify_password_and_create_session("wrong", f"10.0.0.{i // 9}")
        ok, _, _ = auth.verify_password_and_create_session("x" * 32, "10.0.1.1")
        self.assertTrue(ok)
        # Account counter was reset: two more failures do not lock it.
        for _ in range(2):
            auth.verify_password_and_create_session("wrong", "10.0.2.1")
        ok, _, err = auth.verify_password_and_create_session("x" * 32, "10.0.3.1")
        self.assertTrue(ok, err)

    def test_authenticator_uses_shared_limiter_class(self):
        auth = self._make_auth()
        self.assertIs(type(auth._auth_failure_limiter), AuthFailureLimiter)
        self.assertIs(admin_auth.AuthFailureLimiter, AuthFailureLimiter)

    def test_invalid_password_type_is_counted_failure(self):
        auth = self._make_auth()
        for bad in (1, None, ["x"], "", "a" * 2000, "\ud800"):
            ok, data, err = auth.verify_password_and_create_session(bad, "1.2.3.4")
            self.assertFalse(ok)
            self.assertIsNone(data)
            self.assertEqual(err, "invalid_password")
        # 6 counted failures + 4 wrong passwords = per-source max (10).
        for _ in range(4):
            auth.verify_password_and_create_session("wrong", "1.2.3.4")
        _, _, err = auth.verify_password_and_create_session("x" * 32, "1.2.3.4")
        self.assertEqual(err, "rate_limited")


# ---------------------------------------------------------------------------
# Endpoint integration tests via real server
# ---------------------------------------------------------------------------

from _fixtures import RunningServer, make_app_config, make_public_key, make_token_store
from api import tokens as tokens_module
from _http import (
    post_admin_login,
    post_admin_logout,
    get_admin_session,
    get_admin_status,
    parse_http_response,
)


class AdminEndpointDisabledTests(unittest.TestCase):
    """Admin endpoints MUST fail closed (503) when admin_secret_file is blank."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        script = os.path.join(self._tmp.name, "prov.sh")
        with open(script, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env bash\nexit 0\n")
        cfg = make_app_config(self._tmp.name, script)
        self.server = RunningServer(cfg)
        self.addCleanup(self.server.close)

    def test_login_disabled(self):
        status, headers, body = post_admin_login(self.server.port, "x" * 32)
        self.assertEqual(status, 503)
        parsed = json.loads(body)
        self.assertEqual(parsed["error"], "admin_not_configured")

    def test_logout_disabled(self):
        status, headers, body = post_admin_logout(self.server.port)
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body)["error"], "admin_not_configured")

    def test_session_disabled(self):
        status, headers, body = get_admin_session(self.server.port)
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body)["error"], "admin_not_configured")

    def test_status_disabled(self):
        status, headers, body = get_admin_status(self.server.port)
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body)["error"], "admin_not_configured")


class AdminEndpointEnabledTests(unittest.TestCase):
    """Full login/logout/session/status cycle with a valid secret."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        script = os.path.join(self._tmp.name, "prov.sh")
        with open(script, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env bash\nexit 0\n")
        secret_path = _write_secret_file(self._tmp.name)
        cfg = make_app_config(
            self._tmp.name, script,
            admin_secret_file=secret_path,
        )
        self.server = RunningServer(cfg)
        self.addCleanup(self.server.close)
        self.password = "x" * 32

    def _login(self, extra_headers=None):
        status, headers, body = post_admin_login(self.server.port, self.password, extra_headers)
        set_cookie = headers.get("set-cookie", "")
        return status, headers, body, set_cookie

    def _extract_session(self, set_cookie):
        """Parse pocvpn-admin-session from Set-Cookie header."""
        for part in set_cookie.split(";"):
            part = part.strip()
            if part.startswith("pocvpn-admin-session="):
                return part.split("=", 1)[1]
        return None

    def _extract_csrf_from_body(self, body):
        return json.loads(body).get("csrf_token")

    def test_login_success(self):
        status, headers, body, sc = self._login()
        self.assertEqual(status, 200)
        self.assertIn("pocvpn-admin-session=", sc)
        data = json.loads(body)
        self.assertEqual(data["status"], "logged_in")
        self.assertIsInstance(data["csrf_token"], str)
        self.assertGreater(data["session_expires_at"], 0.0)

    def test_login_wrong_password(self):
        status, headers, body = post_admin_login(self.server.port, "wrong-password", {"X-Forwarded-For": "1.2.3.4"})
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"], "unauthorized")

    def test_login_missing_body(self):
        """POST /admin/login without Content-Length must fail closed."""
        from _http import send_raw_lines
        status, headers, body, _ = send_raw_lines(
            self.server.port, "POST", "/admin/login",
            ["Content-Type: application/json"],
            b"not-json",
        )
        # The handler reads Content-Length via _read_content_length which
        # requires it; missing -> LENGTH_REQUIRED (411).
        self.assertEqual(status, 411)

    def test_login_transfer_encoding_rejected(self):
        """Chunked Transfer-Encoding must be rejected to prevent smuggling."""
        from _http import send_raw_lines
        body = json.dumps({"password": self.password}).encode()
        status, headers, body_out, _ = send_raw_lines(
            self.server.port, "POST", "/admin/login",
            [
                "Content-Type: application/json",
                "Transfer-Encoding: chunked",
                f"Content-Length: {len(body)}",
            ],
            body,
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body_out)["error"], "invalid_request")

    def test_session_requires_cookie(self):
        status, headers, body = get_admin_session(self.server.port)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"], "unauthorized")

    def test_session_requires_csrf(self):
        status, headers, body, sc = self._login()
        sid = self._extract_session(sc)
        self.assertIsNotNone(sid)
        # GET /admin/session with cookie but NO X-CSRF-Token and no query param
        status, headers, body = get_admin_session(self.server.port, cookie=f"pocvpn-admin-session={sid}")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["error"], "missing_csrf_token")

    def test_session_valid(self):
        status, headers, body, sc = self._login()
        sid = self._extract_session(sc)
        csrf = self._extract_csrf_from_body(body)
        self.assertIsNotNone(sid)
        self.assertIsNotNone(csrf)
        status, headers, body = get_admin_session(
            self.server.port, cookie=f"pocvpn-admin-session={sid}", csrf_token=csrf
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "authenticated")

    def test_session_bad_csrf(self):
        status, headers, body, sc = self._login()
        sid = self._extract_session(sc)
        status, headers, body = get_admin_session(
            self.server.port, cookie=f"pocvpn-admin-session={sid}", csrf_token="bad"
        )
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"], "unauthorized")

    def test_status_valid(self):
        status, headers, body, sc = self._login()
        sid = self._extract_session(sc)
        status, headers, body = get_admin_status(
            self.server.port, cookie=f"pocvpn-admin-session={sid}"
        )
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["status"], "ok")
        self.assertTrue(data["session_exists"])
        # MUST NOT contain internal metrics like 'sessions' count or rate_limit tuple.
        self.assertNotIn("sessions", data)
        self.assertNotIn("rate_limit", data)

    def test_status_no_cookie(self):
        status, headers, body = get_admin_status(self.server.port)
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"], "unauthorized")

    def test_logout_invalidates_session(self):
        status, headers, body, sc = self._login()
        sid = self._extract_session(sc)
        csrf = self._extract_csrf_from_body(body)
        self.assertIsNotNone(sid)
        # Logout.
        status, headers, body = post_admin_logout(
            self.server.port, cookie=f"pocvpn-admin-session={sid}",
            extra_headers=self._mut(csrf),
        )
        self.assertEqual(status, 200)
        # Session should now be invalid.
        status, headers, body = get_admin_session(
            self.server.port,
            cookie=f"pocvpn-admin-session={sid}",
            csrf_token=csrf,
        )
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"], "unauthorized")

    def _mut(self, csrf, origin=None):
        return {
            "Content-Length": "0",
            "X-CSRF-Token": csrf,
            "Origin": origin or f"http://127.0.0.1:{self.server.port}",
        }

    def test_logout_rejects_missing_or_bad_csrf_and_origin(self):
        status, headers, body, sc = self._login()
        sid = self._extract_session(sc)
        csrf = self._extract_csrf_from_body(body)
        cookie = f"pocvpn-admin-session={sid}"
        port = self.server.port
        s, _, b = post_admin_logout(port, cookie=cookie, extra_headers={"Content-Length": "0"})
        self.assertEqual((s, json.loads(b)["error"]), (400, "missing_csrf_token"))
        s, _, b = post_admin_logout(port, cookie=cookie, extra_headers=self._mut("wrong"))
        self.assertEqual(s, 401)
        s, _, b = post_admin_logout(port, cookie=cookie, extra_headers=self._mut(csrf, "http://evil.example"))
        self.assertEqual((s, json.loads(b)["error"]), (403, "origin_mismatch"))
        h = self._mut(csrf)
        del h["Origin"]
        s, _, b = post_admin_logout(port, cookie=cookie, extra_headers=h)
        self.assertEqual(s, 403)
        # The session survived every rejected attempt, then logs out cleanly
        # and cannot be reused.
        s, _, _ = get_admin_status(port, cookie=cookie)
        self.assertEqual(s, 200)
        s, _, _ = post_admin_logout(port, cookie=cookie, extra_headers=self._mut(csrf))
        self.assertEqual(s, 200)
        s, _, _ = post_admin_logout(port, cookie=cookie, extra_headers=self._mut(csrf))
        self.assertEqual(s, 401)
        s, _, _ = get_admin_status(port, cookie=cookie)
        self.assertEqual(s, 401)

    def test_logout_idempotent(self):
        """Logout with no cookie is OK (idempotent)."""
        status, headers, body = post_admin_logout(self.server.port)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "logged_out")

    def test_wrong_password_consumes_rate_limit_quota(self):
        """Wrong password should increment the brute-force counter."""
        for i in range(10):
            status, _, _ = post_admin_login(self.server.port, "wrong-password")
            self.assertEqual(status, 401)
        # 11th attempt (even with the right password) is rate-limited.
        status, _, body, _ = self._login()
        self.assertEqual(status, 429)
        self.assertEqual(json.loads(body)["error"], "rate_limited")

    def test_logout_clears_cookie(self):
        status, headers, body, sc = self._login()
        sid = self._extract_session(sc)
        csrf = self._extract_csrf_from_body(body)
        status, out_headers, _ = post_admin_logout(
            self.server.port, cookie=f"pocvpn-admin-session={sid}", extra_headers=self._mut(csrf))
        self.assertEqual(status, 200)
        cleared = out_headers.get("set-cookie", "")
        self.assertIn("Max-Age=0", cleared)
        self.assertIn("Secure", cleared)

    def test_login_cookie_flags(self):
        status, _, _, sc = self._login()
        self.assertEqual(status, 200)
        for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/admin"):
            self.assertIn(flag, sc)

    def test_login_non_string_password_is_400(self):
        from _http import send_raw_lines
        for payload in ({"password": 1}, {"password": None}, {"password": ""}):
            raw = json.dumps(payload).encode()
            status, _, body_out, _ = send_raw_lines(
                self.server.port, "POST", "/admin/login",
                ["Content-Type: application/json", f"Content-Length: {len(raw)}"],
                raw,
            )
            self.assertEqual(status, 400)
            self.assertEqual(json.loads(body_out)["error"], "invalid_password")

    def test_session_csrf_query_param_not_accepted(self):
        status, _, body, sc = self._login()
        sid = self._extract_session(sc)
        csrf = self._extract_csrf_from_body(body)
        from _http import raw_request
        status, _, _ = raw_request(
            self.server.port, "GET", f"/admin/session?csrf_token={csrf}",
            {"Cookie": f"pocvpn-admin-session={sid}"}, b"",
        )
        self.assertEqual(status, 404)

    def test_unknown_path_still_404(self):
        from _http import raw_request
        status, _, body = raw_request(self.server.port, "GET", "/nope", {}, b"")
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"], "not_found")

    def test_login_non_json_content_type_rejected(self):
        from _http import send_raw_lines
        body = b"not-json"
        status, headers, body_out, _ = send_raw_lines(
            self.server.port, "POST", "/admin/login",
            ["Content-Type: text/plain", "Content-Length: 8"],
            body,
        )
        self.assertEqual(status, 415)
        self.assertEqual(json.loads(body_out)["error"], "unsupported_media_type")

    def test_login_body_too_large(self):
        from _http import send_raw_lines
        big = json.dumps({"password": "x" * 2000}).encode()
        status, headers, body_out, _ = send_raw_lines(
            self.server.port, "POST", "/admin/login",
            ["Content-Type: application/json", f"Content-Length: {len(big)}"],
            big,
        )
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(body_out)["error"], "payload_too_large")


def _minimal_env(tmp_dir, admin_secret_path):
    import base64
    script = os.path.join(tmp_dir, "provision-peer.sh")
    with open(script, "w", encoding="utf-8") as handle:
        handle.write("#!/usr/bin/env bash" + chr(10) + "exit 0" + chr(10))
    return {
        "POCVPN_API_ENDPOINT_HOST": "203.0.113.1",
        "POCVPN_API_ENDPOINT_PORT": "51820",
        "POCVPN_API_GATEWAY_PUBLIC_KEY": base64.b64encode(bytes([2]) * 32).decode("ascii"),
        "POCVPN_API_GATEWAY_TUNNEL_IP": "10.77.0.1",
        "POCVPN_API_TOKEN_STORE_PATH": os.path.join(tmp_dir, "enrollment-tokens.json"),
        "POCVPN_API_PROVISION_SCRIPT_PATH": script,
        "POCVPN_API_SUBPROCESS_TIMEOUT_SECONDS": "5",
        "POCVPN_API_API_PORT": "8765",
        "POCVPN_API_ADMIN_SECRET_FILE": admin_secret_path,
    }


class AdminSecretFormatTests(unittest.TestCase):
    """read_admin_secret is the single validator for config and authenticator."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_trailing_newline_tolerated(self):
        for content in (b"x" * 32 + b"\n", b"x" * 32 + b"\r\n"):
            path = _write_secret_file(self._tmp.name, content=content)
            self.assertEqual(admin_auth.read_admin_secret(path), b"x" * 32)

    def test_non_printable_rejected(self):
        for content in (b"\xab" * 32, b" " * 32, b"x" * 31 + b"\t"):
            path = _write_secret_file(self._tmp.name, content=content)
            with self.assertRaises(admin_auth.ConfigError):
                admin_auth.read_admin_secret(path)

    def test_config_and_authenticator_agree(self):
        for content, valid in ((b"x" * 32 + b"\n", True), (b"\xab" * 32, False), (b" x" * 16, False)):
            path = _write_secret_file(self._tmp.name, content=content)
            try:
                admin_auth.AdminAuthenticator(path)
                auth_ok = True
            except admin_auth.ConfigError:
                auth_ok = False
            try:
                config_module.load_config(_minimal_env(self._tmp.name, path))
                config_ok = True
            except config_module.ConfigError as exc:
                self.assertIn("ADMIN_SECRET_FILE", str(exc))
                config_ok = False
            self.assertEqual(auth_ok, valid)
            self.assertEqual(config_ok, valid)

    def test_error_never_contains_secret(self):
        path = _write_secret_file(self._tmp.name, content=b"S3cretValue" * 4)
        with self.assertRaises(admin_auth.ConfigError) as ctx:
            admin_auth.read_admin_secret(path)
        self.assertNotIn("S3cret", str(ctx.exception))


class AdminNginxEdgeTests(unittest.TestCase):
    """The admin edge is loopback-only and declared exactly once."""

    def setUp(self):
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "..", "..", "edge", "nginx-pocvpn.conf"), encoding="utf-8") as f:
            self.conf = f.read()

    def test_no_duplicate_exact_locations(self):
        import re
        locs = re.findall(r"^\s*location\s+=\s+(\S+)\s*\{", self.conf, re.M)
        self.assertEqual(len(locs), len(set(locs)), sorted(locs))

    def test_admin_locations_loopback_only(self):
        import re
        for path in ("/admin/login", "/admin/logout", "/admin/session", "/admin/status"):
            m = re.search(r"location = %s \{\s*allow 127\.0\.0\.1;\s*allow ::1;\s*deny all;" % re.escape(path), self.conf)
            self.assertIsNotNone(m, path)
        self.assertNotRegex(self.conf, r"set_real_ip_from|real_ip_header")


class CookieParsingEdgeCases(unittest.TestCase):
    """Defensive tests for the handler's _parse_session_cookie helper."""

    def test_parse_with_other_cookies_first(self):
        from api.handler import ProvisioningRequestHandler
        header = "other=value; pocvpn-admin-session=abc123; more=stuff"
        self.assertEqual(ProvisioningRequestHandler._parse_session_cookie(header), "abc123")

    def test_parse_only_our_cookie(self):
        from api.handler import ProvisioningRequestHandler
        header = "pocvpn-admin-session=xyz"
        self.assertEqual(ProvisioningRequestHandler._parse_session_cookie(header), "xyz")

    def test_parse_missing_cookie(self):
        from api.handler import ProvisioningRequestHandler
        self.assertIsNone(ProvisioningRequestHandler._parse_session_cookie("foo=bar"))

    def test_parse_empty(self):
        from api.handler import ProvisioningRequestHandler
        self.assertIsNone(ProvisioningRequestHandler._parse_session_cookie(""))

    def test_parse_no_value(self):
        from api.handler import ProvisioningRequestHandler
        header = "pocvpn-admin-session=; other=1"
        self.assertIsNone(ProvisioningRequestHandler._parse_session_cookie(header))


if __name__ == "__main__":
    unittest.main()
