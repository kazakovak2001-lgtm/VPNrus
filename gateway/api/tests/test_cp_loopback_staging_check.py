"""B57-5E/B57-5D - tests for gateway/tools/cp_loopback_staging_check.py.

Offline only: a fake nginx models the B57-5A contract plus the B57-5D
server-level scheme check (and broken variants of them); no socket, no
real host.
"""
import hashlib
import importlib.util
from pathlib import Path
import unittest

_TOOL = Path(__file__).resolve().parents[2] / "tools" / "cp_loopback_staging_check.py"
_spec = importlib.util.spec_from_file_location("cp_loopback_staging_check", _TOOL)
h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h)

MANIFEST = b"signed-manifest-bytes"
SHA = hashlib.sha256(MANIFEST).hexdigest()


class FakeEdge:
    """Contract-correct loopback edge; flags switch on one defect each.

    enforce_scheme models the B57-5D server-level `if` (server-rewrite
    phase: before limit_req and before any location, never proxied).
    cdn=True models Cloudflare, which sets X-Forwarded-Proto itself.
    """

    def __init__(self, cdn=False, shared_key=False, auth_public=False, cache_errors=False,
                 never_hit=False, api_limit=60, enforce_scheme=False, missing_cc_on_403=False,
                 scheme_check_proxied=False):
        self.cdn = cdn
        self.shared_key = shared_key
        self.auth_public = auth_public
        self.cache_errors = cache_errors
        self.never_hit = never_hit
        self.enforce_scheme = enforce_scheme
        self.missing_cc_on_403 = missing_cc_on_403
        self.scheme_check_proxied = scheme_check_proxied
        self.buckets = {}
        self.api_calls = 0
        self.api_limit = api_limit
        self.cached = False
        self.seen_forwarded = []

    def _api(self):
        self.api_calls += 1
        return self.api_calls <= self.api_limit

    def __call__(self, method, path, headers=None, body=None, client="203.0.113.1"):
        headers = dict(headers or {})
        if self.cdn:
            headers["X-Forwarded-Proto"] = "https"
        self.seen_forwarded.append((headers.get("X-Forwarded-Proto"), headers.get("CF-Visitor")))
        auth = "Authorization" in headers
        cc_private = "private, no-store"
        cf = {}
        if self.enforce_scheme and headers.get("X-Forwarded-Proto") != "https":
            if self.scheme_check_proxied:
                self._api()
            return h.Response(403, {} if self.missing_cc_on_403 else {"cache-control": cc_private}, b"")
        if path in ("/v1/manifest", "/v1/activate"):
            key = "shared" if self.shared_key else headers.get("CF-Connecting-IP", client)
            zone = (path, key)
            self.buckets[zone] = self.buckets.get(zone, 0) + 1
            limit = 60 if path == "/v1/manifest" else 21
            if self.buckets[zone] > limit:
                return h.Response(429, {"cache-control": cc_private}, b"")
        if path == "/v1/manifest":
            if method == "POST":
                status, cc = 403, cc_private
            elif method == "GET" and not auth:
                if self.cdn and self.cached and not self.never_hit:
                    return h.Response(200, {"cache-control": "public, max-age=300", "cf-cache-status": "HIT"}, MANIFEST)
                if not self._api():
                    return h.Response(429, {"cache-control": cc_private}, b"")
                self.cached = True
                return h.Response(200, {"cache-control": "public, max-age=300", "cf-cache-status": "MISS"}, MANIFEST)
            elif method == "GET":
                self._api()
                cc = "public, max-age=300" if self.auth_public else cc_private
                status = 200
                if self.cdn and self.auth_public:
                    cf = {"cf-cache-status": "HIT"}
                return h.Response(status, dict({"cache-control": cc}, **cf), MANIFEST)
            else:  # HEAD
                self._api()
                status, cc = 405, cc_private
        elif path == "/v1/activate":
            if method != "POST":
                status, cc = 403, cc_private
            else:
                self._api()
                status, cc = 401, cc_private
        else:
            status, cc = 404, cc_private
        if self.cache_errors and status >= 400:
            cc = "public, max-age=300"
            if self.cdn:
                cf = {"cf-cache-status": "HIT"}
        return h.Response(status, dict({"cache-control": cc}, **cf), b"")


def failed(checks):
    return [c.name for c in checks if not c.ok]


def run(edge, mode="loopback", sha=SHA, scheme="off", **kw):
    return h.run_checks(edge, mode, sha, scheme_enforcement=scheme, **kw)


class LoopbackModeTest(unittest.TestCase):
    def test_contract_correct_edge_passes(self):
        self.assertEqual(failed(run(FakeEdge())), [])

    def test_wrong_manifest_sha_fails(self):
        self.assertIn("manifest sha256", failed(run(FakeEdge(), sha="0" * 64)))

    def test_shared_rate_limit_key_fails(self):
        self.assertIn("per-client rate limit (CF-Connecting-IP)", failed(run(FakeEdge(shared_key=True))))

    def test_authorization_must_be_private(self):
        self.assertIn("Authorization GET #1 private", failed(run(FakeEdge(auth_public=True))))

    def test_error_responses_must_be_private(self):
        names = failed(run(FakeEdge(cache_errors=True)))
        self.assertIn("POST manifest denied #1", names)
        self.assertIn("unknown path #1", names)
        self.assertIn("POST activate without credential #1", names)

    def test_run_stays_inside_api_budget(self):
        for scheme, edge in (("off", FakeEdge()), ("on", FakeEdge(enforce_scheme=True))):
            run(edge, scheme=scheme)
            self.assertLessEqual(edge.api_calls, h.api_requests_planned("loopback", scheme), scheme)
            self.assertLessEqual(edge.api_calls, h.API_REQUEST_BUDGET, scheme)

    def test_rate_limit_probe_never_reaches_api(self):
        edge = FakeEdge()
        run(edge)
        # 30 + 3 rate-limit probes would blow the budget if they were proxied.
        self.assertLess(edge.api_calls, h.RATE_LIMIT_PROBE_COUNT)


class SchemeEnforcementTest(unittest.TestCase):
    """B57-5D: loopback emulation of cloudflared and the server-level 403."""

    def test_normal_requests_carry_measured_forwarded_headers(self):
        edge = FakeEdge(enforce_scheme=True)
        run(edge, scheme="on")
        normal = [s for s in edge.seen_forwarded if s[0] == "https"]
        self.assertTrue(normal)
        self.assertTrue(all(s == ("https", '{"scheme":"https"}') for s in normal))

    def test_enforcing_edge_passes_with_on(self):
        self.assertEqual(failed(run(FakeEdge(enforce_scheme=True), scheme="on")), [])

    def test_rejected_requests_are_403_private(self):
        checks = {c.name: c for c in run(FakeEdge(enforce_scheme=True), scheme="on")}
        for name, _ in h.SCHEME_REJECT_PROBES:
            c = checks[f"scheme enforcement on: {name}"]
            self.assertTrue(c.ok, c.detail)
            self.assertEqual("403 private, no-store", c.detail)

    def test_403_without_cache_control_fails(self):
        names = failed(run(FakeEdge(enforce_scheme=True, missing_cc_on_403=True), scheme="on"))
        self.assertIn("scheme enforcement on: no X-Forwarded-Proto", names)
        self.assertIn("scheme enforcement on: X-Forwarded-Proto http", names)

    def test_rejected_requests_never_reach_api(self):
        edge = FakeEdge(enforce_scheme=True)
        run(edge, scheme="on")
        baseline = FakeEdge(enforce_scheme=True)
        h.run_checks(baseline, "loopback", SHA, scheme_enforcement="on")
        self.assertEqual(edge.api_calls, baseline.api_calls)
        self.assertEqual(h.api_requests_planned("loopback", "on") + len(h.SCHEME_REJECT_PROBES),
                         h.api_requests_planned("loopback", "off"))
        proxied = FakeEdge(enforce_scheme=True, scheme_check_proxied=True)
        run(proxied, scheme="on")
        self.assertEqual(edge.api_calls + len(h.SCHEME_REJECT_PROBES), proxied.api_calls)

    def test_on_against_non_enforcing_listener_fails(self):
        names = failed(run(FakeEdge(), scheme="on"))
        self.assertIn("scheme enforcement on: no X-Forwarded-Proto", names)

    def test_off_against_enforcing_listener_fails(self):
        names = failed(run(FakeEdge(enforce_scheme=True), scheme="off"))
        self.assertIn("scheme enforcement off: no X-Forwarded-Proto", names)

    def test_unknown_scheme_mode_rejected(self):
        with self.assertRaises(ValueError):
            run(FakeEdge(), scheme="maybe")

    def test_cli_requires_explicit_scheme_mode(self):
        with self.assertRaises(SystemExit):
            h.main(["--base-url", "http://127.0.0.1:8081", "--mode", "loopback",
                    "--expected-manifest-sha256", SHA])


class CloudflareModeTest(unittest.TestCase):
    def test_contract_correct_cdn_passes(self):
        for scheme in ("off", "on"):
            edge = FakeEdge(cdn=True, enforce_scheme=scheme == "on")
            self.assertEqual(failed(run(edge, "cloudflare", scheme=scheme)), [], scheme)

    def test_cloudflare_mode_sends_no_scheme_probes(self):
        names = [c.name for c in run(FakeEdge(cdn=True, enforce_scheme=True), "cloudflare", scheme="on")]
        self.assertFalse([n for n in names if n.startswith("scheme enforcement")])

    def test_missing_cache_hit_fails(self):
        names = failed(run(FakeEdge(cdn=True, never_hit=True), "cloudflare"))
        self.assertIn("manifest anon cf-cache-status HIT after warm-up", names)

    def test_authorization_hit_fails(self):
        self.assertIn("Authorization GET #1 not HIT", failed(run(FakeEdge(cdn=True, auth_public=True), "cloudflare")))

    def test_error_hit_fails(self):
        names = failed(run(FakeEdge(cdn=True, cache_errors=True), "cloudflare"))
        self.assertIn("unknown path #2 not HIT", names)
        self.assertIn("POST activate without credential #1 not HIT", names)

    def test_two_real_clients_rate_limit(self):
        edge = FakeEdge(cdn=True)
        a = lambda m, p, hd=None, b=None: edge(m, p, hd, b, client="203.0.113.10")
        b_ = lambda m, p, hd=None, b=None: edge(m, p, hd, b, client="203.0.113.20")
        checks = run(a, "cloudflare", fetch_b=b_)
        self.assertEqual(failed(checks), [])
        self.assertIn("per-client rate limit (two real clients)", [c.name for c in checks])

    def test_cloudflare_budget(self):
        for scheme in h.SCHEME_ENFORCEMENT_MODES:
            self.assertLessEqual(h.api_requests_planned("cloudflare", scheme), h.API_REQUEST_BUDGET)


class PureHelpersTest(unittest.TestCase):
    def test_classify_rate_limit(self):
        self.assertTrue(h.classify_rate_limit([403] * 21 + [429] * 9, [403] * 3)[0])
        self.assertFalse(h.classify_rate_limit([403] * 30, [403] * 3)[0])
        self.assertFalse(h.classify_rate_limit([403] * 21 + [429] * 9, [429] * 3)[0])

    def test_budget_is_below_api_global_limiter(self):
        # gateway/api/server.py: _GLOBAL_RATE_LIMIT = 60 per 10 s, shared by
        # every client and endpoint - the harness must stay well below it.
        server_src = (Path(__file__).resolve().parents[1] / "server.py").read_text(encoding="utf-8")
        self.assertIn("_GLOBAL_RATE_LIMIT = 60", server_src)
        self.assertLess(h.API_REQUEST_BUDGET, 60)
        for mode in ("loopback", "cloudflare"):
            for scheme in h.SCHEME_ENFORCEMENT_MODES:
                self.assertLessEqual(h.api_requests_planned(mode, scheme), h.API_REQUEST_BUDGET)

    def test_forwarded_headers_match_b57_5e_measurement(self):
        self.assertEqual({"X-Forwarded-Proto": "https", "CF-Visitor": '{"scheme":"https"}'}, h.CLOUDFLARE_FORWARDED)

    def test_unknown_mode_rejected(self):
        with self.assertRaises(ValueError):
            run(FakeEdge(), "production")


if __name__ == "__main__":
    unittest.main()
