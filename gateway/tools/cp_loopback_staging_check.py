#!/usr/bin/env python3
"""B57-5E staging verification harness for the pocvpn-cp-loopback listener.

Runs the B57-5A section 11 HTTP contract against either the loopback
listener itself (``--mode loopback``, run ON the gateway host against
http://127.0.0.1:8081) or a Cloudflare-fronted staging hostname
(``--mode cloudflare``, run from a machine OUTSIDE the gateway host).

API budget rule (learned in B57-5E): pocvpn-api has ONE process-wide
global limiter (60 requests / 10 s, gateway/api/server.py) shared by every
client and every endpoint. A burst of manifest GETs therefore rate-limits
real production activations. This harness keeps requests that reach the
API at or below ``API_REQUEST_BUDGET`` per run, and proves nginx's own
per-client rate limit with methods that ``limit_except`` denies (counted
by ``limit_req`` in PREACCESS, rejected 403 in ACCESS, never proxied).

Read-only toward the API: no credential is ever sent; the Authorization
probe uses a fixed non-secret sentinel. Never prints response bodies.

B57-5D (origin HTTPS enforcement): in ``--mode loopback`` every normal
request carries ``CLOUDFLARE_FORWARDED`` - the headers measured on the
cloudflared -> nginx hop for an HTTPS client (B57-5E 11.6). This is a
LOCAL emulation of what cloudflared sends, not evidence about Cloudflare:
any local process can send these headers (B57-5A section 7).
``--scheme-enforcement`` must match the deployed listener: ``on`` expects
a request without ``X-Forwarded-Proto: https`` to be rejected with 403 +
``private, no-store`` before any location (never proxied); ``off``
expects such a request to be served as today. This harness never sends a
plain-HTTP request through Cloudflare.
"""
import argparse
import dataclasses
import hashlib
import sys
import urllib.error
import urllib.request

PUBLIC_MANIFEST = "public, max-age=300"
PRIVATE = "private, no-store"
SENTINEL_AUTH = "Bearer b57e5-sentinel-not-a-secret"
API_REQUEST_BUDGET = 20
CACHE_WARMUP_ATTEMPTS = 4
# GET /v1/activate is denied by `limit_except POST` after the
# pocvpn_cp_activate_rl zone (30r/m, burst 20) has counted it.
RATE_LIMIT_PROBE_PATH = "/v1/activate"
RATE_LIMIT_PROBE_COUNT = 30
NGINX_LIMITED_STATUSES = (403, 429)
# Measured on the cloudflared -> nginx hop for an HTTPS client (B57-5E 11.6).
CLOUDFLARE_FORWARDED = {"X-Forwarded-Proto": "https", "CF-Visitor": '{"scheme":"https"}'}
# Requests that B57-5D must reject: no forwarded scheme, and the values
# measured for a plain-HTTP client (B57-5D negative test).
SCHEME_REJECT_PROBES = (
    ("no X-Forwarded-Proto", {}),
    ("X-Forwarded-Proto http", {"X-Forwarded-Proto": "http", "CF-Visitor": '{"scheme":"http"}'}),
)
SCHEME_ENFORCEMENT_MODES = ("off", "on")


@dataclasses.dataclass(frozen=True)
class Response:
    status: int
    headers: dict  # lower-case header name -> value
    body: bytes


@dataclasses.dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def urllib_fetch(base_url, timeout=15.0):
    def fetch(method, path, headers=None, body=None):
        req = urllib.request.Request(base_url.rstrip("/") + path, data=body, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return Response(r.status, {k.lower(): v for k, v in r.headers.items()}, r.read())
        except urllib.error.HTTPError as e:
            return Response(e.code, {k.lower(): v for k, v in e.headers.items()}, e.read())
    return fetch


def cache_control(resp):
    return resp.headers.get("cache-control", "")


def is_cache_hit(resp):
    return resp.headers.get("cf-cache-status", "").upper() == "HIT"


def manifest_sha256(resp):
    return hashlib.sha256(resp.body).hexdigest()


def classify_rate_limit(statuses_a, statuses_b):
    """Client A must eventually see 429; client B, right after, must not."""
    a_limited = 429 in statuses_a
    b_limited = 429 in statuses_b
    if not a_limited:
        return False, "client A never reached 429 (limit not observed)"
    if b_limited:
        return False, "client B was limited by client A's burst (shared key)"
    return True, f"A: {statuses_a.count(429)}x429, B: none"


def api_requests_planned(mode, scheme_enforcement):
    """Upper bound of requests that are proxied to pocvpn-api in one run."""
    # Proxied: anon GET, Authorization GET x2, HEAD, POST /v1/activate (x2
    # through Cloudflare). POST manifest, the unknown path, field-enroll and
    # every rate-limit probe are answered by nginx alone. The scheme probes
    # (loopback only) are proxied only while enforcement is off.
    repeats = 2 if mode == "cloudflare" else 1
    warmup = CACHE_WARMUP_ATTEMPTS if mode == "cloudflare" else 0
    scheme = len(SCHEME_REJECT_PROBES) if mode == "loopback" and scheme_enforcement == "off" else 0
    return 1 + 2 + 1 + repeats + warmup + scheme


def with_forwarded(fetch):
    """Emulates cloudflared: adds CLOUDFLARE_FORWARDED unless the caller overrides a header."""
    def wrapped(method, path, headers=None, body=None):
        return fetch(method, path, dict(CLOUDFLARE_FORWARDED, **(headers or {})), body)
    return wrapped


class _Runner:
    def __init__(self, fetch):
        self.fetch = fetch
        self.checks = []

    def add(self, name, ok, detail):
        self.checks.append(Check(name, bool(ok), detail))


def run_checks(fetch, mode, expected_sha256, *, scheme_enforcement, client_ips=("198.51.100.11", "198.51.100.12"),
               fetch_b=None):
    """Return a list of Check. `fetch_b` is a second client's fetch (cloudflare mode, optional)."""
    if mode not in ("loopback", "cloudflare"):
        raise ValueError(mode)
    if scheme_enforcement not in SCHEME_ENFORCEMENT_MODES:
        raise ValueError(scheme_enforcement)
    if api_requests_planned(mode, scheme_enforcement) > API_REQUEST_BUDGET:
        raise AssertionError("harness would exceed the pocvpn-api request budget")
    cf = mode == "cloudflare"
    raw_fetch = fetch
    if not cf:
        fetch = with_forwarded(raw_fetch)
    r = _Runner(fetch)

    anon = fetch("GET", "/v1/manifest")
    r.add("manifest anon status", anon.status == 200, str(anon.status))
    r.add("manifest anon cache-control", cache_control(anon) == PUBLIC_MANIFEST, cache_control(anon))
    sha = manifest_sha256(anon)
    r.add("manifest sha256", sha == expected_sha256.lower(), sha[:16])

    if cf:
        hit = is_cache_hit(anon)
        attempts = 0
        while not hit and attempts < CACHE_WARMUP_ATTEMPTS:
            again = fetch("GET", "/v1/manifest")
            hit = is_cache_hit(again)
            attempts += 1
        r.add("manifest anon cf-cache-status HIT after warm-up", hit, f"{attempts} warm-up request(s)")

    for i in range(2):
        auth = fetch("GET", "/v1/manifest", {"Authorization": SENTINEL_AUTH})
        r.add(f"Authorization GET #{i + 1} private", cache_control(auth) == PRIVATE, cache_control(auth))
        if cf:
            r.add(f"Authorization GET #{i + 1} not HIT", not is_cache_hit(auth), auth.headers.get("cf-cache-status", ""))

    head = fetch("HEAD", "/v1/manifest")
    r.add("HEAD manifest private", cache_control(head) == PRIVATE, f"{head.status} {cache_control(head)}")

    for name, method, path in (
        ("POST manifest denied", "POST", "/v1/manifest"),
        ("unknown path", "GET", "/b57e5-unknown"),
        ("field-enroll not routed", "GET", "/v1/field-enroll"),
        ("POST activate without credential", "POST", "/v1/activate"),
    ):
        expected = {"POST manifest denied": 403, "unknown path": 404,
                    "field-enroll not routed": 404, "POST activate without credential": 401}[name]
        body = b"{}" if method == "POST" else None
        hdrs = {"Content-Type": "application/json"} if method == "POST" else None
        for i in range(2 if cf else 1):
            resp = fetch(method, path, hdrs, body)
            r.add(f"{name} #{i + 1}", resp.status == expected and cache_control(resp) == PRIVATE,
                  f"{resp.status} {cache_control(resp)}")
            if cf:
                r.add(f"{name} #{i + 1} not HIT", not is_cache_hit(resp), resp.headers.get("cf-cache-status", ""))

    if not cf:
        for name, headers in SCHEME_REJECT_PROBES:
            resp = raw_fetch("GET", "/v1/manifest", headers)
            if scheme_enforcement == "on":
                ok = resp.status == 403 and cache_control(resp) == PRIVATE
            else:
                ok = resp.status == 200 and cache_control(resp) == PUBLIC_MANIFEST
            r.add(f"scheme enforcement {scheme_enforcement}: {name}", ok, f"{resp.status} {cache_control(resp)}")

    if mode == "loopback":
        a, b = client_ips
        sa = [fetch("GET", RATE_LIMIT_PROBE_PATH, {"CF-Connecting-IP": a}).status for _ in range(RATE_LIMIT_PROBE_COUNT)]
        sb = [fetch("GET", RATE_LIMIT_PROBE_PATH, {"CF-Connecting-IP": b}).status for _ in range(3)]
        ok, detail = classify_rate_limit(sa, sb)
        r.add("per-client rate limit (CF-Connecting-IP)", ok and set(sa + sb) <= set(NGINX_LIMITED_STATUSES), detail)
    elif fetch_b is not None:
        sa = [fetch("GET", RATE_LIMIT_PROBE_PATH).status for _ in range(RATE_LIMIT_PROBE_COUNT)]
        sb = [fetch_b("GET", RATE_LIMIT_PROBE_PATH).status for _ in range(3)]
        ok, detail = classify_rate_limit(sa, sb)
        r.add("per-client rate limit (two real clients)", ok, detail)
    return r.checks


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--base-url", required=True)
    p.add_argument("--mode", choices=("loopback", "cloudflare"), required=True)
    p.add_argument("--expected-manifest-sha256", required=True)
    p.add_argument("--scheme-enforcement", choices=SCHEME_ENFORCEMENT_MODES, required=True,
                   help="must match the deployed listener (B57-5D)")
    args = p.parse_args(argv)
    checks = run_checks(urllib_fetch(args.base_url), args.mode, args.expected_manifest_sha256,
                        scheme_enforcement=args.scheme_enforcement)
    for c in checks:
        print(f"{'PASS' if c.ok else 'FAIL'}  {c.name}: {c.detail}")
    failed = [c for c in checks if not c.ok]
    print(f"{len(checks) - len(failed)}/{len(checks)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
