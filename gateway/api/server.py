"""Server wiring and process entry point for the B8B1B provisioning API.

Server-boundary invariant: the bind host is hard-coded to "127.0.0.1"
right here, as a literal, and nowhere else in this package reads a
bind-host value from configuration or the environment (see config.py -
AppConfig has no such field at all). This slice creates no public
listener; only api_port is configurable.
"""
import logging
import sys
import time
from http.server import ThreadingHTTPServer

from . import config as config_module
from . import ingress_config as ingress_config_module
from . import ratelimit
from .handler import ProvisioningRequestHandler

_BIND_HOST = "127.0.0.1"

_PER_TOKEN_RATE_LIMIT = 5
_PER_TOKEN_RATE_WINDOW_SECONDS = 10.0
_GLOBAL_RATE_LIMIT = 60
_GLOBAL_RATE_WINDOW_SECONDS = 10.0

# Field-test zero-touch enrollment (POST /v1/field-enroll) - a SEPARATE,
# stricter, per-public-key limiter from per_token_limiter above (that one is
# keyed by an already-issued credential's digest; a field-enroll request has
# no credential yet, so it is keyed by the presented public key instead).
# Deliberately tighter than the general per-credential limit - this endpoint
# mints a brand new activation record on first use, a strictly more
# expensive/sensitive operation than an ordinary already-activated request.
_FIELD_ENROLLMENT_RATE_LIMIT = 3
_FIELD_ENROLLMENT_RATE_WINDOW_SECONDS = 60.0

# Round-2 review fix (cap exhaustion) - a SECOND, GLOBAL limiter for the
# SAME endpoint, keyed by a single constant (not the public key) so it
# bounds the TOTAL rate of field-enroll attempts regardless of how many
# distinct public keys an attacker presents (the per-key limiter above
# cannot help here at all - an attacker who mints a fresh public key per
# request never repeats a key). Deliberately set at/near
# field_enrollment_max_devices' own typical size (e.g. 5): even a
# perfectly-timed attack can never mint more than one field-enrolled
# device, on average, faster than roughly once per this window - the cap
# (a small, fixed number) can no longer be exhausted in a single instant,
# giving an operator a real chance to notice and disable the endpoint
# (POCVPN_API_FIELD_ENROLLMENT_ENABLED) before real damage is done. This is
# a THROTTLE, not a guarantee the cap can never be exhausted by a
# determined attacker within a few minutes - a cap this small has no
# stronger guarantee available without adding the kind of identity proof
# (IP allowlisting, per-tester manual credential, ...) this field test's
# own constraints explicitly rule out.
_FIELD_ENROLLMENT_GLOBAL_RATE_LIMIT = 5
_FIELD_ENROLLMENT_GLOBAL_RATE_WINDOW_SECONDS = 60.0


class ProvisioningServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, app_config, ingress_config=None):
        super().__init__(server_address, handler_class)
        self.config = app_config
        # B25 (task G) - None for every non-ingress deployment (the default
        # for every existing gateway) - see ingress_config.load_ingress_config's
        # own docs. handler.py's POST /v1/ingress-profile fails closed with
        # 503 whenever this is None, exactly like every other not-configured
        # endpoint already does.
        self.ingress_config = ingress_config
        self.per_token_limiter = ratelimit.RateLimiter(
            _PER_TOKEN_RATE_LIMIT, _PER_TOKEN_RATE_WINDOW_SECONDS, clock=time.monotonic
        )
        self.global_limiter = ratelimit.RateLimiter(
            _GLOBAL_RATE_LIMIT, _GLOBAL_RATE_WINDOW_SECONDS, clock=time.monotonic
        )
        self.field_enrollment_limiter = ratelimit.RateLimiter(
            _FIELD_ENROLLMENT_RATE_LIMIT, _FIELD_ENROLLMENT_RATE_WINDOW_SECONDS, clock=time.monotonic
        )
        self.field_enrollment_global_limiter = ratelimit.RateLimiter(
            _FIELD_ENROLLMENT_GLOBAL_RATE_LIMIT, _FIELD_ENROLLMENT_GLOBAL_RATE_WINDOW_SECONDS, clock=time.monotonic
        )


def build_server(app_config, ingress_config=None):
    return ProvisioningServer((_BIND_HOST, app_config.api_port), ProvisioningRequestHandler, app_config, ingress_config)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        app_config = config_module.load_config()
    except config_module.ConfigError as exc:
        print(f"pocvpn-api: configuration error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    try:
        ingress_cfg = ingress_config_module.load_ingress_config()
    except ingress_config_module.IngressConfigError as exc:
        print(f"pocvpn-api: ingress configuration error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    server = build_server(app_config, ingress_cfg)
    logging.getLogger("pocvpn.api").info("listening on %s:%d", _BIND_HOST, app_config.api_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
