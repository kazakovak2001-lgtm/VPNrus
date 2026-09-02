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
