"""HTTP request handling for the three POST-only endpoints this API
serves: /v1/peers (B8B1B), /v1/activate (B8C1), /v1/xray-profile
(B8K2) - plus ONE GET-only endpoint, /v1/manifest (B12), which serves an
already-signed EndpointManifest artifact verbatim (see _handle_manifest's
own docstring for why this process never signs or validates it).

No DELETE/admin/token-issuance routes exist in this slice. See
gateway/api/__init__.py for the architectural invariant this handler is
built around: it never touches awg0.conf, .provision.lock, or a private
key directly - /v1/peers and /v1/activate only ever reach real gateway
mutation through gateway/scripts/provision-peer.sh (via provision.py);
/v1/xray-profile never shells out DIRECTLY - it durably writes the
identity store it owns (xray_provisioning.py) and, in the SAME
per-activation-locked transaction (B8K2A - see xray_activation.py's own
docstring), synchronously renders/stages/validates/publishes/reloads the
running Xray server's config through the SAME narrow privileged-wrapper
boundary /v1/peers and /v1/activate use for AWG (gateway/api/xray_reload.py,
mirroring provision.py's own shape) - never a bare shell, never
`systemctl` invoked from this process directly. A response is only ever
200 once that activation is CONFIRMED, never merely durably recorded -
see handler.py's own mapping below. Credential storage differs by
endpoint: /v1/peers reads the enrollment-token store read-only (via
tokens.py); /v1/activate both reads AND durably writes the activation
store (via activations.py); /v1/xray-profile reuses the SAME activation
credential and device public key as /v1/activate - it is never a second,
independent credential/token system.
"""
import hmac
import json
import logging
import re
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from . import activations, ingress_activation, provision, relay_probe_token, tokens, xray_activation, xray_provisioning
from .wgkey import is_valid_wg_public_key

logger = logging.getLogger("pocvpn.api")

_PATH_PEERS = "/v1/peers"
_PATH_ACTIVATE = "/v1/activate"
_PATH_XRAY_PROFILE = "/v1/xray-profile"
_PATH_INGRESS_PROFILE = "/v1/ingress-profile"
_PATH_MANIFEST = "/v1/manifest"
_PATH_RELAY_HEALTH = "/v1/relay-health"

# B26 (task B) - the same TransportKind.name strings Android's TransportKind
# enum uses (see transport/TransportKind.kt - no custom toString(), so
# ${transportKind} interpolation IS the enum constant name) - this mapping
# is what lets ingress_config.py compute a historyPathId that matches
# PathCandidate.Relayed.historyPathId byte-for-byte without either side
# depending on the other's source.
_TRANSPORT_KIND_NAMES = {"reality": "XRAY_REALITY", "tls": "TLS_TCP"}
_MAX_BODY_BYTES = 1024
_MAX_MANIFEST_BYTES = 1_000_000
_BEARER_PREFIX = "Bearer "
_SOCKET_TIMEOUT_SECONDS = 5.0

# ASCII decimal digits only - deliberately NOT Python's int(), which also
# accepts a leading "+", "_" digit-group separators (e.g. "1_024"), and
# any Unicode decimal-digit character (e.g. Arabic-indic digits), any of
# which would silently pass int() but must be rejected here.
_CONTENT_LENGTH_RE = re.compile(r"^[0-9]+$")


def _is_json_content_type(content_type):
    return content_type.split(";", 1)[0].strip().lower() == "application/json"


class _RequestError(Exception):
    """Internal control-flow only - carries the (status, error_code) an
    early validation failure inside _handle_post should respond with.
    Never escapes _handle_post."""

    def __init__(self, status, error_code):
        super().__init__(error_code)
        self.status = status
        self.error_code = error_code


class ProvisioningRequestHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 so Content-Length/Connection framing is well-defined; every
    # response still explicitly sends "Connection: close" and sets
    # close_connection = True (see _dispatch) so a client can never send a
    # second request on the same socket - malformed/extra bytes just get
    # dropped when the socket closes, rather than risking their
    # misinterpretation as the start of a pipelined next request.
    protocol_version = "HTTP/1.1"
    server_version = "pocvpn-api"

    def log_message(self, fmt, *args):
        # Silence BaseHTTPRequestHandler's default stderr access log (which
        # would print the raw request line verbatim, including query
        # strings). All logging goes through _log_request's explicit,
        # allowlisted fields instead - see that method.
        pass

    def setup(self):
        # Bounds every socket operation on this connection (header read AND
        # rfile.read(content_length) for the body) to a few seconds, so a
        # client that opens a connection, declares a Content-Length, and
        # then never sends the body cannot hold a ThreadingHTTPServer
        # worker thread forever. A timeout here surfaces as socket.timeout
        # (an OSError subclass), caught by _dispatch's generic Exception
        # handler like any other failure - no exception detail is ever
        # exposed to the client either way.
        super().setup()
        self.connection.settimeout(_SOCKET_TIMEOUT_SECONDS)

    # --- method dispatch: every verb routes through one place so 404 vs
    # 405 is a deliberate decision, never http.server's default 501 ---
    def do_POST(self):
        self._dispatch("POST")

    def do_GET(self):
        self._dispatch("GET")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_OPTIONS(self):
        self._dispatch("OPTIONS")

    def _dispatch(self, method):
        self.close_connection = True
        start = time.monotonic()
        self._log_fields = {}
        status_code = HTTPStatus.INTERNAL_SERVER_ERROR
        try:
            if self.path == _PATH_PEERS:
                if method != "POST":
                    status_code = self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
                else:
                    status_code = self._handle_post()
            elif self.path == _PATH_ACTIVATE:
                if method != "POST":
                    status_code = self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
                else:
                    status_code = self._handle_activate()
            elif self.path == _PATH_XRAY_PROFILE:
                if method != "POST":
                    status_code = self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
                else:
                    status_code = self._handle_xray_profile()
            elif self.path == _PATH_INGRESS_PROFILE:
                if method != "POST":
                    status_code = self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
                else:
                    status_code = self._handle_ingress_profile()
            elif self.path == _PATH_MANIFEST:
                if method != "GET":
                    status_code = self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
                else:
                    status_code = self._handle_manifest()
            elif self.path == _PATH_RELAY_HEALTH:
                if method != "GET":
                    status_code = self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
                else:
                    status_code = self._handle_relay_health()
            else:
                status_code = self._error(HTTPStatus.NOT_FOUND, "not_found")
        except Exception:
            # Deliberately no exception message/repr in the log line - only
            # the exception's type name, so a future refactor that ever
            # raises with sensitive text embedded (body, token, ...) can
            # never leak it through this catch-all.
            exc_type = sys.exc_info()[0]
            logger.error("unhandled_exception exc_type=%s", exc_type.__name__ if exc_type else "unknown")
            try:
                status_code = self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")
            except Exception:
                status_code = HTTPStatus.INTERNAL_SERVER_ERROR
        finally:
            self._log_request(method, self.path, int(status_code), time.monotonic() - start)

    # --- POST /v1/peers ---
    def _handle_post(self):
        try:
            return self._handle_post_inner()
        except _RequestError as exc:
            return self._error(exc.status, exc.error_code)

    def _handle_post_inner(self):
        if not self.server.global_limiter.allow("global"):
            raise _RequestError(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")

        # Chunked (or any other) Transfer-Encoding is not supported at all -
        # never attempt to parse it. Checked before Content-Length so a
        # request carrying BOTH headers (a classic request-smuggling shape)
        # is rejected outright, regardless of what Content-Length says.
        if self.headers.get_all("Transfer-Encoding"):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "invalid_request")

        content_length = self._read_content_length()

        content_type = self.headers.get("Content-Type", "")
        if not _is_json_content_type(content_type):
            raise _RequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")

        token = self._require_bearer_token()

        raw_body = self.rfile.read(content_length)
        public_key = self._parse_and_validate_body(raw_body)
        self._log_fields["pubkey_prefix"] = public_key[:8]

        try:
            lookup = tokens.lookup_token(
                token, self.server.config.token_store_path, self.server.config.token_lock_path
            )
        except tokens.TokenLookupError:
            logger.error("token_store_error")
            raise _RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")

        full_digest = tokens.token_digest(token)
        self._log_fields["token_digest"] = full_digest[:8]

        if not lookup.found or lookup.status != tokens.ACTIVE:
            # Unknown and revoked are intentionally indistinguishable -
            # same status, same body, no branch-specific side effect.
            raise _RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")

        if not self.server.per_token_limiter.allow(full_digest):
            raise _RequestError(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")

        if not hmac.compare_digest(lookup.expected_public_key, public_key):
            raise _RequestError(HTTPStatus.FORBIDDEN, "forbidden")

        try:
            outcome = provision.run_provision_peer(
                self.server.config.provision_script_path,
                public_key,
                self.server.config.subprocess_timeout_seconds,
                sudo_path=self.server.config.sudo_path or None,
            )
        except provision.ProvisionError as exc:
            logger.error("provision_error kind=%s", exc.kind)
            if exc.kind == "exhausted":
                raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "subnet_exhausted")
            if exc.kind == "timeout":
                raise _RequestError(HTTPStatus.GATEWAY_TIMEOUT, "provisioning_timeout")
            raise _RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")

        self._log_fields["state"] = outcome.state
        self._log_fields["tunnel_ip"] = outcome.ip

        payload = {
            "client_tunnel_ip": outcome.ip,
            "gateway_public_key": self.server.config.gateway_public_key,
            "gateway_tunnel_ip": self.server.config.gateway_tunnel_ip,
            "endpoint_host": self.server.config.endpoint_host,
            "endpoint_port": self.server.config.endpoint_port,
        }
        status = HTTPStatus.CREATED if outcome.state == provision.CREATED else HTTPStatus.OK
        return self._success(status, payload)

    # --- POST /v1/activate (B8C1) ---
    def _handle_activate(self):
        try:
            return self._handle_activate_inner()
        except _RequestError as exc:
            return self._error(exc.status, exc.error_code)

    def _handle_activate_inner(self):
        if not self.server.config.activation_store_path:
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "activation_not_configured")

        if not self.server.global_limiter.allow("global"):
            raise _RequestError(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")

        if self.headers.get_all("Transfer-Encoding"):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "invalid_request")

        content_length = self._read_content_length()

        content_type = self.headers.get("Content-Type", "")
        if not _is_json_content_type(content_type):
            raise _RequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")

        # Same header shape as /v1/peers' enrollment token - Authorization:
        # Bearer <credential> - reused verbatim, not reimplemented.
        credential = self._require_bearer_token()

        raw_body = self.rfile.read(content_length)
        # Same {"public_key": "..."} body shape and validation as /v1/peers -
        # reused verbatim (_parse_and_validate_body is already path-agnostic).
        public_key = self._parse_and_validate_body(raw_body)
        self._log_fields["pubkey_prefix"] = public_key[:8]

        credential_digest = activations.credential_digest(credential)
        self._log_fields["activation_digest"] = credential_digest[:8]

        if not self.server.per_token_limiter.allow(credential_digest):
            raise _RequestError(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")

        # B8C1C: ONE call does decide/reserve -> run_provision_peer ->
        # finalize-or-rollback, all inside a single per-activation OS lock
        # (activations.per_activation_lock, keyed by credential digest) that
        # serializes the ENTIRE logical operation - including the external,
        # irreversible AWG provisioning side effect itself - against any
        # other concurrent request for the SAME activation. See
        # activations.provision_with_activation's own docstring for why
        # this is what actually closes the max_devices race at the real
        # gateway-peer level, not just in the JSON store's bookkeeping.
        try:
            result = activations.provision_with_activation(
                credential, public_key,
                self.server.config.activation_store_path,
                self.server.config.activation_lock_path,
                self.server.config.provision_script_path,
                self.server.config.subprocess_timeout_seconds,
                sudo_path=self.server.config.sudo_path or None,
            )
        except activations.ActivationStoreError:
            logger.error("activation_store_error")
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "activation_store_unavailable")

        decision = result.decision
        self._log_fields["activation_outcome"] = decision.outcome

        if decision.outcome == activations.INVALID:
            # Unknown credential and a credential that hashes to no record
            # are intentionally indistinguishable - same status, same body.
            raise _RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")
        if decision.outcome == activations.REVOKED_OUTCOME:
            raise _RequestError(HTTPStatus.FORBIDDEN, "revoked")
        if decision.outcome == activations.EXPIRED:
            raise _RequestError(HTTPStatus.FORBIDDEN, "expired")
        if decision.outcome == activations.DEVICE_LIMIT:
            raise _RequestError(HTTPStatus.FORBIDDEN, "device_limit_reached")

        # decision.outcome is BOUND_NEW or BOUND_EXISTING here - either way
        # this device was durably entitled at decide time, and
        # provision_with_activation already attempted the SAME provisioning
        # boundary /v1/peers uses. No AWG file mutation, no shelling out, is
        # ever reimplemented here.
        if result.provision_error is not None:
            exc = result.provision_error
            logger.error("provision_error kind=%s", exc.kind)
            # Rollback (if this request owned a reservation) already
            # happened inside provision_with_activation, still under the
            # per-activation lock - see its own docstring.
            if exc.kind == "exhausted":
                raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "subnet_exhausted")
            if exc.kind == "timeout":
                raise _RequestError(HTTPStatus.GATEWAY_TIMEOUT, "provisioning_timeout")
            raise _RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")

        outcome = result.provision_outcome
        self._log_fields["state"] = outcome.state
        self._log_fields["tunnel_ip"] = outcome.ip

        finalize_result = result.finalize_result
        if not finalize_result.confirmed:
            # B8C1B: this key's originally-reserved capacity was legitimately
            # reused by a different key while this request's provisioning
            # subprocess was in flight - the device WAS actually provisioned
            # by this request, but recording it now would exceed
            # max_devices, so it is deliberately not recorded and this
            # response must not report success.
            raise _RequestError(HTTPStatus.FORBIDDEN, "device_limit_reached")

        if finalize_result.status != activations.ACTIVE:
            # The device WAS actually provisioned (finalize above still
            # durably recorded it - un-provisioning it is out of scope for
            # this slice), but this specific response must not report
            # success for an activation that is revoked by now.
            raise _RequestError(HTTPStatus.FORBIDDEN, "revoked")

        payload = {
            "client_tunnel_ip": outcome.ip,
            "gateway_public_key": self.server.config.gateway_public_key,
            "gateway_tunnel_ip": self.server.config.gateway_tunnel_ip,
            "endpoint_host": self.server.config.endpoint_host,
            "endpoint_port": self.server.config.endpoint_port,
        }
        # Always 200 - both a new bind and idempotent re-use of an
        # already-bound device are equally "success" here (unlike /v1/peers'
        # 201-vs-200 distinction, which is about peer allocation, not
        # device entitlement).
        return self._success(HTTPStatus.OK, payload)

    # --- POST /v1/xray-profile (B8K2) ---
    def _handle_xray_profile(self):
        try:
            return self._handle_xray_profile_inner()
        except _RequestError as exc:
            return self._error(exc.status, exc.error_code)

    def _handle_xray_profile_inner(self):
        cfg = self.server.config
        if not (cfg.activation_store_path and cfg.xray_store_path and cfg.xray_server_port):
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "xray_not_configured")

        if not self.server.global_limiter.allow("global"):
            raise _RequestError(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")

        if self.headers.get_all("Transfer-Encoding"):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "invalid_request")

        content_length = self._read_content_length()

        content_type = self.headers.get("Content-Type", "")
        if not _is_json_content_type(content_type):
            raise _RequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")

        # Same Authorization: Bearer <activation credential> as /v1/activate -
        # this is the SAME activation, never a separate credential/token type.
        credential = self._require_bearer_token()

        raw_body = self.rfile.read(content_length)
        # {"public_key": "...", "transport": "reality"|"tls"} - "transport" is
        # OPTIONAL and defaults to "reality" (B8O2), so every existing caller
        # of this endpoint (pre-B8O2 Android, this file's own pre-existing
        # tests) is byte-for-byte unaffected. This MUST be the same AWG public
        # key already bound via /v1/activate; the server issues the VLESS
        # identity, the client never sends one (see xray_provisioning.py's
        # own eligibility gate) - the SAME identity is reused for either
        # transport, never a second one.
        public_key, transport = self._parse_and_validate_xray_profile_body(raw_body)
        self._log_fields["pubkey_prefix"] = public_key[:8]
        self._log_fields["xray_transport"] = transport

        if transport == "tls" and not cfg.xray_tls_server_port:
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "xray_tls_not_configured")

        credential_digest = activations.credential_digest(credential)
        self._log_fields["activation_digest"] = credential_digest[:8]

        if not self.server.per_token_limiter.allow(credential_digest):
            raise _RequestError(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")

        if not cfg.xray_activation_wrapper_path:
            # The activation boundary (B8K2A) is a separate completeness
            # group from the client-facing fields checked above - see
            # config.py's own validation. Both must be configured before
            # this endpoint can ever return a profile, since a profile is
            # never usable without a confirmed activation.
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "xray_not_configured")

        try:
            result = xray_activation.provision_and_activate(credential, public_key, cfg)
        except xray_provisioning.XrayStoreError:
            logger.error("xray_store_error")
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "xray_store_unavailable")
        except xray_activation.XrayActivationNotConfigured:
            logger.error("xray_activation_not_configured")
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "xray_not_configured")

        identity_outcome = result.identity_outcome
        self._log_fields["xray_outcome"] = identity_outcome.outcome

        if identity_outcome.outcome == xray_provisioning.NOT_ELIGIBLE_UNKNOWN:
            # Unknown credential and a credential that hashes to no record
            # are intentionally indistinguishable - same status, same body,
            # matching /v1/activate's own rule.
            raise _RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")
        if identity_outcome.outcome == xray_provisioning.NOT_ELIGIBLE_REVOKED:
            raise _RequestError(HTTPStatus.FORBIDDEN, "revoked")
        if identity_outcome.outcome == xray_provisioning.NOT_ELIGIBLE_EXPIRED:
            raise _RequestError(HTTPStatus.FORBIDDEN, "expired")
        if identity_outcome.outcome == xray_provisioning.NOT_ELIGIBLE_DEVICE_NOT_BOUND:
            # This exact device must complete POST /v1/activate first - no
            # Xray identity is ever issued for a device this activation has
            # not already durably entitled.
            raise _RequestError(HTTPStatus.FORBIDDEN, "device_not_bound")

        # B8K2A - the false-success window this whole transaction exists to
        # close: the identity may be durably written/retrieved above, but it
        # is NEVER reported as usable unless the running Xray process has
        # actually been confirmed activated for it, in this SAME request.
        # See xray_provisioning.provision_and_activate_identity's own docs
        # for why a failed activation never rolls back a newly-minted
        # identity - it stays durable and recoverable, just not yet usable.
        self._log_fields["xray_activated"] = bool(result.activated)
        if not result.activated:
            error = result.activation_error
            kind = getattr(error, "kind", "internal")
            logger.error("xray_activation_failed kind=%s", kind)
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "xray_activation_failed")

        # Client-safe fields only - never the REALITY private key, never
        # server-internal config, never the activation digest, never any
        # other user's/device's identity. Snake_case keys, matching the
        # existing /v1/activate and /v1/peers response convention.
        if transport == "tls":
            # B8O2 - TLS needs materially fewer fields than REALITY (no
            # flow/reality_public_key/short_id - see
            # docs/B8O0_TLS_TCP_FALLBACK_AUDIT.md's own "simpler credential
            # shape" finding) - never hand out REALITY-only fields for a TLS
            # profile, even though this same process also serves REALITY.
            payload = {
                "server_address": cfg.endpoint_host,
                "server_port": cfg.xray_tls_server_port,
                "uuid": identity_outcome.vless_uuid,
                "server_name": cfg.xray_tls_server_name,
                "fingerprint": cfg.xray_tls_fingerprint,
            }
        else:
            payload = {
                "server_address": cfg.endpoint_host,
                "server_port": cfg.xray_server_port,
                "uuid": identity_outcome.vless_uuid,
                "flow": cfg.xray_flow,
                "server_name": cfg.xray_server_name,
                "fingerprint": cfg.xray_fingerprint,
                "reality_public_key": cfg.xray_reality_public_key,
                "short_id": cfg.xray_short_id,
            }
        # Always 200 - a new issuance and an idempotent retry are equally
        # "success" here, same rule /v1/activate already uses for its own
        # new-bind-vs-existing-bind distinction - but ONLY once activation
        # is confirmed (see the check above).
        return self._success(HTTPStatus.OK, payload)

    # --- POST /v1/ingress-profile (B25 task G) ---
    def _handle_ingress_profile(self):
        try:
            return self._handle_ingress_profile_inner()
        except _RequestError as exc:
            return self._error(exc.status, exc.error_code)

    def _handle_ingress_profile_inner(self):
        """B25 (task G) - the ingress-role counterpart of
        _handle_xray_profile_inner: SAME activation credential/device
        public key, SAME activations.py entitlement decision, SAME
        xray_provisioning.py identity store (task G's own "reuse existing
        activation authentication, revocation and quota discipline" - no
        second identity system for an ingress). Reachable ONLY on a
        deployment instance whose ingress_config is configured (see
        ingress_config.load_ingress_config's own docs) - every ordinary
        gateway deployment (self.server.ingress_config is None) gets 503,
        exactly like every other not-configured endpoint.

        The response is CLIENT-SAFE ONLY: ingress host/port, this device's
        own vless uuid, the client-facing REALITY/TLS public connection
        facts, and a profile_version/issued_at/expires_at window - NEVER
        the ingress's own REALITY private key, NEVER the ingress->exit
        upstream relay uuid, NEVER another device's credential (task
        requirement G/M's own exclusion list).
        """
        ingress_cfg = self.server.ingress_config
        if ingress_cfg is None:
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "ingress_not_configured")

        if not self.server.global_limiter.allow("global"):
            raise _RequestError(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")

        if self.headers.get_all("Transfer-Encoding"):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "invalid_request")

        content_length = self._read_content_length()

        content_type = self.headers.get("Content-Type", "")
        if not _is_json_content_type(content_type):
            raise _RequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")

        credential = self._require_bearer_token()

        raw_body = self.rfile.read(content_length)
        public_key, transport = self._parse_and_validate_xray_profile_body(raw_body)
        self._log_fields["pubkey_prefix"] = public_key[:8]
        self._log_fields["ingress_transport"] = transport
        self._log_fields["ingress_endpoint_id"] = ingress_cfg.ingress_endpoint_id

        if transport == "tls" and not ingress_cfg.ingress_tls_server_port:
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "ingress_tls_not_configured")

        credential_digest = activations.credential_digest(credential)
        self._log_fields["activation_digest"] = credential_digest[:8]

        if not self.server.per_token_limiter.allow(credential_digest):
            raise _RequestError(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")

        try:
            result = ingress_activation.provision_and_activate(credential, public_key, ingress_cfg)
        except xray_provisioning.XrayStoreError:
            logger.error("ingress_store_error")
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "ingress_store_unavailable")
        except ingress_activation.IngressActivationNotConfigured:
            logger.error("ingress_activation_not_configured")
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "ingress_not_configured")

        identity_outcome = result.identity_outcome
        self._log_fields["ingress_outcome"] = identity_outcome.outcome

        if identity_outcome.outcome == xray_provisioning.NOT_ELIGIBLE_UNKNOWN:
            raise _RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")
        if identity_outcome.outcome == xray_provisioning.NOT_ELIGIBLE_REVOKED:
            raise _RequestError(HTTPStatus.FORBIDDEN, "revoked")
        if identity_outcome.outcome == xray_provisioning.NOT_ELIGIBLE_EXPIRED:
            raise _RequestError(HTTPStatus.FORBIDDEN, "expired")
        if identity_outcome.outcome == xray_provisioning.NOT_ELIGIBLE_DEVICE_NOT_BOUND:
            raise _RequestError(HTTPStatus.FORBIDDEN, "device_not_bound")

        self._log_fields["ingress_activated"] = bool(result.activated)
        if not result.activated:
            error = result.activation_error
            kind = getattr(error, "kind", "internal")
            logger.error("ingress_activation_failed kind=%s", kind)
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "ingress_activation_failed")

        issued_at_epoch_seconds = int(time.time())
        expires_at_epoch_seconds = (
            issued_at_epoch_seconds + ingress_cfg.ingress_profile_ttl_seconds
            if ingress_cfg.ingress_profile_ttl_seconds
            else None
        )

        if transport == "tls":
            payload = {
                "ingress_endpoint_id": ingress_cfg.ingress_endpoint_id,
                "server_address": ingress_cfg.ingress_endpoint_host,
                "server_port": ingress_cfg.ingress_tls_server_port,
                "uuid": identity_outcome.vless_uuid,
                "server_name": ingress_cfg.ingress_tls_server_name,
                "fingerprint": ingress_cfg.ingress_tls_fingerprint,
            }
        else:
            payload = {
                "ingress_endpoint_id": ingress_cfg.ingress_endpoint_id,
                "server_address": ingress_cfg.ingress_endpoint_host,
                "server_port": ingress_cfg.ingress_server_port,
                "uuid": identity_outcome.vless_uuid,
                "flow": ingress_cfg.ingress_flow,
                "server_name": ingress_cfg.ingress_server_name,
                "fingerprint": ingress_cfg.ingress_fingerprint,
                "reality_public_key": ingress_cfg.ingress_reality_public_key,
                "short_id": ingress_cfg.ingress_short_id,
            }
        payload["profile_version"] = 1
        payload["issued_at"] = issued_at_epoch_seconds
        payload["expires_at"] = expires_at_epoch_seconds
        # B27 - echoes this deployment's own configured ingress_kind, upper-
        # cased to match net.pocvpn.client.reachability.IngressKind's exact
        # enum constant names (task E - the client cross-checks this
        # against its own pinned expectation before ever persisting
        # anything; a mismatch here is exactly the "frontend/origin/
        # backend confusion" that must fail closed).
        payload["ingress_kind"] = ingress_cfg.ingress_kind.upper()

        # B26 (task B/C) - mint the real end-to-end proof coordinates this
        # device's IngressClientProfile.endToEndProbeUrl/endToEndProbeToken
        # will carry (see relay/IngressProfile.kt's own docs). historyPathId
        # is computed the SAME way PathCandidate.Relayed.historyPathId is on
        # the client - see _TRANSPORT_KIND_NAMES's own docs - never a value
        # invented independently that could drift from what the client
        # itself checks the probe response against
        # (HttpRelayEndToEndProbe.probe: `body.contains(plan.historyPathId)`).
        exit_transport_name = _TRANSPORT_KIND_NAMES[ingress_cfg.ingress_upstream_transport]
        history_path_id = (
            f"{ingress_cfg.ingress_endpoint_id}:{_TRANSPORT_KIND_NAMES[transport]}->"
            f"{ingress_cfg.ingress_exit_endpoint_id}:{exit_transport_name}"
        )
        try:
            with open(ingress_cfg.ingress_probe_hmac_secret_file, "rb") as handle:
                probe_secret = handle.read().strip()
            probe_token = relay_probe_token.mint(
                probe_secret, history_path_id, public_key, issued_at_epoch_seconds, ingress_cfg.ingress_probe_ttl_seconds,
            )
        except (OSError, ValueError) as exc:
            logger.error("probe_token_mint_failed exc_type=%s", exc.__class__.__name__)
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "ingress_activation_failed")
        finally:
            probe_secret = None  # never held beyond this one mint() call

        payload["probe_url"] = f"https://{ingress_cfg.ingress_exit_probe_host}{_PATH_RELAY_HEALTH}"
        payload["probe_token"] = probe_token
        return self._success(HTTPStatus.OK, payload)

    # --- GET /v1/relay-health (B26 task B) ---
    def _handle_relay_health(self):
        try:
            return self._handle_relay_health_inner()
        except _RequestError as exc:
            return self._error(exc.status, exc.error_code)

    def _handle_relay_health_inner(self):
        """The real EXIT-side proof [HttpRelayEndToEndProbe] calls, over
        whatever route the OS resolves at request time - since Android only
        ever calls this AFTER its ingress transport handshake succeeds, a
        genuine 200 here is only reachable at all when traffic actually
        traversed client -> ingress -> exit (task B's own "must prove real
        traffic reached the EXIT" - this process being reachable via HTTP
        IS that proof, the same way GET /v1/manifest's mere reachability is
        never claimed to prove anything about content). NEVER a generic
        `/health = 200` - reachability alone is insufficient; the request
        must additionally carry a valid, non-expired, correctly-signed
        [relay_probe_token] bound to a specific relayed path identity, or
        this fails closed with 401 - see that module's own docs.

        Deliberately stateless: no store lookup, no revocation list at
        verification time - only the shared HMAC secret this exit was
        provisioned with (see AppConfig.relay_probe_hmac_secret_file). Never
        logs the raw token - only its digest, same discipline
        activations.credential_digest's callers already use.
        """
        if not self.server.config.relay_probe_hmac_secret_file:
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "relay_health_not_configured")

        if not self.server.global_limiter.allow("global"):
            raise _RequestError(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")

        token = self._require_bearer_token()
        self._log_fields["relay_probe_digest"] = tokens.token_digest(token)[:8]

        try:
            with open(self.server.config.relay_probe_hmac_secret_file, "rb") as handle:
                secret = handle.read().strip()
            claims = relay_probe_token.verify(secret, token, int(time.time()))
        except (OSError, relay_probe_token.ProbeTokenError):
            raise _RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")
        finally:
            secret = None  # never held beyond this one verify() call

        self._log_fields["relay_probe_path"] = claims.history_path_id
        # The response body echoes the token's OWN signed path claim (never
        # anything client-supplied) - this is what makes it "bound to the
        # current relay attempt/path identity" (task B) rather than a
        # generic ack a client could reuse to claim a DIFFERENT path
        # succeeded: the path identity comes from the verified signature,
        # not from the request.
        payload = {"status": "ok", "path": claims.history_path_id}
        return self._success(HTTPStatus.OK, payload)

    # --- GET /v1/manifest (B12) ---
    def _handle_manifest(self):
        try:
            return self._handle_manifest_inner()
        except _RequestError as exc:
            return self._error(exc.status, exc.error_code)

    def _handle_manifest_inner(self):
        """Serves the ALREADY-SIGNED manifest artifact byte-for-byte, verbatim.

        This process never signs, never parses, never validates the
        manifest's own contents - it is exactly as trustworthy as any other
        HTTPS response and MUST be independently verified by the client
        (Ed25519ManifestVerifier) before ever being trusted; this endpoint's
        only job is serving bytes an operator placed on disk offline. No
        auth is required - a signed manifest is meant for broad
        distribution, the same way a TLS certificate chain is public - its
        trust comes from the signature, never from who fetched it or how.
        """
        if not self.server.config.manifest_path:
            raise _RequestError(HTTPStatus.SERVICE_UNAVAILABLE, "manifest_not_configured")

        if not self.server.global_limiter.allow("global"):
            raise _RequestError(HTTPStatus.TOO_MANY_REQUESTS, "rate_limited")

        try:
            with open(self.server.config.manifest_path, "rb") as f:
                body = f.read(_MAX_MANIFEST_BYTES + 1)
        except OSError:
            logger.error("manifest_read_error")
            raise _RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")

        if len(body) > _MAX_MANIFEST_BYTES:
            # An operator-placed artifact should never actually be this
            # large (see ManifestCanonicalizer's own MAX_ENDPOINTS/
            # MAX_TRANSPORTS caps) - refuse rather than stream something
            # implausible, same discipline as every other size bound in
            # this codebase.
            logger.error("manifest_too_large")
            raise _RequestError(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error")

        self._log_fields["manifest_bytes"] = len(body)
        return self._write_binary(HTTPStatus.OK, body)

    def _write_binary(self, status, body):
        self.send_response(int(status))
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        return int(status)

    def _require_bearer_token(self):
        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith(_BEARER_PREFIX):
            raise _RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")
        token = auth_header[len(_BEARER_PREFIX):]
        if not token:
            raise _RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")
        return token

    def _read_content_length(self):
        # get_all(), NOT get(): .get() silently returns only the first of
        # several same-named headers, which would let a duplicate
        # Content-Length through unnoticed - exactly the ambiguous framing
        # this must fail closed on, even when every duplicate value is
        # identical.
        values = self.headers.get_all("Content-Length")
        if not values:
            raise _RequestError(HTTPStatus.LENGTH_REQUIRED, "length_required")
        if len(values) > 1:
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        raw = values[0].strip()
        if not _CONTENT_LENGTH_RE.match(raw):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        value = int(raw)  # safe: _CONTENT_LENGTH_RE already guarantees ASCII digits only
        if value > _MAX_BODY_BYTES:
            raise _RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "payload_too_large")
        return value

    def _parse_and_validate_body(self, raw_body):
        try:
            parsed = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_json")

        if not isinstance(parsed, dict):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        if set(parsed.keys()) != {"public_key"}:
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        public_key = parsed["public_key"]
        if not isinstance(public_key, str):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        if not is_valid_wg_public_key(public_key):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "invalid_public_key")

        return public_key

    def _parse_and_validate_xray_profile_body(self, raw_body):
        """B8O2 - /v1/xray-profile's own body shape: {"public_key": "..."}
        (required, same validation as every other endpoint) plus an OPTIONAL
        {"transport": "reality"|"tls"} - defaulting to "reality" when absent
        so every pre-B8O2 caller's exact request body still parses
        identically. Returns (public_key, transport)."""
        try:
            parsed = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_json")

        if not isinstance(parsed, dict):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        allowed_keys = {"public_key", "transport"}
        if not parsed.keys() or "public_key" not in parsed or not (set(parsed.keys()) <= allowed_keys):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        public_key = parsed["public_key"]
        if not isinstance(public_key, str) or not is_valid_wg_public_key(public_key):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "invalid_public_key")

        transport = parsed.get("transport", "reality")
        if transport not in ("reality", "tls"):
            raise _RequestError(HTTPStatus.BAD_REQUEST, "malformed_request")

        return public_key, transport

    # --- response helpers ---
    def _write_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        return int(status)

    def _error(self, status, error_code):
        return self._write_json(status, {"error": error_code})

    def _success(self, status, payload):
        return self._write_json(status, payload)

    # --- logging: explicit allowlisted fields only, never raw
    # headers/body/token - see module docstring and _log_fields sites
    # above, which are the ONLY places allowed to populate this dict ---
    def _log_request(self, method, path, status_code, elapsed_seconds):
        fields = getattr(self, "_log_fields", {}) or {}
        extra = " ".join(f"{key}={value}" for key, value in fields.items())
        logger.info(
            "request method=%s path=%s status=%s latency_ms=%.2f %s",
            method,
            path,
            status_code,
            elapsed_seconds * 1000.0,
            extra,
        )
