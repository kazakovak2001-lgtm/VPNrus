"""Admin authenticator for pocvpn-api M3 admin endpoints.

Provides password verification, session management with expiration,
CSRF tokens, rate limiting, and secure cookie handling.

Security features:
- File-based secret: the admin password itself, exactly 32 printable
  ASCII characters (one trailing newline tolerated) - see read_admin_secret
- HMAC password verification
- Server-side session store with expiration
- HttpOnly, SameSite=Strict cookies
- CSRF token protection
- Rate limiting on login attempts
- Process-local session storage (reset on restart)
"""

import hmac
import hashlib
import secrets
import threading
import time
from typing import Dict, Tuple, Optional

from .auth_ratelimit import AuthFailureLimiter


class ConfigError(Exception):
    """Raised for configuration errors."""
    pass


ADMIN_SECRET_LENGTH = 32


def read_admin_secret(path: str) -> bytes:
    """Read and validate the admin secret file - the single validator used
    by both config.load_config (startup) and AdminAuthenticator.

    Format: the admin password itself, exactly ADMIN_SECRET_LENGTH printable
    ASCII characters (0x21-0x7e). One trailing newline (LF or CRLF) is
    tolerated so `head -c 32 ... > file; echo >> file` style files work;
    nothing else is stripped. Error messages never include file content.

    Raises:
        ValueError: path is not absolute.
        ConfigError: blank path, missing/unreadable file, wrong length or
            non-printable content.
    """
    import os

    if not path:
        raise ConfigError("Admin secret file not configured")
    if not os.path.isabs(path):
        raise ValueError(f"admin secret file must be absolute: {path}")
    if not os.path.isfile(path):
        raise ConfigError(f"admin secret file does not exist: {path}")
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise ConfigError(f"admin secret file cannot be read: {type(exc).__name__}")
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    if len(raw) != ADMIN_SECRET_LENGTH:
        raise ConfigError(
            f"admin secret file must contain exactly {ADMIN_SECRET_LENGTH} bytes, got {len(raw)}"
        )
    if any(b < 0x21 or b > 0x7E for b in raw):
        raise ConfigError("admin secret file must contain only printable ASCII characters")
    return raw


class AdminAuthenticator:
    """Authenticates admin users and manages server-side sessions.

    Uses a shared secret file for password verification and maintains
    HTTP-only, SameSite=Strict cookies with CSRF tokens for session
    management.
    """

    def __init__(self, secret_file: str, viewer_secret_file: str = "") -> None:
        """Initialize the admin authenticator.

        Args:
            secret_file: Path to the file containing the 32-byte admin secret.

        Raises:
            ConfigError: If the secret file is missing, unreadable, or
                contains invalid content.
        """
        self._secret_file = secret_file
        self._secret_hash = self._load_secret_hash()
        # Optional second credential for the read-only "viewer" role. It
        # must differ from the admin secret, otherwise the role a login
        # receives would be ambiguous.
        self._viewer_hash = None
        if viewer_secret_file:
            self._viewer_hash = hashlib.sha256(read_admin_secret(viewer_secret_file)).digest()
            if hmac.compare_digest(self._viewer_hash, self._secret_hash):
                raise ConfigError("admin viewer secret must differ from the admin secret")

        # In-memory session store: session_id -> session_data
        self._sessions: Dict[str, Dict] = {}
        self._sessions_lock = threading.Lock()

        # Rate limiter for brute-force protection — delegates to the
        # shared AuthFailureLimiter implementation (auth_ratelimit.py).
        self._auth_failure_limiter = AuthFailureLimiter(
            per_source_max=10,
            per_account_max=30,
            global_max=100,
            window_seconds=600.0,
            clock=time.monotonic,
            max_entries=10_000,
        )

        # CSRF token cache
        self._csrf_token_cache: Dict[str, str] = {}

    def _load_secret_hash(self) -> bytes:
        """Load the admin secret (see read_admin_secret) and return its
        SHA-256 digest; the plaintext is never kept on the instance."""
        return hashlib.sha256(read_admin_secret(self._secret_file)).digest()

    def _create_session(self, source_ip: str, role: str = "admin") -> Tuple[str, str]:
        """Create a new admin session.

        Args:
            source_ip: The source IP address for rate limiting.

        Returns:
            A tuple of (session_id, csrf_token).
        """
        session_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)

        with self._sessions_lock:
            expires_at = time.monotonic() + 28800  # 8 hours
            self._sessions[session_id] = {
                "created_at": time.monotonic(),
                "expires_at": expires_at,
                "source_ip": source_ip,
                "role": role,
                "csrf_token": csrf_token,
                "last_seen": time.monotonic(),
            }
            self._csrf_token_cache[session_id] = csrf_token

        return session_id, csrf_token

    def _cleanup_expired_sessions(self) -> None:
        """Remove expired sessions from the session store."""
        now = time.monotonic()
        with self._sessions_lock:
            expired_ids = [
                sid for sid, data in self._sessions.items()
                if data["expires_at"] <= now
            ]
            for sid in expired_ids:
                del self._sessions[sid]
                self._csrf_token_cache.pop(sid, None)

    def verify_password_and_create_session(
        self,
        password: str,
        source_ip: str,
    ) -> Tuple[bool, Optional[Tuple[str, str]], Optional[str]]:
        """Verify admin password and create a session if valid.

        Args:
            password: The password to verify (raw text).
            source_ip: The source IP address for rate limiting.

        Returns:
            A tuple of (success, (session_id, csrf_token), error_message).
        """
        # Rate limit check first (fail-closed)
        allowed, _retry_after = self._auth_failure_limiter.check_admission(
            source_ip, "admin"
        )
        if not allowed:
            return False, None, "rate_limited"

        # A non-string / empty / oversized / unencodable password is a
        # failed attempt like any other - it is counted, never a free probe.
        try:
            if not isinstance(password, str) or not password or len(password) > 1024:
                raise ValueError
            password_bytes = password.encode("utf-8")
        except (ValueError, UnicodeEncodeError):
            self._auth_failure_limiter.record_auth_failure(source_ip, "admin")
            return False, None, "invalid_password"

        # Verify password via constant-time digest comparison
        password_hash = hashlib.sha256(password_bytes).digest()
        # Both comparisons always run (no short-circuit on the first match).
        is_admin = hmac.compare_digest(password_hash, self._secret_hash)
        is_viewer = self._viewer_hash is not None and hmac.compare_digest(password_hash, self._viewer_hash)
        if not (is_admin or is_viewer):
            self._auth_failure_limiter.record_auth_failure(source_ip, "admin")
            return False, None, "unauthorized"

        # Verified success: clear the shared account counter (atomic under
        # the limiter's own lock; per-source and global counters are kept).
        self._auth_failure_limiter.reset_account_failures("admin")
        session_id, csrf_token = self._create_session(source_ip, "admin" if is_admin else "viewer")
        return True, (session_id, csrf_token), None

    def validate_session_and_csrf(
        self,
        session_id: str,
        csrf_token: Optional[str] = None,
    ) -> Tuple[bool, Optional[Dict]]:
        """Validate a session and optionally verify a CSRF token.

        Args:
            session_id: The session identifier.
            csrf_token: Optional CSRF token to validate against.

        Returns:
            A tuple of (is_valid, session_data).
        """
        self._cleanup_expired_sessions()

        with self._sessions_lock:
            session_data = self._sessions.get(session_id)
            if not session_data:
                return False, None

            session_data["last_seen"] = time.monotonic()

            # Validate CSRF token if provided
            if csrf_token is not None:
                expected_csrf = session_data.get("csrf_token")
                if not expected_csrf or not hmac.compare_digest(
                    csrf_token.encode(), expected_csrf.encode()
                ):
                    return False, session_data

            return True, session_data

    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a session (logout).

        Args:
            session_id: The session identifier to invalidate.

        Returns:
            True if the session was found and invalidated, False otherwise.
        """
        with self._sessions_lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                self._csrf_token_cache.pop(session_id, None)
                return True
            return False

    def get_session_info(self, session_id: str) -> Optional[Dict]:
        """Get information about a session.

        Args:
            session_id: The session identifier.

        Returns:
            Session information or None if session doesn't exist.
        """
        self._cleanup_expired_sessions()
        with self._sessions_lock:
            return self._sessions.get(session_id)

    def generate_csrf_token(self, session_id: str) -> Optional[str]:
        """Generate a new CSRF token for a session.

        Args:
            session_id: The session identifier.

        Returns:
            A new CSRF token or None if session doesn't exist.
        """
        with self._sessions_lock:
            if session_id in self._sessions:
                new_csrf = secrets.token_urlsafe(32)
                self._sessions[session_id]["csrf_token"] = new_csrf
                self._csrf_token_cache[session_id] = new_csrf
                return new_csrf
        return None

    def get_rate_limit_info(self) -> Dict[str, int]:
        """Get current rate limit state (for monitoring).

        Returns:
            Dictionary with current counter values.
        """
        now = time.monotonic()
        with self._auth_failure_limiter._lock:
            return {
                "per_source_windows": len(self._auth_failure_limiter._source_windows),
                "per_account_windows": len(self._auth_failure_limiter._account_windows),
                "global_windows": len(self._auth_failure_limiter._global_windows),
                "sessions": len(self._sessions),
            }
