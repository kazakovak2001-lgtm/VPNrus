"""Admin authenticator for pocvpn-api M3 admin endpoints.

Provides password verification, session management with expiration,
CSRF tokens, rate limiting, and secure cookie handling.

Security features:
- File-based secret (32 raw bytes)
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


class AdminAuthenticator:
    """Authenticates admin users and manages server-side sessions.

    Uses a shared secret file for password verification and maintains
    HTTP-only, SameSite=Strict cookies with CSRF tokens for session
    management.
    """

    def __init__(self, secret_file: str) -> None:
        """Initialize the admin authenticator.

        Args:
            secret_file: Path to the file containing the 32-byte admin secret.

        Raises:
            ConfigError: If the secret file is missing, unreadable, or
                contains invalid content.
        """
        self._secret_file = secret_file
        self._secret_hash = self._load_secret_hash()

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
        """Load and validate the admin secret file.

        Returns:
            The raw secret bytes as a hex-encoded SHA256 hash.

        Raises:
            ConfigError: If the file is missing, unreadable, or invalid.
        """
        import os

        if not self._secret_file:
            raise ConfigError("Admin secret file not configured")

        if not os.path.isabs(self._secret_file):
            raise ValueError(f"admin secret file must be absolute: {self._secret_file}")

        if not os.path.isfile(self._secret_file):
            raise ConfigError(f"admin secret file does not exist: {self._secret_file}")

        if not os.access(self._secret_file, os.R_OK):
            raise ConfigError(f"admin secret file not readable: {self._secret_file}")

        try:
            with open(self._secret_file, "rb") as f:
                raw_secret = f.read().strip()
        except OSError as e:
            raise ConfigError(f"admin secret file cannot be read: {e}")

        if len(raw_secret) != 32:
            raise ConfigError(
                f"admin secret file must contain exactly 32 bytes, got {len(raw_secret)}"
            )

        # SHA256 hash of the secret
        return hashlib.sha256(raw_secret).digest()

    def _create_session(self, source_ip: str) -> Tuple[str, str]:
        """Create a new admin session.

        Args:
            source_ip: The source IP address for rate limiting.

        Returns:
            A tuple of (session_id, csrf_token).
        """
        session_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)

        with self._sessions_lock:
            expires_at = time.time() + 28800  # 8 hours
            self._sessions[session_id] = {
                "created_at": time.time(),
                "expires_at": expires_at,
                "source_ip": source_ip,
                "csrf_token": csrf_token,
                "last_seen": time.time(),
            }
            self._csrf_token_cache[session_id] = csrf_token

        return session_id, csrf_token

    def _cleanup_expired_sessions(self) -> None:
        """Remove expired sessions from the session store."""
        now = time.time()
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
        allowed, retry_after = self._auth_failure_limiter.check_admission(
            source_ip, "admin"
        )
        if not allowed:
            return False, None, f"rate_limited, try again after {retry_after:.1f}s"

        # Verify password via HMAC comparison
        password_hash = hashlib.sha256(password.encode()).digest()
        if not hmac.compare_digest(password_hash, self._secret_hash):
            self._auth_failure_limiter.record_auth_failure(source_ip, "admin")
            return False, None, "unauthorized"

        # Password is valid, create session
        session_id, csrf_token = self._create_session(source_ip)
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

            session_data["last_seen"] = time.time()

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
        now = time.time()
        with self._auth_failure_limiter._lock:
            return {
                "per_source_windows": len(self._auth_failure_limiter._source_windows),
                "per_account_windows": len(self._auth_failure_limiter._account_windows),
                "global_windows": len(self._auth_failure_limiter._global_windows),
                "sessions": len(self._sessions),
            }


class AuthFailureLimiter:
    """Tracks verified authentication failures separately from admission."""

    def __init__(
        self,
        per_source_max: int,
        per_account_max: int,
        global_max: int,
        window_seconds: float,
        clock,
        max_entries: int = 10_000,
    ) -> None:
        self._per_source_max = per_source_max
        self._per_account_max = per_account_max
        self._global_max = global_max
        self._window_seconds = float(window_seconds)
        self._clock = clock
        self._max_entries = max_entries

        self._lock = threading.Lock()
        self._source_windows: Dict[str, Tuple[float, int]] = {}
        self._account_windows: Dict[str, Tuple[float, int]] = {}
        self._global_key = "_global_auth_"
        self._global_windows: Dict[str, Tuple[float, int]] = {
            self._global_key: (0.0, 0)
        }

    def check_admission(self, source_key: str, account_key: str) -> Tuple[bool, Optional[float]]:
        """May a source attempt authentication?"""
        if not isinstance(source_key, str) or not isinstance(account_key, str):
            return False, None

        norm_src = self._normalize(source_key)
        norm_acct = self._normalize(account_key)

        now = self._clock()
        with self._lock:
            self._prune(now)

            src_start, src_count = self._source_windows.get(norm_src, (now, 0))
            if now - src_start >= self._window_seconds:
                src_start, src_count = now, 0
            src_would_exceed = src_count + 1 > self._per_source_max

            acct_start, acct_count = self._account_windows.get(norm_acct, (now, 0))
            if now - acct_start >= self._window_seconds:
                acct_start, acct_count = now, 0
            acct_would_exceed = acct_count + 1 > self._per_account_max

            glob_start, glob_count = self._global_windows[self._global_key]
            if now - glob_start >= self._window_seconds:
                glob_start, glob_count = now, 0
            glob_would_exceed = glob_count + 1 > self._global_max

            if src_would_exceed or acct_would_exceed or glob_would_exceed:
                retry_after = max(
                    max(0.0, self._window_seconds - (now - src_start)) if src_would_exceed else 0.0,
                    max(0.0, self._window_seconds - (now - acct_start)) if acct_would_exceed else 0.0,
                    max(0.0, self._window_seconds - (now - glob_start)) if glob_would_exceed else 0.0,
                )
                return False, retry_after

            return True, None

    def record_auth_failure(self, source_key: str, account_key: str) -> None:
        """Record a verified authentication failure."""
        if not isinstance(source_key, str) or not isinstance(account_key, str):
            return

        norm_src = self._normalize(source_key)
        norm_acct = self._normalize(account_key)

        now = self._clock()
        with self._lock:
            source_full = len(self._source_windows) >= self._max_entries and norm_src not in self._source_windows
            account_full = len(self._account_windows) >= self._max_entries and norm_acct not in self._account_windows

            if source_full or account_full:
                glob_start, glob_count = self._global_windows[self._global_key]
                if now - glob_start >= self._window_seconds:
                    glob_start, glob_count = now, 0
                self._global_windows[self._global_key] = (glob_start, glob_count + 1)
                return

            src_start, src_count = self._source_windows.get(norm_src, (now, 0))
            if now - src_start >= self._window_seconds:
                src_start, src_count = now, 0

            acct_start, acct_count = self._account_windows.get(norm_acct, (now, 0))
            if now - acct_start >= self._window_seconds:
                acct_start, acct_count = now, 0

            glob_start, glob_count = self._global_windows[self._global_key]
            if now - glob_start >= self._window_seconds:
                glob_start, glob_count = now, 0

            self._source_windows[norm_src] = (src_start, src_count + 1)
            self._account_windows[norm_acct] = (acct_start, acct_count + 1)
            self._global_windows[self._global_key] = (glob_start, glob_count + 1)

    def reset_account_failures(self, account_key: str) -> None:
        """Reset the per-account auth_failure counter after a successful login."""
        if not isinstance(account_key, str):
            return

        norm_acct = self._normalize(account_key)
        now = self._clock()
        with self._lock:
            acct_start, acct_count = self._account_windows.get(norm_acct, (now, 0))
            self._account_windows[norm_acct] = (now, 0)

    def _prune(self, now: float) -> None:
        """Remove stale entries."""
        stale_after = self._window_seconds * 2
        self._source_windows = {k: v for k, v in self._source_windows.items() if now - v[0] < stale_after}
        self._account_windows = {k: v for k, v in self._account_windows.items() if now - v[0] < stale_after}

    @staticmethod
    def _normalize(raw_key: str) -> str:
        """Normalize a key."""
        if not isinstance(raw_key, str):
            raise TypeError("key must be a string")
        return raw_key.strip().lower()
