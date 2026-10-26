"""AuthFailureLimiter — tracks verified authentication failures separately from admission.

Provides three operations: check_admission, record_auth_failure, reset_account_failures.
One threading.Lock protects all shared state.  The clock is injected for deterministic tests.

Architectural invariants:
  - check_admission is called BEFORE credential validation.
    It records nothing and may deny new attempts (fail-closed at capacity).
    Its result is NOT counted as a auth_failure.
  - record_auth_failure is called ONLY AFTER credential validation confirmed
    the credentials are wrong.  It increments per-source, per-account, AND
    the global counter atomically (all three, or none if capacity prevents).
    It is silent on capacity exhaustion — the record is dropped, no exception.
  - reset_account_failures is called ONLY AFTER a verified successful login.
    It resets ONLY the per-account counter.  Per-source and global counters
    are left untouched.
  - All state is process-local, reset on process restart, not shared across workers.
  - The global counter is NOT distributed protection; it is a per-process
    in-memory bucket.  A restart vyluje všechny čítače.
  - No raw passwords, tokens, or session identifiers are stored in keys or logs.
  - Account keys are normalised by str.strip().lower() for lookup; source keys
    are normalised IP addresses (or UNATTRIBUTED) using client_identity norms.
"""

import math
import threading
from typing import Dict, Optional, Tuple


class AuthFailureLimiter:
    """Tracks verified authentication failures separate from admission limiting.

    Parameters
    ----------
    per_source_max : int
        Maximum allowed auth_failure attempts from a single source within
        *window_seconds*.  Must be > 0.
    per_account_max : int
        Maximum allowed auth_failure attempts per account within
        *window_seconds*.  Must be > 0.
    global_max : int
        Maximum allowed auth_failure attempts globally (all sources and
        accounts combined) within *window_seconds*.  Must be > 0.
    window_seconds : float
        Fixed observation window length in seconds.  Must be > 0.
    clock : callable
        Zero-argument function returning the current monotic time (e.g.
        ``time.monotonic``).  Pass a deterministic fake clock for tests.
    max_entries : int
        Hard limit on the number of stored entries.  When this many entries
        exist, ``record_auth_failure`` silently drops the new record (no
        exception).  Must be >= 1.
    """

    def __init__(
        self,
        per_source_max: int,
        per_account_max: int,
        global_max: int,
        window_seconds: float,
        clock,
        max_entries: int = 10_000,
    ) -> None:
        if not isinstance(per_source_max, int) or per_source_max <= 0:
            raise ValueError("per_source_max must be a positive int")
        if not isinstance(per_account_max, int) or per_account_max <= 0:
            raise ValueError("per_account_max must be a positive int")
        if not isinstance(global_max, int) or global_max <= 0:
            raise ValueError("global_max must be a positive int")
        if not isinstance(window_seconds, (int, float)) or window_seconds <= 0:
            raise ValueError("window_seconds must be a positive number")
        if not math.isfinite(window_seconds):
            raise ValueError("window_seconds must be finite")
        if not callable(clock):
            raise ValueError("clock must be a callable")
        if not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be an int >= 1")

        self._per_source_max = per_source_max
        self._per_account_max = per_account_max
        self._global_max = global_max
        self._window_seconds = float(window_seconds)
        self._clock = clock
        self._max_entries = max_entries

        self._lock = threading.Lock()
        # source_key -> (window_start, count)
        self._source_windows: Dict[str, Tuple[float, int]] = {}
        # account_key -> (window_start, count)
        self._account_windows: Dict[str, Tuple[float, int]] = {}
        # single global key
        self._global_key = "_global_auth_"
        self._global_windows: Dict[str, Tuple[float, int]] = {
            self._global_key: (0.0, 0)
        }

    # -----------------------------------------------------------------
    # Key normalisation
    # -----------------------------------------------------------------

    @staticmethod
    def normalise_source(raw_key: str) -> str:
        """Normalise a source key (typically an IP address).

        Uses the same logic as ``client_identity.normalise_client`` but
        without self_addresses awareness — it simply strips whitespace and
        lower-cases.  The caller is responsible for mapping loopback/unspecified
        to ``UNATTRIBUTED`` before passing the key in.
        """
        if not isinstance(raw_key, str):
            raise TypeError("source_key must be a string")
        normalised = raw_key.strip().lower()
        if not normalised:
            raise ValueError("source_key becomes empty after stripping")
        return normalised

    @staticmethod
    def normalise_account(raw_key: str) -> str:
        """Normalise an account key by stripping whitespace and lower-casing.

        This is the deterministic normalisation rule used for all look-ups
        and storage inside the limiter.  Callers must ensure the original
        key is meaningful after normalisation (e.g. not an empty string).
        """
        if not isinstance(raw_key, str):
            raise TypeError("account_key must be a string")
        normalised = raw_key.strip().lower()
        if not normalised:
            raise ValueError("account_key becomes empty after stripping")
        return normalised

    # -----------------------------------------------------------------
    # Core helpers
    # -----------------------------------------------------------------

    def _prune_locked(self, now: float) -> None:
        """Remove entries that are too old to affect any future decision.

        A window strictly older than 2x its own length can never again
        affect a decision, so it is safe to drop.
        """
        stale_after = self._window_seconds * 2

        keys_to_remove = [
            k for k, (start, _count) in self._source_windows.items()
            if now - start >= stale_after
        ]
        for k in keys_to_remove:
            del self._source_windows[k]

        keys_to_remove = [
            k for k, (start, _count) in self._account_windows.items()
            if now - start >= stale_after
        ]
        for k in keys_to_remove:
            del self._account_windows[k]

        # Global key is always retained — it is the only entry.
        # No per-entry pruning needed.

    # -----------------------------------------------------------------
    # 1. check_admission  (BEFORE credential validation)
    # -----------------------------------------------------------------

    def check_admission(self, source_key: str, account_key: str) -> Tuple[bool, Optional[float]]:
        """May a source attempt authentication?  Called BEFORE credential
        validation.

        Reads: per-source, per-account, global counters.
        Modifies: **nothing**.
        Returns: (True, None) if the source may still attempt auth;
        (False, retry_after) if any counter is exhausted.
        A denied result here is an admission refusal, NOT a failed login.
        The result is NOT recorded anywhere.

        The *retry_after* value is derived only from the blocking limit(s),
        exactly as ``AdminRateLimiter.combined_allow`` does.
        """
        if not isinstance(source_key, str):
            raise TypeError("source_key must be a string")
        if not isinstance(account_key, str):
            raise TypeError("account_key must be a string")
        norm_src = self.normalise_source(source_key)
        norm_acct = self.normalise_account(account_key)

        now = self._clock()
        with self._lock:
            self._prune_locked(now)

            # --- per-source window ---
            src_start, src_count = self._source_windows.get(
                norm_src, (now, 0)
            )
            if now - src_start >= self._window_seconds:
                src_start, src_count = now, 0

            src_would_exceed = src_count + 1 > self._per_source_max

            # --- per-account window ---
            acct_start, acct_count = self._account_windows.get(
                norm_acct, (now, 0)
            )
            if now - acct_start >= self._window_seconds:
                acct_start, acct_count = now, 0

            acct_would_exceed = acct_count + 1 > self._per_account_max

            # --- global window ---
            glob_start, glob_count = self._global_windows[self._global_key]
            if now - glob_start >= self._window_seconds:
                glob_start, glob_count = now, 0

            glob_would_exceed = glob_count + 1 > self._global_max

            # --- fail-closed at capacity: new identities are denied when
            #     the dict is full.  Existing entries are never evicted.
            if src_would_exceed or acct_would_exceed or glob_would_exceed:
                # Compute retry_after from blocking limit(s) only.
                if src_would_exceed and acct_would_exceed and glob_would_exceed:
                    retry_after = max(
                        self._window_seconds - (now - src_start),
                        self._window_seconds - (now - acct_start),
                        self._window_seconds - (now - glob_start),
                    )
                elif src_would_exceed and acct_would_exceed:
                    retry_after = max(
                        self._window_seconds - (now - src_start),
                        self._window_seconds - (now - acct_start),
                    )
                elif src_would_exceed and glob_would_exceed:
                    retry_after = max(
                        self._window_seconds - (now - src_start),
                        self._window_seconds - (now - glob_start),
                    )
                elif acct_would_exceed and glob_would_exceed:
                    retry_after = max(
                        self._window_seconds - (now - acct_start),
                        self._window_seconds - (now - glob_start),
                    )
                elif src_would_exceed:
                    retry_after = self._window_seconds - (now - src_start)
                elif acct_would_exceed:
                    retry_after = self._window_seconds - (now - acct_start)
                else:  # glob_would_exceed
                    retry_after = self._window_seconds - (now - glob_start)

                # Clamp to non-negative; caller may see 0.0 meaning "try again".
                retry_after = max(0.0, retry_after)
                return False, retry_after

            # --- all limits allow: admit, but do NOT increment any counter ---
            return True, None

    # -----------------------------------------------------------------
    # 2. record_auth_failure  (AFTER verified wrong credential)
    # -----------------------------------------------------------------

    def record_auth_failure(self, source_key: str, account_key: str) -> None:
        """Record a verified authentication failure.

        Reads: per-source, per-account, global counters.
        Modifies: increments per-source, per-account, AND global counters.

        Capacity policy (fail-closed for new identities, global always
        incremented):
          - If BOTH the source and account dicts have room, all three
            counters are incremented atomically.
          - If EITHER dict is full and the key is new, the new entry is
            NOT stored (memory stays bounded), but the GLOBAL counter
            IS still incremented so that global brute-force protection
            cannot be bypassed by rotating identities.
          - Existing entries are NEVER evicted.
          - Never raises on capacity exhaustion.

        The caller **must** ensure that credential validation has already
        confirmed the credentials are wrong.  Never call this for admission
        refusals, malformed requests, or missing CSRF tokens.
        """
        if not isinstance(source_key, str):
            raise TypeError("source_key must be a string")
        if not isinstance(account_key, str):
            raise TypeError("account_key must be a string")

        norm_src = self.normalise_source(source_key)
        norm_acct = self.normalise_account(account_key)

        now = self._clock()
        with self._lock:
            # --- capacity check for BOTH dicts ---
            source_full = (
                len(self._source_windows) >= self._max_entries
                and norm_src not in self._source_windows
            )
            account_full = (
                len(self._account_windows) >= self._max_entries
                and norm_acct not in self._account_windows
            )

            if source_full or account_full:
                # At least one dict is full and the key is new.
                # We cannot store the new entry (memory stays bounded,
                # existing entries are never evicted), but we MUST still
                # increment the GLOBAL counter so that global brute-force
                # protection is not bypassed by rotating identities.
                glob_start, glob_count = self._global_windows[self._global_key]
                if now - glob_start >= self._window_seconds:
                    glob_start, glob_count = now, 0
                self._global_windows[self._global_key] = (glob_start, glob_count + 1)
                return

            # --- per-source window ---
            src_start, src_count = self._source_windows.get(
                norm_src, (now, 0)
            )
            if now - src_start >= self._window_seconds:
                src_start, src_count = now, 0

            # --- per-account window ---
            acct_start, acct_count = self._account_windows.get(
                norm_acct, (now, 0)
            )
            if now - acct_start >= self._window_seconds:
                acct_start, acct_count = now, 0

            # --- global window ---
            glob_start, glob_count = self._global_windows[self._global_key]
            if now - glob_start >= self._window_seconds:
                glob_start, glob_count = now, 0

            # Update all three atomically
            self._source_windows[norm_src] = (src_start, src_count + 1)
            self._account_windows[norm_acct] = (acct_start, acct_count + 1)
            self._global_windows[self._global_key] = (glob_start, glob_count + 1)

    # -----------------------------------------------------------------
    # 3. reset_account_failures  (AFTER verified successful login)
    # -----------------------------------------------------------------

    def reset_account_failures(self, account_key: str) -> None:
        """Reset the per-account auth_failure counter after a verified
        successful login.

        Reads: per-account counter.
        Modifies: resets ONLY the per-account counter for *this* account.
        Does NOT touch per-source or global counters.
        Returns: ``None``.

        The caller **must** ensure that a verified successful login has
        occurred.  Never call this as a side effect of admission denial.
        """
        if not isinstance(account_key, str):
            raise TypeError("account_key must be a string")
        norm_acct = self.normalise_account(account_key)

        now = self._clock()
        with self._lock:
            acct_start, acct_count = self._account_windows.get(
                norm_acct, (now, 0)
            )
            # Reset the per-account window: start fresh at now, count 0.
            # We keep the entry so that the key is not lost; the next
            # ``check_admission`` / ``record_auth_failure`` will see count 0.
            self._account_windows[norm_acct] = (now, 0)