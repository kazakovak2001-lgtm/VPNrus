"""Admin-rate-limiter for the pocvpn-api admin service (B8B1B+ scope).

Provides a combined per-account + global fixed-window rate limiter with
atomic "both-or-nothing" evaluation.  One threading.Lock protects all
shared state.  The clock is injected for deterministic tests.

Architectural invariant:
  - Never stores raw passwords, session IDs, CSRF tokens, or activation
    credentials in any key or log field.
  - The returned ``retry_after`` value (when present) is derived *only*
    from limits that actually denied the request; non-blocking limits
    contribute nothing.
  - A denied request increments **neither** counter partially – both are
    mutated only when both limits allow, or neither is mutated when either
    denies.
  - Account keys are normalised by ``str.lower().strip()`` before lookup
    so that accidental whitespace or case differences cannot split the
    key space.
  - Stale entries are pruned deterministically on every ``combined_allow``
    call; an attacker who submits many distinct keys cannot grow the
    structure beyond the prune horizon.
"""

import threading
from typing import Dict, Tuple, Optional


class AdminRateLimiter:
    """Combined per-account + global fixed-window rate limiter.

    Parameters
    ----------
    per_account_max : int
        Maximum allowed requests per account within *window_seconds*.
        Must be > 0.
    global_max : int
        Maximum allowed requests globally (all accounts combined) within
        *window_seconds*.  Must be > 0.
    window_seconds : float
        Fixed observation window length in seconds.  Must be > 0.
    clock : callable
        Zero-argument function returning the current monotic time (e.g.
        ``time.monotonic``).  Pass a deterministic fake clock for tests.
    """

    def __init__(
        self,
        per_account_max: int,
        global_max: int,
        window_seconds: float,
        clock,
    ) -> None:
        if per_account_max <= 0:
            raise ValueError("per_account_max must be positive")
        if global_max <= 0:
            raise ValueError("global_max must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if not callable(clock):
            raise ValueError("clock must be a callable")

        self._per_account_max = per_account_max
        self._global_max = global_max
        self._window_seconds = window_seconds
        self._clock = clock

        self._lock = threading.Lock()
        # key (lower‑stripped account key) -> (window_start, count)
        self._per_account_windows: Dict[str, Tuple[float, int]] = {}
        # single global key used for the worldwide counter
        self._global_key = "_global_"
        self._global_windows: Dict[str, Tuple[float, int]] = {
            self._global_key: (0.0, 0)
        }

    # -----------------------------------------------------------------
    # Key normalisation
    # -----------------------------------------------------------------

    @staticmethod
    def normalise_key(raw_key: str) -> str:
        """Normalise an account key by stripping whitespace and lower‑casing.

        This is the deterministic normalisation rule used for all look‑ups
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
    # Core atomic evaluation
    # -----------------------------------------------------------------

    def combined_allow(self, account_key: str) -> Tuple[bool, Optional[float]]:
        """Evaluate per‑account and global limits atomically.

        Returns
        -------
        (allowed, retry_after) : tuple
            * ``allowed`` is ``True`` when both the per‑account and global
              windows still have capacity.
            * ``allowed`` is ``False`` when **either** limit is exhausted.
            * ``retry_after`` is ``None`` when ``allowed`` is ``True``.
              Otherwise it is the *maximum* of the remaining reset times
              of every limit that is currently blocking.  If only the
              per‑account limit blocks, ``retry_after`` is its remaining
              window; if only the global limit blocks, it is the global
              remaining window; if both block, it is the maximum of the two.
        """
        now = self._clock()
        norm_key = self.normalise_key(account_key)

        with self._lock:
            # --- prune stale entries first (deterministic, bounded) ---
            self._prune_locked(norm_key, now)

            # --- evaluate per‑account window ---
            acct_start, acct_count = self._per_account_windows.get(
                norm_key, (now, 0)
            )
            if now - acct_start >= self._window_seconds:
                # window expired → start fresh
                acct_start, acct_count = now, 0

            acct_denies = now - acct_start >= self._window_seconds
            acct_remaining = max(0.0, self._window_seconds - (now - acct_start))
            acct_would_exceed = acct_count + 1 > self._per_account_max

            # --- evaluate global window ---
            glob_start, glob_count = self._global_windows[self._global_key]
            if now - glob_start >= self._window_seconds:
                glob_start, glob_count = now, 0

            glob_denies = now - glob_start >= self._window_seconds
            glob_remaining = max(0.0, self._window_seconds - (now - glob_start))
            glob_would_exceed = glob_count + 1 > self._global_max

            # --- atomic decision: both‑or‑nothing ---
            if acct_would_exceed or glob_would_exceed:
                # Denied – **do not** increment any counter.
                # Compute retry_after from the blocking limit(s) only.
                if acct_would_exceed and glob_would_exceed:
                    retry_after = max(acct_remaining, glob_remaining)
                elif acct_would_exceed:
                    retry_after = acct_remaining
                else:  # glob_would_exceed
                    retry_after = glob_remaining
                return False, retry_after

            # --- both limits allow → increment **both** counters atomically ---
            self._per_account_windows[norm_key] = (acct_start, acct_count + 1)
            self._global_windows[self._global_key] = (glob_start, glob_count + 1)

            return True, None

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    def _prune_locked(self, observed_key: str, now: float) -> None:
        """Remove entries that are too old to affect any future decision.

        A window strictly older than 2x its own length can never again
        affect a decision (the next ``combined_allow`` for that key would
        already start a fresh window), so it is safe to drop.
        The *observed_key* is **kept** even if stale – it guarantees the
        key stays in the dict so that its counter is not lost mid‑session.
        """
        stale_after = self._window_seconds * 2

        # Prune per‑account entries (skip the observed key and the global key)
        keys_to_remove = [
            k for k in self._per_account_windows
            if k not in (observed_key, self._global_key)
            and now - self._per_account_windows[k][0] >= stale_after
        ]
        for k in keys_to_remove:
            del self._per_account_windows[k]

        # Prune global entries (keep the single global key)
        # The global key is always retained – it is the only entry in the
        # dict, so no explicit removal is needed here.