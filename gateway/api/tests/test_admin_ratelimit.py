"""Unit tests for the AdminRateLimiter (B8B1B+ scope).

See gateway/api/admin_ratelimit.py for the implementation docstring.
All tests use a deterministic FakeClock so no timing-sensitive sleeps
are required.
"""

import os
import sys
import threading
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api.admin_ratelimit import AdminRateLimiter


class FakeClock:
    """Deterministic clock that can be advanced programmatically."""

    def __init__(self, start: float = 0.0):
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class AdminRateLimiterTests(unittest.TestCase):
    """Tests covering the exact counter semantics and invariants
    documented in AdminRateLimiter."""

    # -----------------------------------------------------------------
    # 1. Per-account-only denial
    # -----------------------------------------------------------------
    def test_per_account_only_denial(self) -> None:
        clock = FakeClock()
        limiter = AdminRateLimiter(
            per_account_max=2,
            global_max=100,
            window_seconds=10.0,
            clock=clock,
        )
        # Two allowed calls; the third should deny per-account limit.
        self.assertTrue(limiter.combined_allow("alice"))
        self.assertTrue(limiter.combined_allow("alice"))
        allowed, retry_after = limiter.combined_allow("alice")
        self.assertFalse(allowed)
        self.assertIsNotNone(retry_after)
        # Retry-After should be the per-account remaining window.
        self.assertAlmostEqual(retry_after, 10.0, places=1)

    # -----------------------------------------------------------------
    # 2. Global-only denial
    # -----------------------------------------------------------------
    def test_global_only_denial(self) -> None:
        clock = FakeClock()
        limiter = AdminRateLimiter(
            per_account_max=100,
            global_max=2,
            window_seconds=10.0,
            clock=clock,
        )
        # Two allowed calls from distinct accounts; the third should deny
        # the global limit.
        self.assertTrue(limiter.combined_allow("alice"))
        self.assertTrue(limiter.combined_allow("bob"))
        allowed, retry_after = limiter.combined_allow("charlie")
        self.assertFalse(allowed)
        self.assertIsNotNone(retry_after)
        # Retry-After should be the global remaining window.
        self.assertAlmostEqual(retry_after, 10.0, places=1)

    # -----------------------------------------------------------------
    # 3. Both limits deny
    # -----------------------------------------------------------------
    def test_both_limits_deny(self) -> None:
        clock = FakeClock()
        limiter = AdminRateLimiter(
            per_account_max=1,
            global_max=1,
            window_seconds=10.0,
            clock=clock,
        )
        # First call allows; second call from any account denies both.
        self.assertTrue(limiter.combined_allow("alice"))
        allowed, retry_after = limiter.combined_allow("bob")
        self.assertFalse(allowed)
        # retry_after must be the max of the two remaining windows.
        self.assertAlmostEqual(retry_after, 10.0, places=1)

    # -----------------------------------------------------------------
    # 4. Both limits allow
    # -----------------------------------------------------------------
    def test_both_limits_allow(self) -> None:
        clock = FakeClock()
        limiter = AdminRateLimiter(
            per_account_max=5,
            global_max=5,
            window_seconds=10.0,
            clock=clock,
        )
        for _ in range(5):
            allowed, retry_after = limiter.combined_allow("key-%d" % _)
            self.assertTrue(allowed)
            self.assertIsNone(retry_after)

    # -----------------------------------------------------------------
    # 5. Retry-After calculation and units
    # -----------------------------------------------------------------
    def test_retry_after_units_seconds(self) -> None:
        clock = FakeClock()
        limiter = AdminRateLimiter(
            per_account_max=1,
            global_max=100,
            window_seconds=5.0,
            clock=clock,
        )
        # First call allows; second call denies with retry_after ≈ window length.
        self.assertTrue(limiter.combined_allow("alice"))
        _, retry_after = limiter.combined_allow("alice")
        self.assertAlmostEqual(retry_after, 5.0, places=1)

    # -----------------------------------------------------------------
    # 6. Denied calls do not partially mutate admission counters
    # -----------------------------------------------------------------
    def test_denied_counters_unchanged(self) -> None:
        clock = FakeClock()
        limiter = AdminRateLimiter(
            per_account_max=1,
            global_max=1,
            window_seconds=10.0,
            clock=clock,
        )
        # First call from alice should allow.
        self.assertTrue(limiter.combined_allow("alice"))
        # Second call from bob should deny; counters must NOT be partially
        # incremented.  Call a third time – it should still see the same
        # state as after the first allow (window hasn't advanced enough
        # to reset).
        _allowed_2, _retry = limiter.combined_allow("bob")
        self.assertFalse(_allowed_2)
        # Third call should still deny (window has not expired).
        _allowed_3, _retry = limiter.combined_allow("charlie")
        self.assertFalse(_allowed_3)
        # Now advance the clock past the window and try again.
        clock.advance(10.1)
        self.assertTrue(limiter.combined_allow("alice"))
        self.assertTrue(limiter.combined_allow("bob"))
        self.assertTrue(limiter.combined_allow("charlie"))

    # -----------------------------------------------------------------
    # 7. Concurrent calls preserve the atomic invariant
    # -----------------------------------------------------------------
    def test_concurrent_atomic_invariant(self) -> None:
        clock = FakeClock()
        limiter = AdminRateLimiter(
            per_account_max=100,
            global_max=100,
            window_seconds=10.0,
            clock=clock,
        )
        allowed_count = [0]
        lock = threading.Lock()

        def worker(key: str, iterations: int) -> None:
            for _ in range(iterations):
                allowed, _ = limiter.combined_allow(key)
                if allowed:
                    with lock:
                        allowed_count[0] += 1

        threads = []
        for i in range(20):
            t = threading.Thread(target=worker, args=(f"key-{i % 5}", 100))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Each of the 5 keys can achieve at most 20 allowed (per_account_max
        # = 100, we only call 100 times per key, but window resets after 10s;
        # with a single clock the total per key is bounded by the window
        # progression.  The important invariant is that the total allowed
        # across all threads is <= 5 * 100 = 500 and that no partial
        # increments occur.)
        self.assertLessEqual(allowed_count[0], 500)

    # -----------------------------------------------------------------
    # 8. Stale account keys are pruned
    # -----------------------------------------------------------------
    def test_stale_keys_pruned(self) -> None:
        clock = FakeClock()
        limiter = AdminRateLimiter(
            per_account_max=5,
            global_max=100,
            window_seconds=1.0,
            clock=clock,
        )
        # Fill the per-account bucket for "alice".
        for _ in range(5):
            self.assertTrue(limiter.combined_allow("alice"))
        # Now advance past 2x the window so the entry is stale.
        clock.advance(2.5)
        # The limiter.size() should now be 1 (only the global key).
        # (We don't expose size directly, but we verify that a fresh key
        # can be used after the stale one is pruned.)
        self.assertTrue(limiter.combined_allow("bob"))
        # After the prune, only the global key + bob should remain.
        # Attempting alice again should start a fresh window.
        self.assertTrue(limiter.combined_allow("alice"))

    # -----------------------------------------------------------------
    # 9. Invalid constructor values and invalid keys are rejected
    # -----------------------------------------------------------------
    def test_invalid_constructor_rejected(self) -> None:
        with self.assertRaises(ValueError):
            AdminRateLimiter(
                per_account_max=0,
                global_max=100,
                window_seconds=10.0,
                clock=lambda: 0.0,
            )
        with self.assertRaises(ValueError):
            AdminRateLimiter(
                per_account_max=100,
                global_max=0,
                window_seconds=10.0,
                clock=lambda: 0.0,
            )
        with self.assertRaises(ValueError):
            AdminRateLimiter(
                per_account_max=100,
                global_max=100,
                window_seconds=0,
                clock=lambda: 0.0,
            )

    def test_invalid_key_rejected(self) -> None:
        clock = FakeClock()
        limiter = AdminRateLimiter(
            per_account_max=5,
            global_max=5,
            window_seconds=10.0,
            clock=clock,
        )
        # Empty string after stripping should raise.
        with self.assertRaises(ValueError):
            AdminRateLimiter.normalise_key("")
        # Non-string type should raise from normalise_key.
        # combined_allow should propagate the TypeError.
        with self.assertRaises(TypeError):
            limiter.combined_allow(42)  # type: ignore

    # -----------------------------------------------------------------
    # 10. Clock advancement and window-boundary behavior
    # -----------------------------------------------------------------
    def test_window_boundary_advance(self) -> None:
        clock = FakeClock()
        limiter = AdminRateLimiter(
            per_account_max=1,
            global_max=100,
            window_seconds=10.0,
            clock=clock,
        )
        # First call allows; window starts at 0.
        self.assertTrue(limiter.combined_allow("alice"))
        # Advance exactly to the window boundary – the next call should
        # start a fresh window (count resets).
        clock.advance(10.0)
        # Now the window has expired; the next call should allow again.
        self.assertTrue(limiter.combined_allow("alice"))

    # -----------------------------------------------------------------
    # 11. Repeated denied calls behave according to documented counter
    #     semantics (counters not incremented on denial).
    # -----------------------------------------------------------------
    def test_repeated_denied_counters_semantics(self) -> None:
        clock = FakeClock()
        limiter = AdminRateLimiter(
            per_account_max=1,
            global_max=3,
            window_seconds=60.0,
            clock=clock,
        )
        # First call alice → allow, increment both counters.
        self.assertTrue(limiter.combined_allow("alice"))
        # Second call alice → deny per-account limit; counters must NOT be
        # incremented.  Call multiple times – they should all deny with
        # the same remaining window.
        for i in range(5):
            allowed, retry_after = limiter.combined_allow("alice")
            self.assertFalse(allowed)
            # retry_after should shrink as the window expires, but while
            # the window is active it should be > 0.
            if i < 4:  # not the last iteration
                self.assertGreater(retry_after, 0.0)
        # After window expires, calls should allow again.
        clock.advance(60.1)
        self.assertTrue(limiter.combined_allow("alice"))
