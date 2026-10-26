"""Unit tests for AuthFailureLimiter (Phase 1.8.18 contract).

See gateway/api/auth_ratelimit.py for the implementation docstring.
All tests use a deterministic FakeClock so no timing-sensitive sleeps
are required.
"""

import math
import sys
import threading
import unittest

_THIS_DIR = __import__("os").path.dirname(__import__("os").path.abspath(__file__))
_GATEWAY_DIR = __import__("os").path.abspath(__import__("os").path.join(_THIS_DIR, "..", ".."))
for _p in (_GATEWAY_DIR, _THIS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from api.auth_ratelimit import AuthFailureLimiter


class FakeClock:
    """Deterministic clock that can be advanced programmatically."""

    def __init__(self, start: float = 0.0):
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class AuthFailureLimiterTests(unittest.TestCase):
    """Tests covering the exact contract and invariants
    documented in AuthFailureLimiter."""

    # -----------------------------------------------------------------
    # 1. Check admission vs verified auth failure — no double counting
    # -----------------------------------------------------------------
    def test_check_admission_not_recorded(self) -> None:
        """Admission denial does NOT increment any counter.

        If check_admission denies, the caller should NOT call
        record_auth_failure — that is a separate step after verified
        wrong credentials.  Here we verify the state is unchanged.
        """
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=2,
            per_account_max=5,
            global_max=10,
            window_seconds=60.0,
            clock=clock,
        )
        # Before any calls, admission should allow.
        allowed, _ = limiter.check_admission("127.0.0.1", "alice")
        self.assertTrue(allowed)
        # Record a failure from a different step (simulating verified wrong cred).
        limiter.record_auth_failure("127.0.0.1", "alice")
        # Admission should still allow (different counter).
        allowed, _ = limiter.check_admission("127.0.0.1", "alice")
        self.assertTrue(allowed)
        # Two failures from same source/account should eventually deny.
        limiter.record_auth_failure("127.0.0.1", "alice")
        allowed, _ = limiter.check_admission("127.0.0.1", "alice")
        # Second failure from same source pushes per-source to 2 (= max).
        # Third call should deny.
        self.assertFalse(allowed)

    # -----------------------------------------------------------------
    # 2. Reset one account without resetting another
    # -----------------------------------------------------------------
    def test_reset_one_account_no_other(self) -> None:
        """reset_account_failures("alice") only resets alice's per-account
        counter.  bob's counter and the global counter are untouched."""
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=5,
            per_account_max=2,
            global_max=10,
            window_seconds=60.0,
            clock=clock,
        )
        # Simulate two failures for alice and bob from the same source.
        limiter.record_auth_failure("10.0.0.1", "alice")
        limiter.record_auth_failure("10.0.0.1", "bob")
        limiter.record_auth_failure("10.0.0.1", "alice")  # alice now at max 2
        # Alice's per-account should be at max; bob's should be 1.
        # Reset alice.
        limiter.reset_account_failures("alice")
        # After reset, alice should allow again via check_admission
        # (but record_auth_failure would bump it back).
        allowed, _ = limiter.check_admission("10.0.0.1", "alice")
        self.assertTrue(allowed)
        # Bob's counter should still be 1 (not reset).
        limiter.record_auth_failure("10.0.0.1", "bob")
        allowed, _ = limiter.check_admission("10.0.0.1", "bob")
        # Bob's counter is now 2, which equals max; next denial.
        self.assertFalse(allowed)
        # Global counter should be 3 (2 alice + 1 bob before reset, but
        # reset only touches per-account; global was never reset).
        # Actually global was incremented on each record_auth_failure:
        # 3 total (2 alice + 1 bob). After alice reset, global stays 3.

    # -----------------------------------------------------------------
    # 3. Multiple account identities sharing one source
    # -----------------------------------------------------------------
    def test_multiple_accounts_one_source(self) -> None:
        """Different accounts from the same source each have independent
        per-account counters, but share the per-source counter."""
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=3,
            per_account_max=2,
            global_max=20,
            window_seconds=60.0,
            clock=clock,
        )
        # Alice 2 failures, Bob 2 failures, from same source.
        limiter.record_auth_failure("10.0.0.1", "alice")
        limiter.record_auth_failure("10.0.0.1", "alice")
        limiter.record_auth_failure("10.0.0.1", "bob")
        limiter.record_auth_failure("10.0.0.1", "bob")
        # Per-source count = 4, which exceeds per_source_max=3.
        # check_admission should deny (per-source exhausted).
        allowed, _ = limiter.check_admission("10.0.0.1", "alice")
        self.assertFalse(allowed)
        # Per-account: alice=2, bob=2; global=4.

    # -----------------------------------------------------------------
    # 4. Multiple sources reaching the global limit
    # -----------------------------------------------------------------
    def test_multiple_sources_global_limit(self) -> None:
        """Different sources each contribute to the global counter."""
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=10,
            per_account_max=10,
            global_max=5,
            window_seconds=60.0,
            clock=clock,
        )
        # Source A: 3 failures.
        limiter.record_auth_failure("1.0.0.1", "alice")
        limiter.record_auth_failure("1.0.0.1", "alice")
        limiter.record_auth_failure("1.0.0.1", "alice")
        # Source B: 3 failures.
        limiter.record_auth_failure("2.0.0.1", "bob")
        limiter.record_auth_failure("2.0.0.1", "bob")
        limiter.record_auth_failure("2.0.0.1", "bob")
        # Global count = 6 > global_max=5. check_admission from either
        # source should now deny.
        allowed, _ = limiter.check_admission("1.0.0.1", "alice")
        self.assertFalse(allowed)
        allowed, _ = limiter.check_admission("2.0.0.1", "bob")
        self.assertFalse(allowed)

    # -----------------------------------------------------------------
    # 5. Global fixed-window expiration
    # -----------------------------------------------------------------
    def test_global_window_expiration(self) -> None:
        """After advancing past the window, the global counter resets."""
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=10,
            per_account_max=10,
            global_max=2,
            window_seconds=5.0,
            clock=clock,
        )
        # Two failures quickly.
        limiter.record_auth_failure("10.0.0.1", "alice")
        limiter.record_auth_failure("10.0.0.1", "bob")
        # Global count = 2 = global_max; next admission should deny.
        allowed, _ = limiter.check_admission("10.0.0.1", "alice")
        self.assertFalse(allowed)
        # Advance past the window.
        clock.advance(5.1)
        # Now global should have reset; admission should allow.
        allowed, _ = limiter.check_admission("10.0.0.1", "alice")
        self.assertTrue(allowed)

    # -----------------------------------------------------------------
    # 6. Concurrent failure recording with no lost increments
    # -----------------------------------------------------------------
    def test_concurrent_no_lost_increments(self) -> None:
        """20 threads recording failures from the same source/account —
        no lost increments."""
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=200,
            per_account_max=200,
            global_max=500,
            window_seconds=60.0,
            clock=clock,
        )
        def worker(src: str, acct: str, iterations: int) -> None:
            for _ in range(iterations):
                limiter.record_auth_failure(src, acct)

        threads = []
        for i in range(20):
            t = threading.Thread(target=worker, args=(f"10.0.{i}.1", f"acct-{i % 10}", 50))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Fixed clock, no window boundary, far below max_entries: every
        # increment must be visible in the limiter's own counters.
        sources = {k: c for k, (_s, c) in limiter._source_windows.items()}
        accounts = {k: c for k, (_s, c) in limiter._account_windows.items()}
        self.assertEqual(len(sources), 20)
        self.assertTrue(all(c == 50 for c in sources.values()), sources)
        self.assertEqual(len(accounts), 10)
        self.assertTrue(all(c == 100 for c in accounts.values()), accounts)
        self.assertEqual(limiter._global_windows[limiter._global_key][1], 1000)

    # -----------------------------------------------------------------
    # 7. Capacity exhaustion and bounded policy
    # -----------------------------------------------------------------
    def test_capacity_exhaustion_new_source_dropped(self) -> None:
        """When dict is at max_entries and a new source key appears,
        record_auth_failure silently drops the new entry (no exception),
        but the GLOBAL counter is still incremented so that global
        brute-force protection is not bypassed by rotating identities."""
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=100,
            per_account_max=100,
            global_max=100,
            window_seconds=60.0,
            clock=clock,
            max_entries=3,  # very small
        )
        # Fill with 3 existing source keys.
        limiter.record_auth_failure("1.0.0.1", "alice")
        limiter.record_auth_failure("2.0.0.1", "bob")
        limiter.record_auth_failure("3.0.0.1", "charlie")
        # Now try a 4th new source — the entry is dropped (no exception),
        # but the global counter MUST still be incremented.
        limiter.record_auth_failure("4.0.0.1", "dave")
        # The new source is NOT stored: the dict stays at 3 entries.
        self.assertEqual(len(limiter._source_windows), 3)
        # The new account is NOT stored either.
        self.assertEqual(len(limiter._account_windows), 3)
        # The global counter WAS incremented (4 total).
        self.assertEqual(limiter._global_windows["_global_auth_"][1], 4)
        # check_admission from any of the 3 known sources should still
        # work (counters may be at max per-source/per-account/global,
        # but the dict has 3 entries, and the new key is dropped).
        # Since per-source/per-account/global max are 100 and we only
        # recorded 1 per key, admission should allow.
        allowed, _ = limiter.check_admission("1.0.0.1", "alice")
        self.assertTrue(allowed)

    # -----------------------------------------------------------------
    # 7b. New identity rotation cannot bypass the global limit
    # -----------------------------------------------------------------
    def test_identity_rotation_cannot_bypass_global_limit(self) -> None:
        """An attacker who rotates source identities to fill the dict
        still cannot avoid the global limit: every new identity
        increments the global counter, so the global limit is reached
        regardless of how many distinct identities are created."""
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=100,
            per_account_max=100,
            global_max=5,
            window_seconds=60.0,
            clock=clock,
            max_entries=3,  # very small — only 3 source entries allowed
        )
        # Fill the source dict with 3 distinct sources.
        for i in range(1, 4):
            limiter.record_auth_failure(f"{i}.0.0.1", f"acct-{i}")
        # Now rotate through NEW source identities.  Each one is dropped
        # from the source dict, but the global counter MUST still be
        # incremented.  After 2 more rotations, global count = 5 = max.
        limiter.record_auth_failure("4.0.0.1", "acct-4")
        limiter.record_auth_failure("5.0.0.1", "acct-5")
        # Global counter is now 5 (= global_max).
        self.assertEqual(limiter._global_windows["_global_auth_"][1], 5)
        # Source dict is still bounded at 3.
        self.assertEqual(len(limiter._source_windows), 3)
        # Even a brand-new identity is now denied by check_admission
        # because the global limit is exhausted.
        allowed, retry_after = limiter.check_admission("6.0.0.1", "acct-6")
        self.assertFalse(allowed)
        # retry_after reflects the global window remaining.
        self.assertAlmostEqual(retry_after, 60.0, places=1)

    # -----------------------------------------------------------------
    # 7c. Account dict full: new account still increments global
    # -----------------------------------------------------------------
    def test_account_dict_full_still_increments_global(self) -> None:
        """When the account dict is full and a new account key appears,
        the new account entry is dropped but the global counter is
        still incremented.  The source dict may have room."""
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=100,
            per_account_max=100,
            global_max=100,
            window_seconds=60.0,
            clock=clock,
            max_entries=3,
        )
        # Fill the account dict with 3 distinct accounts (same source).
        for i in range(1, 4):
            limiter.record_auth_failure("10.0.0.1", f"acct-{i}")
        # Now a 4th new account from the same source — account dict is
        # full, so the new account entry is dropped, but the global
        # counter is still incremented.
        limiter.record_auth_failure("10.0.0.1", "acct-4")
        self.assertEqual(len(limiter._account_windows), 3)
        self.assertEqual(limiter._global_windows["_global_auth_"][1], 4)
        # Source dict has room (only 1 source), so it was incremented.
        self.assertEqual(len(limiter._source_windows), 1)

    # -----------------------------------------------------------------
    # 7d. Both dicts full: global still incremented, dict stays bounded
    # -----------------------------------------------------------------
    def test_both_dicts_full_global_still_incremented(self) -> None:
        """When BOTH the source and account dicts are full and both
        keys are new, the global counter is still incremented and the
        dicts stay bounded at max_entries."""
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=100,
            per_account_max=100,
            global_max=100,
            window_seconds=60.0,
            clock=clock,
            max_entries=3,
        )
        # Fill both dicts with 3 distinct (source, account) pairs.
        for i in range(1, 4):
            limiter.record_auth_failure(f"{i}.0.0.1", f"acct-{i}")
        # Now a completely new pair — both dicts are full.
        limiter.record_auth_failure("99.0.0.1", "newacct")
        # Both dicts stay at 3 entries.
        self.assertEqual(len(limiter._source_windows), 3)
        self.assertEqual(len(limiter._account_windows), 3)
        # Global counter is still incremented.
        self.assertEqual(limiter._global_windows["_global_auth_"][1], 4)

    # -----------------------------------------------------------------
    # 8. Invalid types, empty strings, NaN, infinity, backwards clock
    # -----------------------------------------------------------------
    def test_invalid_constructor_rejected(self) -> None:
        clock = FakeClock()
        # per_source_max <= 0
        with self.assertRaises(ValueError):
            AuthFailureLimiter(
                per_source_max=0,
                per_account_max=10,
                global_max=10,
                window_seconds=60.0,
                clock=clock,
            )
        # per_account_max <= 0
        with self.assertRaises(ValueError):
            AuthFailureLimiter(
                per_source_max=10,
                per_account_max=0,
                global_max=10,
                window_seconds=60.0,
                clock=clock,
            )
        # global_max <= 0
        with self.assertRaises(ValueError):
            AuthFailureLimiter(
                per_source_max=10,
                per_account_max=10,
                global_max=0,
                window_seconds=60.0,
                clock=clock,
            )
        # window_seconds <= 0
        with self.assertRaises(ValueError):
            AuthFailureLimiter(
                per_source_max=10,
                per_account_max=10,
                global_max=10,
                window_seconds=0,
                clock=clock,
            )
        # window_seconds = NaN
        with self.assertRaises(ValueError):
            AuthFailureLimiter(
                per_source_max=10,
                per_account_max=10,
                global_max=10,
                window_seconds=float("nan"),
                clock=clock,
            )
        # window_seconds = +inf
        with self.assertRaises(ValueError):
            AuthFailureLimiter(
                per_source_max=10,
                per_account_max=10,
                global_max=10,
                window_seconds=float("inf"),
                clock=clock,
            )
        # window_seconds = -inf
        with self.assertRaises(ValueError):
            AuthFailureLimiter(
                per_source_max=10,
                per_account_max=10,
                global_max=10,
                window_seconds=float("-inf"),
                clock=clock,
            )
        # clock not callable
        with self.assertRaises(ValueError):
            AuthFailureLimiter(
                per_source_max=10,
                per_account_max=10,
                global_max=10,
                window_seconds=60.0,
                clock="not_callable",  # type: ignore
            )

    def test_invalid_key_rejected(self) -> None:
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=5,
            per_account_max=5,
            global_max=5,
            window_seconds=60.0,
            clock=clock,
        )
        # Empty source key after stripping.
        with self.assertRaises(ValueError):
            AuthFailureLimiter.normalise_source("")
        # Empty account key after stripping.
        with self.assertRaises(ValueError):
            AuthFailureLimiter.normalise_account("")
        # Non-string source key in check_admission.
        with self.assertRaises(TypeError):
            limiter.check_admission(42, "alice")  # type: ignore
        # Non-string account key in reset.
        with self.assertRaises(TypeError):
            limiter.reset_account_failures(42)  # type: ignore

    # -----------------------------------------------------------------
    # 9. New limiter instance starts with empty process-local counters
    # -----------------------------------------------------------------
    def test_new_limiter_empty_counters(self) -> None:
        """A freshly created AuthFailureLimiter has zero counters."""
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=5,
            per_account_max=5,
            global_max=5,
            window_seconds=60.0,
            clock=clock,
        )
        # All admissions should allow.
        for _ in range(10):
            allowed, _ = limiter.check_admission("10.0.0.1", "alice")
            self.assertTrue(allowed)
        # Record a few failures.
        limiter.record_auth_failure("10.0.0.1", "alice")
        limiter.record_auth_failure("10.0.0.1", "alice")
        # After 2, per-source=2, per-account=2, global=2.
        # Admission should still allow (below max=5).
        allowed, _ = limiter.check_admission("10.0.0.1", "alice")
        self.assertTrue(allowed)
        # After 3 more, per-source=5 (=max); next denial.
        limiter.record_auth_failure("10.0.0.1", "alice")
        limiter.record_auth_failure("10.0.0.1", "alice")
        limiter.record_auth_failure("10.0.0.1", "alice")
        allowed, _ = limiter.check_admission("10.0.0.1", "alice")
        self.assertFalse(allowed)

    # -----------------------------------------------------------------
    # 9b. New identity denied when global limit exhausted, dicts full
    # -----------------------------------------------------------------
    def test_new_identity_denied_when_global_exhausted_dicts_full(self) -> None:
        """check_admission() refuses a brand-new identity whose source
        and account records do NOT exist, when the global limit is
        exhausted and BOTH dicts are at max_entries.

        This is the invariant that closes the identity-rotation bypass:
        the global counter is a single never-evicted entry, so it is
        reachable from any identity — new or existing.
        """
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=100,
            per_account_max=100,
            global_max=3,
            window_seconds=60.0,
            clock=clock,
            max_entries=3,  # both dicts capped at 3
        )
        # Fill both dicts with 3 distinct (source, account) pairs.
        for i in range(1, 4):
            limiter.record_auth_failure(f"{i}.0.0.1", f"acct-{i}")
        # Global counter is now 3 (= global_max).
        self.assertEqual(limiter._global_windows["_global_auth_"][1], 3)
        # A brand-new identity (not in either dict) must be denied by
        # check_admission because the global limit is exhausted.
        allowed, retry_after = limiter.check_admission("99.0.0.1", "newacct")
        self.assertFalse(allowed)
        # retry_after reflects the global window remaining (60s).
        self.assertAlmostEqual(retry_after, 60.0, places=1)
        # The new identity was NOT recorded — dicts stay at 3.
        self.assertEqual(len(limiter._source_windows), 3)
        self.assertEqual(len(limiter._account_windows), 3)

    # -----------------------------------------------------------------
    # 9c. Global counter rolls into a new window; dicts stay bounded
    # -----------------------------------------------------------------
    def test_global_window_resets_and_dicts_stay_bounded(self) -> None:
        """After the global window expires, the global counter rolls
        into a fresh window and admission is allowed again.  The dicts
        stay bounded at max_entries — stale entries are pruned, never
        evicted.

        Note: ``check_admission`` modifies nothing, so the window reset
        is observed on the next ``record_auth_failure`` call (which is
        the only writer of the global counter).  ``check_admission``
        sees the reset locally and therefore admits.
        """
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=100,
            per_account_max=100,
            global_max=3,
            window_seconds=5.0,
            clock=clock,
            max_entries=3,
        )
        # Fill both dicts and exhaust the global limit.
        for i in range(1, 4):
            limiter.record_auth_failure(f"{i}.0.0.1", f"acct-{i}")
        self.assertEqual(limiter._global_windows["_global_auth_"][1], 3)
        # New identity denied (global exhausted).
        allowed, _ = limiter.check_admission("99.0.0.1", "newacct")
        self.assertFalse(allowed)
        # Advance past the window.
        clock.advance(5.1)
        # check_admission sees the reset locally and admits.
        allowed, retry_after = limiter.check_admission("99.0.0.1", "newacct")
        self.assertTrue(allowed)
        self.assertIsNone(retry_after)
        # The global counter rolls into a fresh window on the next
        # record_auth_failure: count is 1, not the stale 3.
        limiter.record_auth_failure("99.0.0.1", "newacct")
        glob_start, glob_count = limiter._global_windows["_global_auth_"]
        self.assertEqual(glob_count, 1)
        self.assertAlmostEqual(glob_start, 5.1, places=1)
        # Dicts stay bounded — stale entries pruned at 2x window horizon.
        self.assertLessEqual(len(limiter._source_windows), 3)
        self.assertLessEqual(len(limiter._account_windows), 3)

    # -----------------------------------------------------------------
    # 10. Retry-After on admission denial (simultaneous exhausted counters)
    # -----------------------------------------------------------------
    def test_retry_after_on_denial(self) -> None:
        """check_admission returns (False, retry_after) when denied."""
        clock = FakeClock()
        limiter = AuthFailureLimiter(
            per_source_max=1,
            per_account_max=1,
            global_max=1,
            window_seconds=10.0,
            clock=clock,
        )
        # First call allows; second call from any source denies all limits.
        # Note: check_admission does NOT increment counters, so we must
        # use record_auth_failure to trigger the denial.
        limiter.record_auth_failure("alice", "alice")
        allowed, retry_after = limiter.check_admission("bob", "bob")
        self.assertFalse(allowed)
        # retry_after should be the max of the three remaining windows.
        # Window started at 0, now is clock() = 0 (advance not called yet).
        # Actually clock() = 0, window_seconds = 10, so remaining = 10.
        self.assertAlmostEqual(retry_after, 10.0, places=1)
        # Advance clock to mid-window.
        clock.advance(5.0)
        allowed, retry_after = limiter.check_admission("charlie", "charlie")
        self.assertFalse(allowed)
        # Remaining should be ~5.0.
        self.assertAlmostEqual(retry_after, 5.0, places=1)


if __name__ == "__main__":
    unittest.main()