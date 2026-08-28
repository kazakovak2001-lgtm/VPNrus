import os
import sys
import threading
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GATEWAY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
for _path in (_GATEWAY_DIR, _THIS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from api.ratelimit import RateLimiter


class FakeClock:
    def __init__(self, start=0.0):
        self._now = start

    def __call__(self):
        return self._now

    def advance(self, seconds):
        self._now += seconds


class RateLimiterTests(unittest.TestCase):
    def test_allows_up_to_max_then_blocks(self):
        clock = FakeClock()
        limiter = RateLimiter(max_requests=3, window_seconds=10, clock=clock)
        self.assertTrue(limiter.allow("k"))
        self.assertTrue(limiter.allow("k"))
        self.assertTrue(limiter.allow("k"))
        self.assertFalse(limiter.allow("k"))

    def test_resets_after_window(self):
        clock = FakeClock()
        limiter = RateLimiter(max_requests=2, window_seconds=10, clock=clock)
        self.assertTrue(limiter.allow("k"))
        self.assertTrue(limiter.allow("k"))
        self.assertFalse(limiter.allow("k"))
        clock.advance(10.1)
        self.assertTrue(limiter.allow("k"))

    def test_keys_are_independent(self):
        clock = FakeClock()
        limiter = RateLimiter(max_requests=1, window_seconds=10, clock=clock)
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))

    def test_storage_is_pruned_and_bounded(self):
        clock = FakeClock()
        limiter = RateLimiter(max_requests=5, window_seconds=1, clock=clock)
        for i in range(50):
            limiter.allow(f"key-{i}")
        self.assertEqual(limiter.size(), 50)
        # Past 2x the window, every one of those old entries is stale and
        # must be pruned on the next call, regardless of how many distinct
        # keys were ever seen.
        clock.advance(2.5)
        limiter.allow("fresh-key")
        self.assertEqual(limiter.size(), 1)

    def test_thread_safety_under_concurrent_access(self):
        import time

        limiter = RateLimiter(max_requests=1000, window_seconds=10, clock=time.monotonic)
        allowed_count = [0]
        lock = threading.Lock()

        def worker():
            if limiter.allow("shared-key"):
                with lock:
                    allowed_count[0] += 1

        threads = [threading.Thread(target=worker) for _ in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(allowed_count[0], 200)

    def test_rejects_non_positive_arguments(self):
        with self.assertRaises(ValueError):
            RateLimiter(max_requests=0, window_seconds=10, clock=lambda: 0.0)
        with self.assertRaises(ValueError):
            RateLimiter(max_requests=5, window_seconds=0, clock=lambda: 0.0)


if __name__ == "__main__":
    unittest.main()
