"""Small thread-safe in-memory rate limiter.

Fixed-window counter per key. State resets on process restart (acceptable
- see B8B1B design notes: this is a localhost-only slice, not a durable
rate-limit service). Bounded memory: every call prunes windows old enough
that they can no longer affect any future decision, so an attacker who
tries many distinct token digests cannot grow this structure without
bound - entries age out automatically as time passes, independent of how
many distinct keys were ever seen.
"""
import threading


class RateLimiter:
    def __init__(self, max_requests, window_seconds, clock):
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._windows = {}  # key -> (window_start, count)

    def allow(self, key):
        now = self._clock()
        with self._lock:
            self._prune_locked(now)
            window_start, count = self._windows.get(key, (now, 0))
            if now - window_start >= self._window_seconds:
                window_start, count = now, 0
            if count >= self._max_requests:
                self._windows[key] = (window_start, count)
                return False
            self._windows[key] = (window_start, count + 1)
            return True

    def _prune_locked(self, now):
        # A window strictly older than 2x its own length can never again
        # affect a decision (the next `allow()` for that key would already
        # start a fresh window), so it is safe to drop.
        stale_after = self._window_seconds * 2
        expired = [key for key, (start, _count) in self._windows.items() if now - start >= stale_after]
        for key in expired:
            del self._windows[key]

    def size(self):
        """Current number of tracked keys - test/introspection only."""
        with self._lock:
            return len(self._windows)
