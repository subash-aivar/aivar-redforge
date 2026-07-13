"""In-memory sliding window rate limiter.

Uses a sorted list of timestamps per key. On each check, removes
expired entries and counts remaining. Thread-safe for async usage
within a single process.

For multi-process production deployments, replace with Redis-backed
implementation using the same RateLimiter protocol.
"""

from __future__ import annotations

import time
from collections import defaultdict

from redforge.infrastructure.rate_limiting.contracts import RateLimitResult


class InMemorySlidingWindowLimiter:
    """Sliding window rate limiter backed by in-memory storage.

    Suitable for single-process deployments and testing.
    For multi-worker production, use RedisSlidingWindowLimiter.
    """

    def __init__(self) -> None:
        self._windows: dict[str, list[float]] = defaultdict(list)

    async def check(
        self, key: str, max_requests: int, window_seconds: int
    ) -> RateLimitResult:
        """Check if a request is allowed under the sliding window.

        Removes expired timestamps, then checks if the count is within limits.
        """
        now = time.time()
        cutoff = now - window_seconds
        window = self._windows[key]

        # Remove expired entries (sliding window)
        window[:] = [ts for ts in window if ts > cutoff]

        if len(window) < max_requests:
            window.append(now)
            return RateLimitResult(
                allowed=True,
                remaining=max_requests - len(window),
                limit=max_requests,
                retry_after_seconds=0,
            )

        # Rate limited — calculate retry-after from oldest entry
        oldest = window[0] if window else now
        retry_after = int(oldest + window_seconds - now) + 1

        return RateLimitResult(
            allowed=False,
            remaining=0,
            limit=max_requests,
            retry_after_seconds=max(retry_after, 1),
        )

    async def reset(self, key: str) -> None:
        """Clear all entries for a key."""
        self._windows.pop(key, None)
