"""Rate limiting infrastructure.

Protocol-based abstraction supporting:
- In-memory sliding window (default, single-process)
- Redis sliding window (production, multi-process)

Usage:
    limiter = InMemorySlidingWindowLimiter()
    result = await limiter.check("ip:192.168.1.1", max_requests=10, window_seconds=60)
    if not result.allowed:
        # Return 429 with Retry-After header
"""

from redforge.infrastructure.rate_limiting.contracts import RateLimiter, RateLimitResult
from redforge.infrastructure.rate_limiting.sliding_window import (
    InMemorySlidingWindowLimiter,
)

__all__ = ["InMemorySlidingWindowLimiter", "RateLimitResult", "RateLimiter"]
