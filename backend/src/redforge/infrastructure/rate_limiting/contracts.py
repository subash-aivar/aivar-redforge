"""Rate limiting contracts.

Protocol-based abstraction for rate limiting implementations.
Allows swapping between in-memory (dev/test) and Redis (production)
without changing application logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    remaining: int
    limit: int
    retry_after_seconds: int  # 0 if allowed


@runtime_checkable
class RateLimiter(Protocol):
    """Port for rate limiting. Implementations: in-memory, Redis, etc."""

    async def check(
        self, key: str, max_requests: int, window_seconds: int
    ) -> RateLimitResult:
        """Check if a request is allowed for the given key.

        Args:
            key: Unique identifier (e.g., "ip:1.2.3.4" or "user:abc123")
            max_requests: Maximum requests allowed in the window
            window_seconds: Sliding window size in seconds

        Returns:
            RateLimitResult with allowed status and metadata
        """
        ...

    async def reset(self, key: str) -> None:
        """Reset the rate limit counter for a key (admin use)."""
        ...
