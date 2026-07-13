"""Unit tests for rate limiting infrastructure."""

import pytest

from redforge.infrastructure.rate_limiting import InMemorySlidingWindowLimiter


class TestInMemorySlidingWindowLimiter:
    """Tests for sliding window rate limiter."""

    @pytest.fixture
    def limiter(self) -> InMemorySlidingWindowLimiter:
        return InMemorySlidingWindowLimiter()

    async def test_allows_under_limit(self, limiter: InMemorySlidingWindowLimiter) -> None:
        result = await limiter.check("ip:1.2.3.4", max_requests=5, window_seconds=60)
        assert result.allowed is True
        assert result.remaining == 4
        assert result.limit == 5
        assert result.retry_after_seconds == 0

    async def test_allows_up_to_limit(self, limiter: InMemorySlidingWindowLimiter) -> None:
        for _ in range(5):
            result = await limiter.check("ip:1.2.3.4", max_requests=5, window_seconds=60)
        assert result.allowed is True
        assert result.remaining == 0

    async def test_blocks_over_limit(self, limiter: InMemorySlidingWindowLimiter) -> None:
        for _ in range(5):
            await limiter.check("ip:1.2.3.4", max_requests=5, window_seconds=60)

        result = await limiter.check("ip:1.2.3.4", max_requests=5, window_seconds=60)
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after_seconds > 0

    async def test_different_keys_independent(
        self, limiter: InMemorySlidingWindowLimiter
    ) -> None:
        for _ in range(5):
            await limiter.check("ip:1.1.1.1", max_requests=5, window_seconds=60)

        # Different key should not be affected
        result = await limiter.check("ip:2.2.2.2", max_requests=5, window_seconds=60)
        assert result.allowed is True

    async def test_reset_clears_history(self, limiter: InMemorySlidingWindowLimiter) -> None:
        for _ in range(5):
            await limiter.check("ip:1.2.3.4", max_requests=5, window_seconds=60)

        await limiter.reset("ip:1.2.3.4")
        result = await limiter.check("ip:1.2.3.4", max_requests=5, window_seconds=60)
        assert result.allowed is True
        assert result.remaining == 4

    async def test_per_user_key(self, limiter: InMemorySlidingWindowLimiter) -> None:
        """User-scoped keys work independently from IP keys."""
        for _ in range(3):
            await limiter.check("user:alice@example.com", max_requests=3, window_seconds=60)

        # User is blocked
        result = await limiter.check("user:alice@example.com", max_requests=3, window_seconds=60)
        assert result.allowed is False

        # But IP is still allowed
        result = await limiter.check("ip:10.0.0.1", max_requests=5, window_seconds=60)
        assert result.allowed is True

    async def test_retry_after_is_positive(
        self, limiter: InMemorySlidingWindowLimiter
    ) -> None:
        for _ in range(5):
            await limiter.check("ip:x", max_requests=5, window_seconds=60)
        result = await limiter.check("ip:x", max_requests=5, window_seconds=60)
        assert result.retry_after_seconds >= 1
