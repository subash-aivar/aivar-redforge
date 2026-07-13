"""Unit tests for retry strategy — Sprint 25."""

from __future__ import annotations

import pytest

from redforge.application.platform.retry_strategy import (
    RetryableError,
    RetryConfig,
    RetryExecutor,
)


class TestRetryConfig:
    def test_defaults_valid(self) -> None:
        cfg = RetryConfig()
        assert cfg.max_attempts == 3
        assert cfg.base_delay_s == 0.1

    def test_no_retry_factory(self) -> None:
        cfg = RetryConfig.no_retry()
        assert cfg.max_attempts == 1

    def test_aggressive_factory(self) -> None:
        cfg = RetryConfig.aggressive()
        assert cfg.max_attempts == 5

    def test_invalid_max_attempts(self) -> None:
        with pytest.raises(ValueError):
            RetryConfig(max_attempts=0)

    def test_invalid_jitter_factor(self) -> None:
        with pytest.raises(ValueError):
            RetryConfig(jitter_factor=1.5)

    def test_delay_zero_for_first_attempt(self) -> None:
        cfg = RetryConfig(base_delay_s=5.0, jitter_factor=0.0)
        assert cfg.delay_for_attempt(0) == 0.0

    def test_delay_doubles(self) -> None:
        cfg = RetryConfig(base_delay_s=1.0, max_delay_s=100.0, jitter_factor=0.0)
        assert cfg.delay_for_attempt(1) == 1.0
        assert cfg.delay_for_attempt(2) == 2.0
        assert cfg.delay_for_attempt(3) == 4.0

    def test_delay_capped_at_max(self) -> None:
        cfg = RetryConfig(base_delay_s=1.0, max_delay_s=3.0, jitter_factor=0.0)
        assert cfg.delay_for_attempt(10) == 3.0


class TestRetryExecutor:
    @pytest.mark.asyncio
    async def test_succeeds_on_first_try(self) -> None:
        cfg = RetryConfig.no_retry()
        result = await RetryExecutor(cfg).execute(lambda: _return(42))
        assert result == 42

    @pytest.mark.asyncio
    async def test_retries_on_retryable_exception(self) -> None:
        calls = [0]

        async def flaky() -> int:
            calls[0] += 1
            if calls[0] < 3:
                raise RetryableError("transient")
            return calls[0]

        cfg = RetryConfig(max_attempts=3, base_delay_s=0.0, jitter_factor=0.0)
        result = await RetryExecutor(cfg).execute(flaky)
        assert result == 3
        assert calls[0] == 3

    @pytest.mark.asyncio
    async def test_raises_after_max_attempts(self) -> None:
        async def always_fail() -> int:
            raise RetryableError("always")

        cfg = RetryConfig(max_attempts=2, base_delay_s=0.0)
        with pytest.raises(RetryableError):
            await RetryExecutor(cfg).execute(always_fail)

    @pytest.mark.asyncio
    async def test_non_retryable_exception_propagates_immediately(self) -> None:
        calls = [0]

        async def bad() -> int:
            calls[0] += 1
            raise ValueError("fatal")

        cfg = RetryConfig(max_attempts=5, base_delay_s=0.0)
        with pytest.raises(ValueError):
            await RetryExecutor(cfg).execute(bad)
        assert calls[0] == 1  # no retries

    @pytest.mark.asyncio
    async def test_custom_retryable_exception(self) -> None:
        calls = [0]

        class MyError(Exception):
            pass

        async def fails_twice() -> str:
            calls[0] += 1
            if calls[0] < 3:
                raise MyError("temp")
            return "ok"

        cfg = RetryConfig(max_attempts=3, base_delay_s=0.0)
        result = await RetryExecutor(cfg).execute(
            fails_twice,
            retryable_exceptions=(MyError,),
        )
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_execute_with_outcome_no_raise(self) -> None:
        async def always_fail() -> int:
            raise RetryableError("x")

        cfg = RetryConfig(max_attempts=2, base_delay_s=0.0)
        value, outcome = await RetryExecutor(cfg).execute_with_outcome(always_fail)
        assert value is None
        assert not outcome.succeeded
        assert outcome.attempts == 2

    @pytest.mark.asyncio
    async def test_execute_with_outcome_success(self) -> None:
        async def succeed() -> str:
            return "done"

        cfg = RetryConfig()
        value, outcome = await RetryExecutor(cfg).execute_with_outcome(succeed)
        assert value == "done"
        assert outcome.succeeded
        assert outcome.attempts == 1


async def _return(v: int) -> int:
    return v
