"""Retry strategy for transient failures — Sprint 25.

Provides:
- RetryConfig: frozen configuration (max retries, backoff, jitter).
- RetryExecutor: generic async retry loop with exponential backoff + jitter.
- RetryableError: marker exception so callers distinguish retryable failures.

Design rules:
- No imports from infrastructure layer.
- Retry logic is stateless — RetryConfig holds all parameters.
- Jitter is additive to prevent thundering-herd on concurrent retries.
- Concrete exception types to retry on are caller-supplied — no hardcoding.

Usage::

    config = RetryConfig(max_attempts=3, base_delay_s=0.1, max_delay_s=5.0)
    result = await RetryExecutor(config).execute(
        coro_factory=lambda: event_store.append(batch),
        retryable_exceptions=(OptimisticConcurrencyError,),
    )
"""

from __future__ import annotations

import asyncio
import dataclasses
import random
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

T = TypeVar("T")


class RetryableError(Exception):
    """Marker for errors that should trigger a retry.

    Implementations may raise RetryableError to signal the executor
    that the operation should be retried without knowing the config.
    """


@dataclasses.dataclass(frozen=True, slots=True)
class RetryConfig:
    """Configuration for exponential-backoff retry with jitter.

    Attributes:
        max_attempts: Total attempts including the first try. Must be >= 1.
        base_delay_s: Initial delay in seconds. Doubles on each retry.
        max_delay_s: Cap on delay before jitter is added.
        jitter_factor: Random jitter as a fraction of the current delay.
            0.0 = no jitter. 0.25 = ±25% of delay. Max 1.0.
    """

    max_attempts: int = 3
    base_delay_s: float = 0.1
    max_delay_s: float = 30.0
    jitter_factor: float = 0.25

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.base_delay_s < 0:
            raise ValueError("base_delay_s must be non-negative")
        if self.max_delay_s < self.base_delay_s:
            raise ValueError("max_delay_s must be >= base_delay_s")
        if not 0.0 <= self.jitter_factor <= 1.0:
            raise ValueError("jitter_factor must be in [0, 1]")

    def delay_for_attempt(self, attempt: int) -> float:
        """Return delay in seconds before attempt `attempt` (0-indexed).

        Attempt 0 → no delay (first try).
        Attempt 1 → base_delay_s ± jitter.
        Attempt 2 → 2 * base_delay_s ± jitter.
        ...capped at max_delay_s.
        """
        if attempt == 0:
            return 0.0
        delay: float = min(self.base_delay_s * (2 ** (attempt - 1)), self.max_delay_s)
        if self.jitter_factor > 0:
            jitter: float = delay * self.jitter_factor * (random.random() * 2 - 1)
            delay = max(0.0, delay + jitter)
        return delay

    @classmethod
    def no_retry(cls) -> RetryConfig:
        return cls(max_attempts=1, base_delay_s=0.0, max_delay_s=0.0)

    @classmethod
    def aggressive(cls) -> RetryConfig:
        return cls(max_attempts=5, base_delay_s=0.05, max_delay_s=2.0)

    @classmethod
    def conservative(cls) -> RetryConfig:
        return cls(max_attempts=3, base_delay_s=1.0, max_delay_s=30.0)


@dataclasses.dataclass(frozen=True, slots=True)
class RetryOutcome:
    """Result of a retry execution."""

    succeeded: bool
    attempts: int
    last_error: BaseException | None = None


class RetryExecutor:
    """Executes an async operation with exponential-backoff retry.

    Usage::

        executor = RetryExecutor(RetryConfig(max_attempts=3))
        value = await executor.execute(
            coro_factory=lambda: my_async_fn(arg),
            retryable_exceptions=(TransientError, TimeoutError),
        )
    """

    def __init__(self, config: RetryConfig) -> None:
        self._config = config

    async def execute(
        self,
        coro_factory: Callable[[], Awaitable[T]],
        retryable_exceptions: tuple[type[BaseException], ...] = (RetryableError,),
    ) -> T:
        """Execute the coroutine factory with retry on specified exceptions.

        Args:
            coro_factory: Zero-argument callable that returns an awaitable.
                Called freshly on each attempt.
            retryable_exceptions: Tuple of exception types that trigger retry.
                Other exceptions propagate immediately.

        Returns:
            The result of the first successful attempt.

        Raises:
            The last exception if all attempts are exhausted.
        """
        last_exc: BaseException | None = None
        for attempt in range(self._config.max_attempts):
            delay = self._config.delay_for_attempt(attempt)
            if delay > 0:
                await asyncio.sleep(delay)
            try:
                return await coro_factory()
            except retryable_exceptions as exc:
                last_exc = exc
                continue
            except BaseException:
                raise

        assert last_exc is not None
        raise last_exc

    async def execute_with_outcome(
        self,
        coro_factory: Callable[[], Awaitable[T]],
        retryable_exceptions: tuple[type[BaseException], ...] = (RetryableError,),
    ) -> tuple[T | None, RetryOutcome]:
        """Like execute() but never raises — returns outcome with error info."""
        last_exc: BaseException | None = None
        for attempt in range(self._config.max_attempts):
            delay = self._config.delay_for_attempt(attempt)
            if delay > 0:
                await asyncio.sleep(delay)
            try:
                result = await coro_factory()
                return result, RetryOutcome(
                    succeeded=True,
                    attempts=attempt + 1,
                )
            except retryable_exceptions as exc:
                last_exc = exc
            except BaseException as exc:
                return None, RetryOutcome(
                    succeeded=False,
                    attempts=attempt + 1,
                    last_error=exc,
                )
        return None, RetryOutcome(
            succeeded=False,
            attempts=self._config.max_attempts,
            last_error=last_exc,
        )
