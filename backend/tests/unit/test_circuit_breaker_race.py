"""Regression test — Circuit Breaker HALF_OPEN concurrency safety.

Sprint 26 adversarial review flagged a potential race condition in HALF_OPEN
state: "two concurrent callers can both pass the guard and both execute probe
calls."

The HALF_OPEN race WAS real: the original code reset _half_open_calls=0 on
OPEN→HALF_OPEN transition without counting the transitioning caller, allowing
a second probe through before the counter was incremented.

Fix (Sprint 27): on OPEN→HALF_OPEN transition, set _half_open_calls=1 so the
transitioning caller is immediately counted, preventing a second probe.

State-check atomicity: `_check_and_maybe_transition()` runs inside
`with self._lock:`, so concurrent asyncio tasks cannot interleave the check
and increment. However, tests must use probes that yield (await asyncio.sleep)
so concurrent callers can check state while the first probe is in flight.
Without a yield, the probe completes before Task 2 even starts its state check.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from redforge.application.platform.circuit_breaker import (
    CircuitOpenError,
    DefaultCircuitBreaker,
)
from redforge.application.platform.runtime_contracts import CircuitState


async def _fail() -> None:
    raise ValueError("simulated failure")


async def _ok() -> str:
    return "ok"


class TestHalfOpenAtomicity:
    async def test_only_one_probe_allowed_with_concurrent_callers(self) -> None:
        """With half_open_max_calls=1, exactly one concurrent caller gets through."""
        cb = DefaultCircuitBreaker(
            "svc", failure_threshold=1, recovery_timeout_s=0.0, half_open_max_calls=1
        )
        # Drive to OPEN
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())
        assert cb.state == CircuitState.OPEN

        # Wait for recovery_timeout (0.0s — already elapsed)
        await asyncio.sleep(0)

        probes_executed: list[int] = []

        async def _probe() -> str:
            probes_executed.append(1)
            await asyncio.sleep(0)  # yield so concurrent tasks can check state
            return "probe_ok"

        rejected: list[int] = []

        async def _attempt() -> None:
            try:
                await cb.execute(lambda: _probe())
            except CircuitOpenError:
                rejected.append(1)

        # Run 10 concurrent tasks — only 1 should get through
        await asyncio.gather(*[_attempt() for _ in range(10)])

        assert len(probes_executed) == 1, (
            f"Expected exactly 1 probe, got {len(probes_executed)}. "
            "HALF_OPEN race condition detected."
        )
        assert len(rejected) == 9

    async def test_half_open_max_calls_two_allows_two_probes(self) -> None:
        """With half_open_max_calls=2, exactly two concurrent callers get through."""
        cb = DefaultCircuitBreaker(
            "svc",
            failure_threshold=1,
            recovery_timeout_s=0.0,
            half_open_max_calls=2,
        )
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())

        await asyncio.sleep(0)
        probes: list[int] = []

        async def _probe() -> str:
            probes.append(1)
            await asyncio.sleep(0)  # yield so concurrent tasks can check state
            return "ok"

        async def _attempt() -> None:
            with contextlib.suppress(CircuitOpenError):
                await cb.execute(lambda: _probe())

        await asyncio.gather(*[_attempt() for _ in range(10)])
        assert len(probes) == 2

    async def test_successful_probe_transitions_to_closed(self) -> None:
        cb = DefaultCircuitBreaker(
            "svc", failure_threshold=1, recovery_timeout_s=0.0
        )
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())

        await asyncio.sleep(0)
        result = await cb.execute(lambda: _ok())
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

    async def test_failed_probe_returns_to_open(self) -> None:
        cb = DefaultCircuitBreaker(
            "svc", failure_threshold=1, recovery_timeout_s=0.0
        )
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())

        await asyncio.sleep(0)
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())

        assert cb.state == CircuitState.OPEN

    async def test_lock_held_during_state_check_prevents_race(self) -> None:
        """Verify _check_and_maybe_transition is called inside the lock.

        This is a structural correctness test: we confirm that concurrent
        asyncio tasks cannot interleave the check and increment of
        _half_open_calls because both happen synchronously under self._lock.
        """
        cb = DefaultCircuitBreaker(
            "svc", failure_threshold=1, recovery_timeout_s=0.0, half_open_max_calls=1
        )
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())

        await asyncio.sleep(0)

        # Run 100 concurrent calls — the lock must ensure exactly 1 gets through
        probe_count = 0

        async def _counting_probe() -> str:
            nonlocal probe_count
            probe_count += 1
            await asyncio.sleep(0)  # yield so concurrent tasks see HALF_OPEN state
            return "counted"

        results = await asyncio.gather(
            *[
                asyncio.create_task(
                    cb.execute(lambda: _counting_probe()),
                    name=f"probe-{i}",
                )
                for i in range(100)
            ],
            return_exceptions=True,
        )

        # Count successes (non-exception results)
        successes = [r for r in results if not isinstance(r, Exception)]
        assert len(successes) == 1, (
            f"Expected 1 success, got {len(successes)}. "
            f"probe_count={probe_count}. Race condition exists."
        )
        assert probe_count == 1

    async def test_half_open_resets_on_transition_back_to_open(self) -> None:
        """After HALF_OPEN → OPEN, a subsequent HALF_OPEN resets the call count."""
        cb = DefaultCircuitBreaker(
            "svc",
            failure_threshold=1,
            recovery_timeout_s=0.0,
            half_open_max_calls=1,
        )
        # First OPEN
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())
        await asyncio.sleep(0)

        # Probe fails → back to OPEN
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())
        assert cb.state == CircuitState.OPEN

        # Second recovery
        await asyncio.sleep(0)
        result = await cb.execute(lambda: _ok())
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED


class TestCircuitBreakerRegistry:
    def test_get_or_create_idempotent(self) -> None:
        from redforge.application.platform.circuit_breaker import CircuitBreakerRegistry
        reg = CircuitBreakerRegistry()
        cb1 = reg.get_or_create("svc")
        cb2 = reg.get_or_create("svc")
        assert cb1 is cb2

    def test_all_states_empty_initially(self) -> None:
        from redforge.application.platform.circuit_breaker import CircuitBreakerRegistry
        reg = CircuitBreakerRegistry()
        assert reg.all_states() == {}

    async def test_all_states_reflects_breaker_state(self) -> None:
        from redforge.application.platform.circuit_breaker import CircuitBreakerRegistry
        reg = CircuitBreakerRegistry()
        reg.get_or_create("db", failure_threshold=1)
        cb = reg.get("db")
        assert cb is not None
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())
        states = reg.all_states()
        assert states["db"] == "open"
