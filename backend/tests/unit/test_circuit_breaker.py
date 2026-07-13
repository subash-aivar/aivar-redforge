"""Tests for DefaultCircuitBreaker — Sprint 26."""

from __future__ import annotations

import asyncio

import pytest

from redforge.application.platform.circuit_breaker import (
    CircuitBreakerRegistry,
    CircuitOpenError,
    DefaultCircuitBreaker,
)
from redforge.application.platform.runtime_contracts import CircuitState


async def _ok() -> str:
    return "ok"


async def _fail() -> None:
    raise ValueError("boom")


class TestCircuitBreakerClosed:
    async def test_initial_state_is_closed(self) -> None:
        cb = DefaultCircuitBreaker("svc", failure_threshold=3)
        assert cb.state == CircuitState.CLOSED

    async def test_success_stays_closed(self) -> None:
        cb = DefaultCircuitBreaker("svc", failure_threshold=3)
        result = await cb.execute(lambda: _ok())
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

    async def test_failure_below_threshold_stays_closed(self) -> None:
        cb = DefaultCircuitBreaker("svc", failure_threshold=3, window_size=5)
        for _ in range(2):
            with pytest.raises(ValueError):
                await cb.execute(lambda: _fail())
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 2

    async def test_failure_at_threshold_opens(self) -> None:
        cb = DefaultCircuitBreaker("svc", failure_threshold=3, window_size=5)
        for _ in range(3):
            with pytest.raises(ValueError):
                await cb.execute(lambda: _fail())
        assert cb.state == CircuitState.OPEN

    async def test_sliding_window_evicts_old_failures(self) -> None:
        cb = DefaultCircuitBreaker("svc", failure_threshold=3, window_size=3)
        # 2 failures then 2 successes; window now has [fail, ok, ok] = 1 failure
        for _ in range(2):
            with pytest.raises(ValueError):
                await cb.execute(lambda: _fail())
        await cb.execute(lambda: _ok())
        await cb.execute(lambda: _ok())
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 1  # window=[fail,ok,ok], first failure still in window


class TestCircuitBreakerOpen:
    async def test_open_rejects_calls(self) -> None:
        cb = DefaultCircuitBreaker("svc", failure_threshold=1, window_size=2)
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())
        assert cb.state == CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            await cb.execute(lambda: _ok())

    async def test_open_uses_fallback(self) -> None:
        cb = DefaultCircuitBreaker("svc", failure_threshold=1, window_size=2)
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())
        result = await cb.execute(lambda: _ok(), fallback=lambda: "fallback")
        assert result == "fallback"

    async def test_circuit_open_error_has_state(self) -> None:
        cb = DefaultCircuitBreaker("svc", failure_threshold=1)
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())
        try:
            await cb.execute(lambda: _ok())
        except CircuitOpenError as e:
            assert e.component_id == "svc"
            assert e.state == CircuitState.OPEN


class TestCircuitBreakerHalfOpen:
    async def test_transitions_to_half_open_after_timeout(self) -> None:
        cb = DefaultCircuitBreaker(
            "svc", failure_threshold=1, recovery_timeout_s=0.05, window_size=2
        )
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())
        assert cb.state == CircuitState.OPEN
        await asyncio.sleep(0.1)
        # Next call should be allowed (half-open probe)
        result = await cb.execute(lambda: _ok())
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

    async def test_half_open_failure_reopens(self) -> None:
        cb = DefaultCircuitBreaker(
            "svc", failure_threshold=1, recovery_timeout_s=0.05, window_size=2
        )
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())
        await asyncio.sleep(0.1)
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())
        assert cb.state == CircuitState.OPEN

    async def test_reset_forces_closed(self) -> None:
        cb = DefaultCircuitBreaker("svc", failure_threshold=1)
        with pytest.raises(ValueError):
            await cb.execute(lambda: _fail())
        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0


class TestCircuitBreakerRegistry:
    def test_register_and_get(self) -> None:
        reg = CircuitBreakerRegistry()
        cb = DefaultCircuitBreaker("svc")
        reg.register("svc", cb)
        assert reg.get("svc") is cb

    def test_get_missing_returns_none(self) -> None:
        reg = CircuitBreakerRegistry()
        assert reg.get("nonexistent") is None

    def test_get_or_create(self) -> None:
        reg = CircuitBreakerRegistry()
        cb1 = reg.get_or_create("svc", failure_threshold=3)
        cb2 = reg.get_or_create("svc")
        assert cb1 is cb2

    def test_all_states(self) -> None:
        reg = CircuitBreakerRegistry()
        reg.register("a", DefaultCircuitBreaker("a"))
        reg.register("b", DefaultCircuitBreaker("b"))
        states = reg.all_states()
        assert states == {"a": "closed", "b": "closed"}

    def test_list_names(self) -> None:
        reg = CircuitBreakerRegistry()
        reg.register("x", DefaultCircuitBreaker("x"))
        assert "x" in reg.list_names()
