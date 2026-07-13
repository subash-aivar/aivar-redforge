"""Circuit Breaker — Sprint 26.

Three-state machine: CLOSED → OPEN → HALF_OPEN → CLOSED.

State transitions:
    CLOSED:    Count failures in sliding window.
               If failures >= failure_threshold → OPEN.
    OPEN:      Reject all calls with CircuitOpenError.
               After recovery_timeout_s → HALF_OPEN.
    HALF_OPEN: Allow up to half_open_max_calls probes.
               First success → CLOSED (reset counts).
               Any failure → OPEN (restart timeout).

Sliding window:
    Fixed-size deque of boolean outcomes (True=success, False=failure).
    Only the last `window_size` calls determine the failure count.
    This bounds memory regardless of call volume.

Design rules:
- No infrastructure imports.
- Thread-safe via threading.Lock (safe in asyncio + background threads).
- All state transitions are atomic under the lock.
- execute() never holds the lock while awaiting the coroutine.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import TYPE_CHECKING, Any

from redforge.application.platform.runtime_contracts import CircuitState

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


class CircuitOpenError(Exception):
    """Raised when a call is rejected because the circuit is OPEN."""

    def __init__(self, component_id: str, state: CircuitState) -> None:
        super().__init__(
            f"Circuit {component_id!r} is {state.value} — call rejected"
        )
        self.component_id = component_id
        self.state = state


class DefaultCircuitBreaker:
    """Production circuit breaker with sliding-window failure detection.

    Usage::

        cb = DefaultCircuitBreaker(
            component_id="event_store",
            failure_threshold=5,
            recovery_timeout_s=30.0,
            window_size=10,
        )
        try:
            result = await cb.execute(lambda: event_store.append(batch))
        except CircuitOpenError:
            # dependency is down, serve from cache or return degraded response
            ...
    """

    def __init__(
        self,
        component_id: str,
        failure_threshold: int = 5,
        recovery_timeout_s: float = 30.0,
        window_size: int = 10,
        half_open_max_calls: int = 1,
    ) -> None:
        self._component_id = component_id
        self._failure_threshold = failure_threshold
        self._recovery_timeout_s = recovery_timeout_s
        self._window_size = window_size
        self._half_open_max_calls = half_open_max_calls

        self._lock = threading.Lock()
        self._state = CircuitState.CLOSED
        self._window: deque[bool] = deque(maxlen=window_size)  # True=success
        self._open_at: float | None = None
        self._half_open_calls: int = 0

    # ── Public interface ───────────────────────────────────────────────────

    async def execute(
        self,
        coro_factory: Callable[[], Awaitable[Any]],
        fallback: Callable[[], Any] | None = None,
    ) -> Any:
        """Execute the coroutine respecting circuit state.

        Args:
            coro_factory: Zero-argument callable returning an awaitable.
            fallback: Optional zero-argument sync callable invoked when circuit
                      is OPEN instead of raising CircuitOpenError.

        Raises:
            CircuitOpenError: When OPEN and no fallback is provided.
        """
        with self._lock:
            allowed, current_state = self._check_and_maybe_transition()

        if not allowed:
            if fallback is not None:
                return fallback()
            raise CircuitOpenError(self._component_id, current_state)

        try:
            result = await coro_factory()
            self._on_success()
            return result
        except Exception:
            self._on_failure()
            raise

    @property
    def state(self) -> CircuitState:
        with self._lock:
            return self._state

    @property
    def failure_count(self) -> int:
        with self._lock:
            return sum(1 for ok in self._window if not ok)

    @property
    def success_count(self) -> int:
        with self._lock:
            return sum(1 for ok in self._window if ok)

    @property
    def component_id(self) -> str:
        return self._component_id

    def reset(self) -> None:
        """Manually force circuit to CLOSED and clear the window."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._window.clear()
            self._open_at = None
            self._half_open_calls = 0

    # ── State machine (must be called under lock) ──────────────────────────

    def _check_and_maybe_transition(self) -> tuple[bool, CircuitState]:
        """Return (allowed, current_state). May transition OPEN → HALF_OPEN."""
        if self._state == CircuitState.CLOSED:
            return True, CircuitState.CLOSED

        if self._state == CircuitState.OPEN:
            if self._open_at is not None:
                elapsed = time.monotonic() - self._open_at
                if elapsed >= self._recovery_timeout_s:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 1  # count this caller
                    return True, CircuitState.HALF_OPEN
            return False, CircuitState.OPEN

        # HALF_OPEN
        if self._half_open_calls < self._half_open_max_calls:
            self._half_open_calls += 1
            return True, CircuitState.HALF_OPEN
        return False, CircuitState.HALF_OPEN

    def _on_success(self) -> None:
        with self._lock:
            self._window.append(True)
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.CLOSED
                self._window.clear()
                self._open_at = None
                self._half_open_calls = 0

    def _on_failure(self) -> None:
        with self._lock:
            self._window.append(False)
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._open_at = time.monotonic()
                self._half_open_calls = 0
            elif self._state == CircuitState.CLOSED:
                failures = sum(1 for ok in self._window if not ok)
                if failures >= self._failure_threshold:
                    self._state = CircuitState.OPEN
                    self._open_at = time.monotonic()

    # ── Async context manager support ─────────────────────────────────────

    async def __aenter__(self) -> DefaultCircuitBreaker:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False


class CircuitBreakerRegistry:
    """Thread-safe registry of named circuit breakers.

    Usage::

        registry = CircuitBreakerRegistry()
        registry.register("event_store", DefaultCircuitBreaker("event_store"))
        cb = registry.get("event_store")
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._breakers: dict[str, DefaultCircuitBreaker] = {}

    def register(self, name: str, breaker: DefaultCircuitBreaker) -> None:
        with self._lock:
            self._breakers[name] = breaker

    def get(self, name: str) -> DefaultCircuitBreaker | None:
        with self._lock:
            return self._breakers.get(name)

    def get_or_create(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout_s: float = 30.0,
        window_size: int = 10,
    ) -> DefaultCircuitBreaker:
        with self._lock:
            if name not in self._breakers:
                self._breakers[name] = DefaultCircuitBreaker(
                    component_id=name,
                    failure_threshold=failure_threshold,
                    recovery_timeout_s=recovery_timeout_s,
                    window_size=window_size,
                )
            return self._breakers[name]

    def all_states(self) -> dict[str, str]:
        with self._lock:
            return {name: cb._state.value for name, cb in self._breakers.items()}

    def reset_all(self) -> None:
        with self._lock:
            for cb in self._breakers.values():
                cb.reset()

    def list_names(self) -> list[str]:
        with self._lock:
            return list(self._breakers.keys())
