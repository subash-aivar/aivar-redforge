"""Vendor-neutral metrics abstraction — Sprint 26.

Provides a clean interface for recording metrics WITHOUT any direct
dependency on Prometheus, Datadog, StatsD, or OpenTelemetry SDK.

Adapter pattern:
    The MetricsCollector protocol (in runtime_contracts.py) defines the
    interface. Adapters implement it for each vendor:
    - PrometheusMetricsAdapter (in infrastructure layer, NOT here)
    - DatadogMetricsAdapter (in infrastructure layer, NOT here)
    - InMemoryMetricsCollector (here — for testing and development)

InMemoryMetricsCollector:
    Stores samples in a bounded deque. The snapshot() method returns all
    samples for inspection in tests. Suitable for single-process deployments
    that export via a periodic push rather than a scrape endpoint.

Design rules:
- NO prometheus_client, datadog, statsd, or opentelemetry imports.
- InMemoryMetricsCollector is the only concrete implementation here.
- Labels are dict[str, str] at call site; stored as sorted tuples for hashability.
- All record_* methods are SYNC (hot path — called per event, per request).
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import UTC, datetime

from redforge.application.platform.runtime_contracts import MetricSample, MetricType


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _normalise_labels(
    labels: dict[str, str] | None,
) -> tuple[tuple[str, str], ...]:
    if labels is None:
        return ()
    return tuple(sorted(labels.items()))


class InMemoryMetricsCollector:
    """Bounded in-memory metrics store for testing and development.

    Stores the last `max_samples` observations across all metric names.
    Thread-safe for concurrent record_* calls.

    Usage in tests::

        collector = InMemoryMetricsCollector()
        collector.record_counter("events_processed", labels={"projection": "campaign"})
        samples = collector.snapshot("events_processed")
        assert len(samples) == 1
    """

    def __init__(self, max_samples: int = 10_000) -> None:
        self._max_samples = max_samples
        self._lock = threading.Lock()
        self._samples: deque[MetricSample] = deque(maxlen=max_samples)

    def record_counter(
        self,
        name: str,
        value: float = 1.0,
        labels: dict[str, str] | None = None,
    ) -> None:
        self._append(MetricSample(
            name=name,
            value=value,
            metric_type=MetricType.COUNTER,
            labels=_normalise_labels(labels),
            sampled_at=_utc_now(),
        ))

    def record_gauge(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        self._append(MetricSample(
            name=name,
            value=value,
            metric_type=MetricType.GAUGE,
            labels=_normalise_labels(labels),
            sampled_at=_utc_now(),
        ))

    def record_histogram(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        self._append(MetricSample(
            name=name,
            value=value,
            metric_type=MetricType.HISTOGRAM,
            labels=_normalise_labels(labels),
            sampled_at=_utc_now(),
        ))

    def snapshot(self, name: str | None = None) -> list[MetricSample]:
        """Return all stored samples, optionally filtered by metric name."""
        with self._lock:
            if name is None:
                return list(self._samples)
            return [s for s in self._samples if s.name == name]

    def last_value(self, name: str) -> float | None:
        """Return the most recently recorded value for a metric name."""
        with self._lock:
            for sample in reversed(self._samples):
                if sample.name == name:
                    return sample.value
            return None

    def sum_counter(self, name: str) -> float:
        """Sum all counter observations for a metric name."""
        with self._lock:
            return sum(
                s.value for s in self._samples
                if s.name == name and s.metric_type == MetricType.COUNTER
            )

    def clear(self) -> None:
        with self._lock:
            self._samples.clear()

    def _append(self, sample: MetricSample) -> None:
        with self._lock:
            self._samples.append(sample)

    @property
    def total_samples(self) -> int:
        with self._lock:
            return len(self._samples)


class NoopMetricsCollector:
    """No-op metrics collector that discards all observations.

    Use when metrics are disabled (e.g., in lightweight deployments
    where the overhead of InMemory storage is undesirable).
    """

    def record_counter(
        self, name: str, value: float = 1.0, labels: dict[str, str] | None = None
    ) -> None:
        pass

    def record_gauge(
        self, name: str, value: float, labels: dict[str, str] | None = None
    ) -> None:
        pass

    def record_histogram(
        self, name: str, value: float, labels: dict[str, str] | None = None
    ) -> None:
        pass


class CompositeMetricsCollector:
    """Fan-out to multiple MetricsCollector implementations simultaneously.

    Allows recording to both InMemory (for tests) and a real vendor
    backend at the same time during a transitional phase.
    """

    def __init__(self, collectors: list[InMemoryMetricsCollector | NoopMetricsCollector]) -> None:
        self._collectors = list(collectors)

    def record_counter(
        self, name: str, value: float = 1.0, labels: dict[str, str] | None = None
    ) -> None:
        for c in self._collectors:
            c.record_counter(name, value, labels)

    def record_gauge(
        self, name: str, value: float, labels: dict[str, str] | None = None
    ) -> None:
        for c in self._collectors:
            c.record_gauge(name, value, labels)

    def record_histogram(
        self, name: str, value: float, labels: dict[str, str] | None = None
    ) -> None:
        for c in self._collectors:
            c.record_histogram(name, value, labels)


# ── Standard metric names ──────────────────────────────────────────────────
# Centralised name registry prevents typos and enables global search.


class RuntimeMetricNames:
    """Canonical metric names for the runtime platform."""

    EVENTS_PROCESSED = "redforge.events.processed"
    EVENTS_SKIPPED = "redforge.events.skipped"
    PROJECTION_ERRORS = "redforge.projection.errors"
    PROJECTION_RESTART_COUNT = "redforge.projection.restarts"
    DLQ_DEPTH = "redforge.dlq.depth"
    DLQ_ENTRIES_ADDED = "redforge.dlq.entries_added"
    CIRCUIT_OPEN = "redforge.circuit.open"
    CIRCUIT_HALF_OPEN = "redforge.circuit.half_open"
    CIRCUIT_FAILURE_COUNT = "redforge.circuit.failure_count"
    BULKHEAD_ACTIVE_CALLS = "redforge.bulkhead.active_calls"
    BULKHEAD_REJECTED = "redforge.bulkhead.rejected"
    BACKPRESSURE_THROTTLED = "redforge.backpressure.throttled"
    WORKER_RESTART_COUNT = "redforge.worker.restarts"
    HEALTH_CHECK_DURATION_MS = "redforge.health.check_duration_ms"
    HEARTBEAT_MISSED = "redforge.heartbeat.missed"
    REPLAY_EVENTS_PROCESSED = "redforge.replay.events_processed"
    SNAPSHOT_SAVES = "redforge.snapshot.saves"
    CHECKPOINT_SAVES = "redforge.checkpoint.saves"
