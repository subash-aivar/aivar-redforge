"""Tests for InMemoryMetricsCollector and NoopMetricsCollector — Sprint 26."""

from __future__ import annotations

from redforge.application.platform.metrics_abstraction import (
    CompositeMetricsCollector,
    InMemoryMetricsCollector,
    NoopMetricsCollector,
    RuntimeMetricNames,
)
from redforge.application.platform.runtime_contracts import MetricType


class TestInMemoryMetricsCollector:
    def test_record_counter(self) -> None:
        c = InMemoryMetricsCollector()
        c.record_counter("events", 1.0, {"projection": "campaign"})
        samples = c.snapshot("events")
        assert len(samples) == 1
        assert samples[0].metric_type == MetricType.COUNTER
        assert samples[0].value == 1.0

    def test_record_gauge(self) -> None:
        c = InMemoryMetricsCollector()
        c.record_gauge("dlq_depth", 42.0)
        samples = c.snapshot("dlq_depth")
        assert samples[0].value == 42.0
        assert samples[0].metric_type == MetricType.GAUGE

    def test_record_histogram(self) -> None:
        c = InMemoryMetricsCollector()
        c.record_histogram("check_duration_ms", 12.5)
        samples = c.snapshot("check_duration_ms")
        assert samples[0].metric_type == MetricType.HISTOGRAM

    def test_labels_stored_as_sorted_tuple(self) -> None:
        c = InMemoryMetricsCollector()
        c.record_counter("ev", labels={"z": "1", "a": "2"})
        samples = c.snapshot("ev")
        assert samples[0].labels == (("a", "2"), ("z", "1"))

    def test_no_labels_stored_as_empty_tuple(self) -> None:
        c = InMemoryMetricsCollector()
        c.record_counter("ev")
        samples = c.snapshot("ev")
        assert samples[0].labels == ()

    def test_snapshot_all(self) -> None:
        c = InMemoryMetricsCollector()
        c.record_counter("a")
        c.record_gauge("b", 1.0)
        assert len(c.snapshot()) == 2

    def test_last_value(self) -> None:
        c = InMemoryMetricsCollector()
        c.record_gauge("q", 10.0)
        c.record_gauge("q", 20.0)
        assert c.last_value("q") == 20.0

    def test_last_value_missing(self) -> None:
        c = InMemoryMetricsCollector()
        assert c.last_value("nonexistent") is None

    def test_sum_counter(self) -> None:
        c = InMemoryMetricsCollector()
        c.record_counter("ev", 3.0)
        c.record_counter("ev", 5.0)
        assert c.sum_counter("ev") == 8.0

    def test_clear(self) -> None:
        c = InMemoryMetricsCollector()
        c.record_counter("ev")
        c.clear()
        assert c.total_samples == 0

    def test_bounded_max_samples(self) -> None:
        c = InMemoryMetricsCollector(max_samples=5)
        for i in range(10):
            c.record_counter(f"ev{i}")
        assert c.total_samples == 5

    def test_total_samples(self) -> None:
        c = InMemoryMetricsCollector()
        c.record_counter("a")
        c.record_gauge("b", 1.0)
        assert c.total_samples == 2


class TestNoopMetricsCollector:
    def test_noop_does_not_raise(self) -> None:
        c = NoopMetricsCollector()
        c.record_counter("ev", 1.0, {"k": "v"})
        c.record_gauge("g", 2.0)
        c.record_histogram("h", 3.0)


class TestCompositeMetricsCollector:
    def test_fans_out_to_all_collectors(self) -> None:
        a = InMemoryMetricsCollector()
        b = InMemoryMetricsCollector()
        composite = CompositeMetricsCollector([a, b])
        composite.record_counter("ev")
        assert a.total_samples == 1
        assert b.total_samples == 1

    def test_fans_out_gauge(self) -> None:
        a = InMemoryMetricsCollector()
        b = InMemoryMetricsCollector()
        composite = CompositeMetricsCollector([a, b])
        composite.record_gauge("g", 10.0)
        assert a.last_value("g") == 10.0
        assert b.last_value("g") == 10.0


class TestRuntimeMetricNames:
    def test_canonical_names_are_strings(self) -> None:
        assert RuntimeMetricNames.EVENTS_PROCESSED.startswith("redforge.")
        assert RuntimeMetricNames.DLQ_DEPTH.startswith("redforge.")
        assert RuntimeMetricNames.CIRCUIT_OPEN.startswith("redforge.")
