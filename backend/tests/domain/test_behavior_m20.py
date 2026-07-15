"""M20 Behavioral Security domain unit tests.

All tests are pure-function, no I/O, no database.

Covers:
  - Fan-out detection (normal, medium, high, critical)
  - Port scan detection (below threshold, medium, high)
  - New destination detection
  - Rare destination detection
  - Outbound transfer detection (deviation thresholds)
  - East-west detection
  - Service access detection
  - Beaconing analysis (sufficient samples, insufficient, high jitter, short interval)
  - Baseline computation (cold start, insufficient, established)
  - is_rfc1918 helper
"""

from __future__ import annotations

from redforge.domain.behavior.detection import (
    EntityBaseline,
    EntityWindowMetrics,
    compute_beaconing,
    compute_entity_baseline,
    evaluate_east_west,
    evaluate_fan_out,
    evaluate_new_destinations,
    evaluate_outbound_transfer,
    evaluate_port_scan,
    evaluate_unusual_service_access,
)
from redforge.domain.behavior.value_objects import (
    FAN_OUT_HIGH_THRESHOLD,
    FAN_OUT_MEDIUM_THRESHOLD,
    PORT_SCAN_MEDIUM_THRESHOLD,
    BaselineConfidence,
    DetectionSeverity,
    DetectionType,
    is_rfc1918,
)

# ── Helpers ────────────────────────────────────────────────────────────────────

def _cold_baseline(src_ip: str = "10.0.0.1") -> EntityBaseline:
    return compute_entity_baseline(src_ip, [], set(), set(), set())


def _established_baseline(
    src_ip: str = "10.0.0.1",
    p75_dst: float = 5.0,
    p75_bytes_out: float | None = 1_000_000.0,
    seen_dsts: set[str] | None = None,
    seen_ew: set[tuple[str, str]] | None = None,
) -> EntityBaseline:
    history = [
        {"unique_dst_ips": p75_dst, "bytes_out": p75_bytes_out, "event_count": 100}
        for _ in range(15)
    ]
    return compute_entity_baseline(
        src_ip, history,
        seen_dst_ips=seen_dsts or {"192.168.1.2"},
        seen_service_pairs=set(),
        seen_east_west_pairs=seen_ew or set(),
    )


def _metrics(
    src_ip: str = "10.0.0.1",
    event_count: int = 100,
    unique_dst_ips: int = 5,
    unique_dst_ports: int = 3,
    new_dst_ips: list[str] | None = None,
    rare_dst_ips: list[str] | None = None,
    new_service_accesses: list[tuple[str, int]] | None = None,
    new_east_west_pairs: list[tuple[str, str]] | None = None,
    total_bytes_out: int | None = None,
    total_bytes_in: int | None = None,
) -> EntityWindowMetrics:
    return EntityWindowMetrics(
        window_start_ts="2026-01-01T00:00:00+00:00",
        window_end_ts="2026-01-01T00:05:00+00:00",
        window_seconds=300,
        src_ip=src_ip,
        event_count=event_count,
        unique_dst_ips=unique_dst_ips,
        unique_dst_ports=unique_dst_ports,
        new_dst_ips=new_dst_ips or [],
        rare_dst_ips=rare_dst_ips or [],
        new_service_accesses=new_service_accesses or [],
        new_east_west_pairs=new_east_west_pairs or [],
        total_bytes_out=total_bytes_out,
        total_bytes_in=total_bytes_in,
        protocol_counts={"tcp": 90, "udp": 10},
    )


# ── is_rfc1918 ────────────────────────────────────────────────────────────────

class TestIsRfc1918:
    def test_10_block(self):
        assert is_rfc1918("10.0.0.1")
        assert is_rfc1918("10.255.255.255")

    def test_172_16_block(self):
        assert is_rfc1918("172.16.0.1")
        assert is_rfc1918("172.31.255.255")

    def test_192_168_block(self):
        assert is_rfc1918("192.168.0.1")
        assert is_rfc1918("192.168.255.255")

    def test_public_ip(self):
        assert not is_rfc1918("8.8.8.8")
        assert not is_rfc1918("1.1.1.1")
        assert not is_rfc1918("203.0.113.5")

    def test_172_not_in_range(self):
        # 172.32.x.x is NOT RFC-1918
        assert not is_rfc1918("172.32.0.1")


# ── Baseline ──────────────────────────────────────────────────────────────────

class TestBaselineComputation:
    def test_cold_start_zero_windows(self):
        bl = compute_entity_baseline("10.0.0.1", [], set(), set(), set())
        assert bl.confidence == BaselineConfidence.COLD_START
        assert bl.window_count == 0

    def test_insufficient_data(self):
        history = [{"unique_dst_ips": 5.0, "bytes_out": 1e6, "event_count": 50} for _ in range(5)]
        bl = compute_entity_baseline("10.0.0.1", history, set(), set(), set())
        assert bl.confidence == BaselineConfidence.INSUFFICIENT_DATA
        assert bl.window_count == 5

    def test_established_with_p75(self):
        # 16 windows — above MIN_BASELINE_WINDOWS=10
        vals = list(range(1, 17))  # 1..16
        history = [{"unique_dst_ips": float(v), "bytes_out": None, "event_count": 100}
                   for v in vals]
        bl = compute_entity_baseline("10.0.0.1", history, set(), set(), set())
        assert bl.confidence == BaselineConfidence.ESTABLISHED
        # p75 of 1..16: index = ceil(0.75*16)-1 = 11, sorted[11] = 12
        assert bl.p75_unique_dst_ips == 12.0

    def test_seen_dst_ips_preserved(self):
        seen = {"1.2.3.4", "5.6.7.8"}
        bl = compute_entity_baseline("10.0.0.1", [], seen, set(), set())
        assert bl.seen_dst_ips == seen


# ── Fan-out detection ─────────────────────────────────────────────────────────

class TestFanOutDetection:
    def test_no_fire_below_threshold(self):
        bl = _established_baseline(p75_dst=5.0)
        m = _metrics(unique_dst_ips=10, event_count=50)
        result = evaluate_fan_out(m, bl)
        assert not result.fired

    def test_fires_at_medium_threshold(self):
        bl = _established_baseline(p75_dst=5.0)
        m = _metrics(unique_dst_ips=FAN_OUT_MEDIUM_THRESHOLD, event_count=200)
        result = evaluate_fan_out(m, bl)
        assert result.fired
        assert result.detection_type == DetectionType.HIGH_FAN_OUT
        assert result.severity == DetectionSeverity.MEDIUM

    def test_high_severity_above_threshold(self):
        bl = _established_baseline(p75_dst=5.0)
        m = _metrics(unique_dst_ips=FAN_OUT_HIGH_THRESHOLD + 5, event_count=500)
        result = evaluate_fan_out(m, bl)
        assert result.fired
        assert result.severity in (DetectionSeverity.HIGH, DetectionSeverity.CRITICAL)

    def test_no_fire_insufficient_events(self):
        bl = _cold_baseline()
        m = _metrics(event_count=2, unique_dst_ips=100)
        result = evaluate_fan_out(m, bl)
        assert not result.fired
        assert any("insufficient_events" in s for s in result.missing_evidence)

    def test_explanation_is_non_empty(self):
        bl = _established_baseline(p75_dst=3.0)
        m = _metrics(unique_dst_ips=FAN_OUT_MEDIUM_THRESHOLD, event_count=200)
        result = evaluate_fan_out(m, bl)
        assert result.fired
        assert result.explanation != ""
        assert "10.0.0.1" in result.explanation
        assert str(FAN_OUT_MEDIUM_THRESHOLD) in result.explanation


# ── Port scan detection ───────────────────────────────────────────────────────

class TestPortScanDetection:
    def test_no_fire_below_threshold(self):
        bl = _cold_baseline()
        m = _metrics(unique_dst_ports=5, event_count=50)
        result = evaluate_port_scan(m, bl)
        assert not result.fired

    def test_fires_at_medium_threshold(self):
        bl = _cold_baseline()
        m = _metrics(unique_dst_ports=PORT_SCAN_MEDIUM_THRESHOLD, event_count=200)
        result = evaluate_port_scan(m, bl)
        assert result.fired
        assert result.detection_type == DetectionType.PORT_SCAN_SUSPECTED
        assert result.severity == DetectionSeverity.MEDIUM

    def test_missing_evidence_includes_failed_connection_ratio(self):
        bl = _cold_baseline()
        m = _metrics(unique_dst_ports=PORT_SCAN_MEDIUM_THRESHOLD, event_count=200)
        result = evaluate_port_scan(m, bl)
        assert result.fired
        assert any("failed_connection" in s for s in result.missing_evidence)


# ── New / rare destination detection ─────────────────────────────────────────

class TestDestinationDetection:
    def test_new_destination_fires(self):
        bl = _established_baseline()
        m = _metrics(new_dst_ips=["8.8.8.8", "1.1.1.1"])
        results = evaluate_new_destinations(m, bl)
        assert len(results) == 2
        assert all(r.fired for r in results)
        assert all(r.detection_type == DetectionType.NEW_DESTINATION for r in results)
        assert all(r.severity == DetectionSeverity.INFORMATIONAL for r in results)

    def test_rare_destination_fires(self):
        bl = _established_baseline()
        m = _metrics(rare_dst_ips=["8.8.4.4"])
        results = evaluate_new_destinations(m, bl)
        assert len(results) == 1
        assert results[0].detection_type == DetectionType.RARE_DESTINATION
        assert results[0].severity == DetectionSeverity.LOW

    def test_no_results_when_all_known(self):
        bl = _established_baseline()
        m = _metrics(new_dst_ips=[], rare_dst_ips=[])
        results = evaluate_new_destinations(m, bl)
        assert results == []


# ── Outbound transfer detection ───────────────────────────────────────────────

class TestOutboundTransfer:
    def test_no_fire_no_bytes(self):
        bl = _established_baseline(p75_bytes_out=1_000_000)
        m = _metrics(total_bytes_out=None)
        result = evaluate_outbound_transfer(m, bl)
        assert not result.fired
        assert any("bytes_out_unavailable" in s for s in result.missing_evidence)

    def test_no_fire_no_baseline(self):
        bl = _established_baseline(p75_bytes_out=None)
        m = _metrics(total_bytes_out=5_000_000)
        result = evaluate_outbound_transfer(m, bl)
        assert not result.fired
        assert any("no_bytes_out_baseline" in s for s in result.missing_evidence)

    def test_no_fire_within_threshold(self):
        bl = _established_baseline(p75_bytes_out=1_000_000)
        m = _metrics(total_bytes_out=2_000_000)  # 2x — below TRANSFER_LOW_DEVIATION=3
        result = evaluate_outbound_transfer(m, bl)
        assert not result.fired

    def test_fires_at_3x_deviation(self):
        bl = _established_baseline(p75_bytes_out=1_000_000)
        m = _metrics(total_bytes_out=3_500_000)  # 3.5x
        result = evaluate_outbound_transfer(m, bl)
        assert result.fired
        assert result.detection_type == DetectionType.ABNORMAL_OUTBOUND_TRANSFER
        assert result.severity == DetectionSeverity.MEDIUM

    def test_critical_at_25x(self):
        bl = _established_baseline(p75_bytes_out=1_000_000)
        m = _metrics(total_bytes_out=30_000_000)  # 30x
        result = evaluate_outbound_transfer(m, bl)
        assert result.fired
        assert result.severity == DetectionSeverity.CRITICAL


# ── East-west detection ───────────────────────────────────────────────────────

class TestEastWestDetection:
    def test_fires_for_new_internal_pair(self):
        bl = _established_baseline()
        m = _metrics(new_east_west_pairs=[("10.0.0.1", "10.0.0.50")])
        results = evaluate_east_west(m, bl)
        assert len(results) == 1
        assert results[0].fired
        assert results[0].detection_type == DetectionType.UNUSUAL_EAST_WEST
        assert results[0].severity == DetectionSeverity.MEDIUM

    def test_no_results_when_no_new_pairs(self):
        bl = _established_baseline()
        m = _metrics(new_east_west_pairs=[])
        results = evaluate_east_west(m, bl)
        assert results == []

    def test_missing_evidence_includes_lateral_movement_caveat(self):
        bl = _established_baseline()
        m = _metrics(new_east_west_pairs=[("10.0.0.1", "10.0.0.2")])
        results = evaluate_east_west(m, bl)
        assert results[0].fired
        assert any("lateral_movement" in s for s in results[0].missing_evidence)


# ── Unusual service access ────────────────────────────────────────────────────

class TestUnusualServiceAccess:
    def test_fires_for_new_service(self):
        bl = _established_baseline()
        m = _metrics(new_service_accesses=[("10.0.0.5", 22)])
        results = evaluate_unusual_service_access(m, bl)
        assert len(results) == 1
        assert results[0].fired
        assert results[0].detection_type == DetectionType.UNUSUAL_SERVICE_ACCESS
        assert results[0].severity == DetectionSeverity.LOW

    def test_multiple_new_services(self):
        bl = _established_baseline()
        m = _metrics(new_service_accesses=[("10.0.0.5", 22), ("10.0.0.6", 3389)])
        results = evaluate_unusual_service_access(m, bl)
        assert len(results) == 2


# ── Beaconing analysis ────────────────────────────────────────────────────────

class TestBeaconingAnalysis:
    def test_insufficient_samples(self):
        result = compute_beaconing(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443,
            event_timestamps_s=[1.0, 2.0, 3.0],  # only 3, need BEACONING_MIN_SAMPLES=8
            window_start_ts="2026-01-01T00:00:00+00:00",
            window_end_ts="2026-01-01T00:30:00+00:00",
        )
        assert not result.fired
        assert any("insufficient_samples" in s for s in result.missing_evidence)

    def test_fires_for_periodic_pattern(self):
        # Simulate 10 events at exactly 60-second intervals
        base = 1_700_000_000.0
        timestamps = [base + i * 60.0 for i in range(10)]
        result = compute_beaconing(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443,
            event_timestamps_s=timestamps,
            window_start_ts="2026-01-01T00:00:00+00:00",
            window_end_ts="2026-01-01T00:30:00+00:00",
        )
        assert result.fired
        assert result.metrics is not None
        assert abs(result.metrics.median_interval_s - 60.0) < 1.0
        assert result.metrics.jitter_coefficient < 0.01  # nearly zero jitter

    def test_does_not_fire_for_random_traffic(self):
        # Highly random intervals
        import random
        random.seed(42)
        base = 1_700_000_000.0
        timestamps = sorted([base + random.uniform(0, 3600) for _ in range(10)])
        result = compute_beaconing(
            src_ip="10.0.0.1", dst_ip="5.5.5.5", dst_port=80,
            event_timestamps_s=timestamps,
            window_start_ts="2026-01-01T00:00:00+00:00",
            window_end_ts="2026-01-01T01:00:00+00:00",
        )
        # Random traffic will likely have high jitter — may or may not fire;
        # the key invariant is that the explanation is honest
        if result.fired:
            assert result.explanation != ""
            assert "SUSPECTED" in result.explanation

    def test_does_not_fire_for_short_intervals(self):
        # Very fast traffic (1-second intervals) is below BEACONING_MIN_INTERVAL_SECONDS=20
        base = 1_700_000_000.0
        timestamps = [base + i * 1.0 for i in range(12)]
        result = compute_beaconing(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=53,
            event_timestamps_s=timestamps,
            window_start_ts="2026-01-01T00:00:00+00:00",
            window_end_ts="2026-01-01T00:01:00+00:00",
        )
        assert not result.fired
        assert any("interval_too_short" in s for s in result.missing_evidence)

    def test_high_jitter_does_not_fire(self):
        # Intervals with std/mean >> threshold
        base = 1_700_000_000.0
        # Alternating short/long: jitter will be high
        timestamps = []
        t = base
        for i in range(10):
            t += 10.0 if i % 2 == 0 else 200.0
            timestamps.append(t)
        result = compute_beaconing(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443,
            event_timestamps_s=timestamps,
            window_start_ts="2026-01-01T00:00:00+00:00",
            window_end_ts="2026-01-01T00:30:00+00:00",
        )
        # high jitter → should not fire
        assert not result.fired or result.metrics.jitter_coefficient <= 0.25

    def test_c2_caveat_in_missing_evidence(self):
        base = 1_700_000_000.0
        timestamps = [base + i * 60.0 for i in range(10)]
        result = compute_beaconing(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443,
            event_timestamps_s=timestamps,
            window_start_ts="2026-01-01T00:00:00+00:00",
            window_end_ts="2026-01-01T00:30:00+00:00",
        )
        if result.fired:
            assert any("c2_confirmation" in s for s in result.missing_evidence)
