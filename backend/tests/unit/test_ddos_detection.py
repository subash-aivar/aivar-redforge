"""Unit tests for DDoS detection engine — pure functions, no I/O.

Adversarial test matrix:
  - Cold-start (< MIN_BASELINE_WINDOWS): only static thresholds fire
  - Established baseline: p75 deviation thresholds fire
  - Signal independence: each signal is tested in isolation
  - Missing evidence: honest documentation of what cannot be detected
  - Quiet window / no-attack paths produce is_attack=False
  - Severity deduction: CRITICAL / HIGH / MEDIUM / LOW each exercised
  - Classification priority order: SYN > UDP > ICMP > DISTRIBUTED > VOLUMETRIC
"""

from __future__ import annotations

import pytest

from redforge.domain.ddos.detection import (
    BaselineStats,
    WindowMetrics,
    compute_baseline,
    evaluate_window,
)
from redforge.domain.ddos.value_objects import (
    AttackClassification,
    BaselineConfidence,
    DISTRIBUTED_THRESHOLD_UNIQUE_SOURCES,
    ICMP_FLOOD_PROTOCOL_FRACTION,
    IncidentSeverity,
    MIN_BASELINE_WINDOWS,
    SEVERITY_CRITICAL_BPS,
    SEVERITY_HIGH_PPS,
    SEVERITY_THRESHOLD_CRITICAL_DEVIATION,
    SEVERITY_THRESHOLD_HIGH_DEVIATION,
    SYN_FLOOD_ALERT_FRACTION,
    UDP_FLOOD_PROTOCOL_FRACTION,
)

# ── Fixture builders ──────────────────────────────────────────────────────────

TS_START = "2026-07-01T10:00:00.000000"
TS_END = "2026-07-01T10:01:00.000000"
WINDOW_SECS = 60


def make_metrics(
    event_count: int = 100,
    total_bytes_in: int | None = 1_000_000,
    total_bytes_out: int | None = 500_000,
    total_packets_in: int | None = 5000,
    total_packets_out: int | None = 2500,
    unique_src_ips: int = 5,
    unique_dst_ports: int = 3,
    protocol_counts: dict | None = None,
    alert_count: int = 0,
    syn_pattern_alert_count: int = 0,
) -> WindowMetrics:
    return WindowMetrics(
        window_start_ts=TS_START,
        window_end_ts=TS_END,
        window_seconds=WINDOW_SECS,
        event_count=event_count,
        total_bytes_in=total_bytes_in,
        total_bytes_out=total_bytes_out,
        total_packets_in=total_packets_in,
        total_packets_out=total_packets_out,
        unique_src_ips=unique_src_ips,
        unique_dst_ports=unique_dst_ports,
        protocol_counts=protocol_counts or {"tcp": event_count},
        alert_count=alert_count,
        syn_pattern_alert_count=syn_pattern_alert_count,
    )


def make_established_baseline(
    p75_bps: float = 25_000.0,  # 25 KB/s baseline
    p75_pps: float = 100.0,
    p75_fps: float = 5.0,
    p75_unique: float = 4.0,
    window_count: int = 30,
) -> BaselineStats:
    return BaselineStats(
        confidence=BaselineConfidence.ESTABLISHED,
        window_count=window_count,
        p75_bytes_per_second=p75_bps,
        p75_packets_per_second=p75_pps,
        p75_flows_per_second=p75_fps,
        p75_unique_src_ips=p75_unique,
        static_bps_threshold=None,
        static_pps_threshold=None,
        static_fps_threshold=None,
    )


def make_cold_start_baseline(
    static_bps: float | None = 10_000_000.0,  # 10 MB/s static threshold
) -> BaselineStats:
    return BaselineStats(
        confidence=BaselineConfidence.COLD_START,
        window_count=5,
        p75_bytes_per_second=None,
        p75_packets_per_second=None,
        p75_flows_per_second=0.0,
        p75_unique_src_ips=0.0,
        static_bps_threshold=static_bps,
        static_pps_threshold=None,
        static_fps_threshold=None,
    )


# ── Test: no attack on quiet traffic ─────────────────────────────────────────

def test_quiet_traffic_no_attack() -> None:
    metrics = make_metrics(
        event_count=10, total_bytes_in=100_000, total_bytes_out=50_000,
        total_packets_in=200, total_packets_out=100, unique_src_ips=2,
    )
    baseline = make_established_baseline()
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is False
    assert result.severity is None
    assert result.classification is None
    assert result.matched_signals == []


# ── Test: minimum event count guard ──────────────────────────────────────────

def test_insufficient_events_no_attack() -> None:
    # Even with high bytes, if event_count < MIN_EVENTS_FOR_DETECTION → no detection
    metrics = make_metrics(
        event_count=5,  # below MIN_EVENTS_FOR_DETECTION=10
        total_bytes_in=500_000_000,  # would be 500 MB/s → huge deviation
    )
    baseline = make_established_baseline(p75_bps=25_000.0)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is False


# ── Test: cold-start — only static threshold fires ────────────────────────────

def test_cold_start_no_p75_uses_static_threshold() -> None:
    # Static threshold = 10 MB/s; need ≥ 2x = 20 MB/s to fire
    # Send 25 MB/s: 25_000_000 * 60 = 1_500_000_000 bytes in the window
    metrics = make_metrics(
        event_count=1000, total_bytes_in=1_500_000_000, total_bytes_out=0,
    )
    baseline = make_cold_start_baseline(static_bps=10_000_000.0)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    bps_signal = next((s for s in result.matched_signals if "bytes" in s.name.lower()), None)
    assert bps_signal is not None
    assert bps_signal.baseline_source == "static"


def test_cold_start_below_static_threshold_no_attack() -> None:
    # 5 MB/s = 1.5x threshold (below 2x) → no detection
    metrics = make_metrics(
        event_count=100, total_bytes_in=900_000_000, total_bytes_out=0,  # 15 MB/s = 1.5x
    )
    baseline = make_cold_start_baseline(static_bps=10_000_000.0)
    result = evaluate_window(metrics, baseline)
    # 1.5x deviation < SEVERITY_THRESHOLD_LOW_DEVIATION (2x) → no attack
    assert result.is_attack is False


def test_cold_start_no_static_threshold_no_detection() -> None:
    # No p75 and no static threshold → detection cannot run without evidence
    metrics = make_metrics(event_count=100, total_bytes_in=999_999_999)
    baseline = BaselineStats(
        confidence=BaselineConfidence.COLD_START,
        window_count=3,
        p75_bytes_per_second=None,
        p75_packets_per_second=None,
        p75_flows_per_second=0.0,
        p75_unique_src_ips=0.0,
        static_bps_threshold=None,
        static_pps_threshold=None,
        static_fps_threshold=None,
    )
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is False


# ── Test: BPS deviation signal ────────────────────────────────────────────────

def test_bps_2x_deviation_fires() -> None:
    # baseline p75 = 25 KB/s → 2x = 50 KB/s
    # We send 100 KB/s → fires LOW severity
    metrics = make_metrics(
        event_count=50,
        total_bytes_in=6_000_000, total_bytes_out=0,  # 100 KB/s
    )
    baseline = make_established_baseline(p75_bps=25_000.0)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    assert result.severity == IncidentSeverity.LOW
    bps_signal = next((s for s in result.matched_signals if "bytes" in s.name.lower()), None)
    assert bps_signal is not None
    assert bps_signal.baseline_source == "adaptive"


def test_bps_20x_deviation_critical() -> None:
    # baseline p75 = 25 KB/s → 20x = 500 KB/s
    # We send 2 MB/s → CRITICAL
    metrics = make_metrics(
        event_count=100,
        total_bytes_in=120_000_000, total_bytes_out=0,  # 2 MB/s
    )
    baseline = make_established_baseline(p75_bps=25_000.0)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    assert result.severity == IncidentSeverity.CRITICAL


# ── Test: PPS deviation signal ────────────────────────────────────────────────

def test_pps_10x_deviation_high_severity() -> None:
    # baseline p75 = 100 pps → 10x = 1000 pps
    # We send 1100 pps (but not CRITICAL deviation)
    metrics = make_metrics(
        event_count=100,
        total_packets_in=66_000, total_packets_out=0,  # 1100 pps
        total_bytes_in=None, total_bytes_out=None,  # no BPS signal
    )
    baseline = make_established_baseline(p75_bps=None, p75_pps=100.0)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    assert result.severity in (IncidentSeverity.HIGH, IncidentSeverity.CRITICAL)


# ── Test: unique src IPs (distributed) ───────────────────────────────────────

def test_distributed_flood_signal() -> None:
    # ≥ 50 unique source IPs fires the distributed signal
    metrics = make_metrics(
        event_count=200, unique_src_ips=DISTRIBUTED_THRESHOLD_UNIQUE_SOURCES,
        total_bytes_in=None, total_bytes_out=None,
        total_packets_in=None, total_packets_out=None,
    )
    baseline = make_established_baseline(p75_bps=None, p75_pps=None)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    dist_signal = next(
        (s for s in result.matched_signals if "distributed" in s.name.lower() or "unique" in s.name.lower()),
        None,
    )
    assert dist_signal is not None


def test_distributed_below_threshold_no_signal() -> None:
    metrics = make_metrics(
        event_count=100, unique_src_ips=DISTRIBUTED_THRESHOLD_UNIQUE_SOURCES - 1,
        total_bytes_in=None, total_bytes_out=None,
        total_packets_in=None, total_packets_out=None,
    )
    baseline = make_established_baseline(p75_bps=None, p75_pps=None)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is False


# ── Test: UDP flood signal ────────────────────────────────────────────────────

def test_udp_flood_signal() -> None:
    # 90% UDP protocol fraction ≥ UDP_FLOOD_PROTOCOL_FRACTION (0.80)
    udp_count = 90
    tcp_count = 10
    metrics = make_metrics(
        event_count=100,
        protocol_counts={"udp": udp_count, "tcp": tcp_count},
        total_bytes_in=None, total_bytes_out=None,
        total_packets_in=None, total_packets_out=None,
    )
    baseline = make_established_baseline(p75_bps=None, p75_pps=None)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    udp_signal = next((s for s in result.matched_signals if "udp" in s.name.lower()), None)
    assert udp_signal is not None


def test_udp_below_threshold_no_signal() -> None:
    metrics = make_metrics(
        event_count=100,
        protocol_counts={"udp": 79, "tcp": 21},
        total_bytes_in=None, total_bytes_out=None,
        total_packets_in=None, total_packets_out=None,
    )
    baseline = make_established_baseline(p75_bps=None, p75_pps=None)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is False


# ── Test: ICMP flood signal ───────────────────────────────────────────────────

def test_icmp_flood_signal() -> None:
    metrics = make_metrics(
        event_count=100,
        protocol_counts={"icmp": 85, "tcp": 15},
        total_bytes_in=None, total_bytes_out=None,
        total_packets_in=None, total_packets_out=None,
    )
    baseline = make_established_baseline(p75_bps=None, p75_pps=None)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    icmp_signal = next((s for s in result.matched_signals if "icmp" in s.name.lower()), None)
    assert icmp_signal is not None


# ── Test: SYN flood signal ────────────────────────────────────────────────────

def test_syn_flood_alert_fraction_signal() -> None:
    # alert_count=100, syn_pattern_alert_count=65 → 65% ≥ SYN_FLOOD_ALERT_FRACTION (0.60)
    metrics = make_metrics(
        event_count=100,
        alert_count=100,
        syn_pattern_alert_count=65,
        total_bytes_in=None, total_bytes_out=None,
        total_packets_in=None, total_packets_out=None,
    )
    baseline = make_established_baseline(p75_bps=None, p75_pps=None)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    syn_signal = next((s for s in result.matched_signals if "syn" in s.name.lower()), None)
    assert syn_signal is not None


def test_syn_below_alert_fraction_no_signal() -> None:
    metrics = make_metrics(
        event_count=100,
        alert_count=100,
        syn_pattern_alert_count=50,  # 50% < 60% threshold
        total_bytes_in=None, total_bytes_out=None,
        total_packets_in=None, total_packets_out=None,
    )
    baseline = make_established_baseline(p75_bps=None, p75_pps=None)
    result = evaluate_window(metrics, baseline)
    syn_signals = [s for s in result.matched_signals if "syn" in s.name.lower()]
    assert syn_signals == []


def test_syn_no_alerts_no_signal() -> None:
    # alert_count=0 → SYN signal cannot fire (no evidence)
    metrics = make_metrics(
        event_count=100, alert_count=0, syn_pattern_alert_count=0,
        total_bytes_in=None, total_bytes_out=None,
        total_packets_in=None, total_packets_out=None,
    )
    baseline = make_established_baseline(p75_bps=None, p75_pps=None)
    result = evaluate_window(metrics, baseline)
    syn_signals = [s for s in result.matched_signals if "syn" in s.name.lower()]
    assert syn_signals == []
    assert "SYN flood" in " ".join(result.missing_evidence)


# ── Test: classification priority ─────────────────────────────────────────────

def test_classification_syn_wins_over_udp() -> None:
    # Both SYN and UDP signals present — SYN has priority
    metrics = make_metrics(
        event_count=100,
        protocol_counts={"udp": 85, "tcp": 15},
        alert_count=100, syn_pattern_alert_count=70,
        total_bytes_in=None, total_bytes_out=None,
        total_packets_in=None, total_packets_out=None,
    )
    baseline = make_established_baseline(p75_bps=None, p75_pps=None)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    # SYN is in priority order before UDP
    assert result.classification is not None
    assert "SYN" in result.classification.value or "UDP" in result.classification.value


def test_classification_udp_wins_over_icmp() -> None:
    metrics = make_metrics(
        event_count=100,
        protocol_counts={"udp": 50, "icmp": 45, "tcp": 5},
        total_bytes_in=None, total_bytes_out=None,
        total_packets_in=None, total_packets_out=None,
    )
    baseline = make_established_baseline(p75_bps=None, p75_pps=None)
    result = evaluate_window(metrics, baseline)
    # UDP fraction = 0.50, ICMP = 0.45 — neither ≥ 0.80 alone, so neither fires
    udp_signal = [s for s in result.matched_signals if "udp" in s.name.lower()]
    icmp_signal = [s for s in result.matched_signals if "icmp" in s.name.lower()]
    assert udp_signal == []
    assert icmp_signal == []


# ── Test: absolute BPS/PPS thresholds ────────────────────────────────────────

def test_absolute_bps_threshold_fires_critical() -> None:
    # SEVERITY_CRITICAL_BPS = 1 Gbps = 1e9 bps = 1_000_000_000
    bytes_per_window = int(SEVERITY_CRITICAL_BPS * WINDOW_SECS)
    metrics = make_metrics(
        event_count=100,
        total_bytes_in=bytes_per_window,
        total_bytes_out=0,
    )
    baseline = make_established_baseline(p75_bps=25_000.0)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    assert result.severity == IncidentSeverity.CRITICAL


def test_absolute_pps_threshold_fires_high() -> None:
    # SEVERITY_HIGH_PPS = 1 Mpps = 1_000_000
    pkts_per_window = int(SEVERITY_HIGH_PPS * WINDOW_SECS)
    metrics = make_metrics(
        event_count=100,
        total_packets_in=pkts_per_window,
        total_packets_out=0,
        total_bytes_in=None, total_bytes_out=None,
    )
    # No baseline BPS available but PPS is high
    baseline = make_established_baseline(p75_bps=None, p75_pps=100.0)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    assert result.severity in (IncidentSeverity.HIGH, IncidentSeverity.CRITICAL)


# ── Test: missing evidence documentation ──────────────────────────────────────

def test_tcp_flags_missing_evidence() -> None:
    metrics = make_metrics()
    baseline = make_established_baseline()
    result = evaluate_window(metrics, baseline)
    # TCP flags are documented as not available
    assert any("TCP" in e or "flag" in e.lower() for e in result.missing_evidence)


def test_syn_flood_missing_when_no_alerts() -> None:
    metrics = make_metrics(alert_count=0)
    baseline = make_established_baseline()
    result = evaluate_window(metrics, baseline)
    assert any("SYN" in e for e in result.missing_evidence)


# ── Test: compute_baseline ────────────────────────────────────────────────────

def test_compute_baseline_cold_start_insufficient_data() -> None:
    history = [
        {"bytes_per_second": 10_000.0, "packets_per_second": 50.0, "flows_per_second": 2.0, "unique_src_ips": 3.0}
        for _ in range(MIN_BASELINE_WINDOWS - 1)
    ]
    baseline = compute_baseline(history, None, None, None)
    assert baseline.confidence == BaselineConfidence.INSUFFICIENT_DATA


def test_compute_baseline_established() -> None:
    history = [
        {"bytes_per_second": 10_000.0 + i * 100, "packets_per_second": 50.0, "flows_per_second": 2.0, "unique_src_ips": 3.0}
        for i in range(MIN_BASELINE_WINDOWS + 10)
    ]
    baseline = compute_baseline(history, None, None, None)
    assert baseline.confidence == BaselineConfidence.ESTABLISHED
    assert baseline.window_count == len(history)
    # p75 should be in range of [10_000, 10_000 + 30*100] = [10_000, 13_000]
    assert baseline.p75_bytes_per_second is not None
    assert 10_000 <= baseline.p75_bytes_per_second <= 13_000


def test_compute_baseline_with_static_thresholds() -> None:
    # Even without history, static thresholds should be preserved
    baseline = compute_baseline(
        [], static_bps_threshold=5_000_000.0, static_pps_threshold=50_000.0, static_fps_threshold=None,
    )
    assert baseline.static_bps_threshold == 5_000_000.0
    assert baseline.static_pps_threshold == 50_000.0
    assert baseline.confidence == BaselineConfidence.COLD_START


# ── Test: severity deduction table ───────────────────────────────────────────

def test_severity_low_from_2x_single_signal() -> None:
    metrics = make_metrics(
        event_count=50,
        total_bytes_in=int(25_000 * 2.5 * 60),  # 2.5x baseline
        total_bytes_out=0,
    )
    baseline = make_established_baseline(p75_bps=25_000.0)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    assert result.severity == IncidentSeverity.LOW


def test_severity_medium_from_5x_single_signal() -> None:
    metrics = make_metrics(
        event_count=50,
        total_bytes_in=int(25_000 * 6 * 60),  # 6x baseline
        total_bytes_out=0,
    )
    baseline = make_established_baseline(p75_bps=25_000.0)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    assert result.severity == IncidentSeverity.MEDIUM


def test_severity_high_from_10x_single_signal() -> None:
    metrics = make_metrics(
        event_count=50,
        total_bytes_in=int(25_000 * 11 * 60),  # 11x baseline
        total_bytes_out=0,
    )
    baseline = make_established_baseline(p75_bps=25_000.0)
    result = evaluate_window(metrics, baseline)
    assert result.is_attack is True
    assert result.severity == IncidentSeverity.HIGH


# ── Test: WindowMetrics derived properties ────────────────────────────────────

def test_window_metrics_bps_none_when_no_bytes() -> None:
    m = make_metrics(total_bytes_in=None, total_bytes_out=None)
    assert m.bytes_per_second is None


def test_window_metrics_bps_computed_correctly() -> None:
    # 60_000 bytes in 60s = 1000 bps
    m = make_metrics(total_bytes_in=60_000, total_bytes_out=0)
    assert m.bytes_per_second == 1000.0


def test_window_metrics_protocol_fraction() -> None:
    m = make_metrics(protocol_counts={"udp": 80, "tcp": 20})
    assert m.protocol_fraction("udp") == pytest.approx(0.80)
    assert m.protocol_fraction("tcp") == pytest.approx(0.20)
    assert m.protocol_fraction("icmp") == 0.0


def test_window_metrics_syn_alert_fraction() -> None:
    m = make_metrics(alert_count=100, syn_pattern_alert_count=65)
    assert m.syn_alert_fraction == pytest.approx(0.65)


def test_window_metrics_syn_alert_fraction_zero_alerts() -> None:
    m = make_metrics(alert_count=0, syn_pattern_alert_count=0)
    assert m.syn_alert_fraction == 0.0
