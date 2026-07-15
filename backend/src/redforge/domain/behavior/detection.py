"""Behavioral Security Detection Engine — M20.

Pure functions, no I/O.  Every detection produces a full evidence record.
Every threshold is documented in value_objects.py.  All classifications
end with _SUSPECTED where evidence is inferential.

What this engine CAN detect from telemetry_events (canonical schema):
  - NEW_DESTINATION: first-ever dst_ip for a given src_ip (org-scoped)
  - RARE_DESTINATION: dst_ip with very low baseline occurrence count
  - HIGH_FAN_OUT: src_ip contacting many distinct dst_ips per window
  - PORT_SCAN_SUSPECTED: src_ip hitting many distinct dst_ports per window
  - BEACONING_SUSPECTED: periodic inter-arrival timing (min samples required)
  - ABNORMAL_OUTBOUND_TRANSFER: bytes_out deviation from entity p75 baseline
  - UNUSUAL_EAST_WEST: first-seen RFC-1918 → RFC-1918 pair
  - UNUSUAL_SERVICE_ACCESS: first-seen dst_port for a src→dst pair

What this engine CANNOT detect (no canonical evidence available):
  - User authentication anomalies (no auth events in telemetry_events)
  - Impossible travel (no session geo)
  - True TCP connection success/failure ratio (no TCP state)
  - Lateral movement confirmed (need host-level evidence)
  - MFA bypass, credential stuffing
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import Any

from redforge.domain.behavior.value_objects import (
    BEACONING_MAX_JITTER_COEFFICIENT,
    BEACONING_MIN_INTERVAL_SECONDS,
    BEACONING_MIN_SAMPLES,
    FAN_OUT_HIGH_THRESHOLD,
    FAN_OUT_MEDIUM_THRESHOLD,
    MIN_BASELINE_WINDOWS,
    MIN_EVENTS_FOR_DETECTION,
    PORT_SCAN_HIGH_THRESHOLD,
    PORT_SCAN_MEDIUM_THRESHOLD,
    RARE_DESTINATION_THRESHOLD,
    TRANSFER_CRITICAL_DEVIATION,
    TRANSFER_HIGH_DEVIATION,
    TRANSFER_LOW_DEVIATION,
    BaselineConfidence,
    DetectionSeverity,
    DetectionType,
)

# ── Window aggregation ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class EntityWindowMetrics:
    """Traffic metrics for one source IP over one time window.

    Derived from real telemetry_events rows.  None means the metric
    was unavailable (e.g. bytes fields all NULL in this window).
    """

    window_start_ts: str       # ISO-8601 UTC
    window_end_ts: str         # ISO-8601 UTC
    window_seconds: int
    src_ip: str
    event_count: int
    unique_dst_ips: int
    unique_dst_ports: int
    # First-seen destinations: dst_ips not in entity's prior history
    new_dst_ips: list[str]
    # Rare destinations: in history but below RARE_DESTINATION_THRESHOLD
    rare_dst_ips: list[str]
    # First-seen (dst_ip, dst_port) pairs for this src
    new_service_accesses: list[tuple[str, int]]
    # Internal (RFC-1918) pairs that are new for this org
    new_east_west_pairs: list[tuple[str, str]]
    total_bytes_out: int | None
    total_bytes_in: int | None
    protocol_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class EntityBaseline:
    """Documented adaptive baseline for one source IP entity.

    Computed from p75 of historical EntityWindowMetrics over a rolling
    14-day lookback.  When fewer than MIN_BASELINE_WINDOWS exist,
    cold-start semantics apply and thresholds fall back to absolute values.
    """

    confidence: BaselineConfidence
    window_count: int
    p75_unique_dst_ips: float
    p75_bytes_out: float | None
    p75_event_count: float
    # Seen destination IP set (for new/rare classification)
    seen_dst_ips: set[str]
    # Seen (src_ip, dst_ip, dst_port) set (for UNUSUAL_SERVICE_ACCESS)
    seen_service_pairs: set[tuple[str, str, int]]
    # Seen internal pairs (src_ip, dst_ip) for UNUSUAL_EAST_WEST
    seen_east_west_pairs: set[tuple[str, str]]


@dataclass(frozen=True, slots=True)
class BehaviorSignal:
    """One evidence signal contributing to a detection."""

    name: str
    threshold: float
    observed: float
    deviation: float
    detail: str


@dataclass(frozen=True, slots=True)
class BehaviorDetectionResult:
    """Full evidence-backed result for one entity window evaluation.

    detection_type is None when no anomaly fires.
    All matched signals are preserved for investigation.
    missing_evidence documents what additional data would help.
    """

    fired: bool
    detection_type: DetectionType | None
    severity: DetectionSeverity | None
    matched_signals: list[BehaviorSignal]
    missing_evidence: list[str]
    baseline: EntityBaseline
    metrics: EntityWindowMetrics
    # Human-readable explanation of WHY this fired
    explanation: str = ""

    @property
    def primary_deviation(self) -> float:
        if not self.matched_signals:
            return 1.0
        return max(s.deviation for s in self.matched_signals)


@dataclass(frozen=True, slots=True)
class BeaconingMetrics:
    """Per-destination connection timing analysis for beaconing detection.

    Must have ≥ BEACONING_MIN_SAMPLES intervals to produce a result.
    """

    src_ip: str
    dst_ip: str
    dst_port: int | None
    sample_count: int         # number of connection events
    interval_count: int       # len(intervals) = sample_count - 1
    median_interval_s: float
    mean_interval_s: float
    std_interval_s: float
    min_interval_s: float
    max_interval_s: float
    jitter_coefficient: float  # std / mean
    window_start_ts: str
    window_end_ts: str


@dataclass(frozen=True, slots=True)
class BeaconingDetectionResult:
    """Result of beaconing analysis for one (src, dst) pair."""

    fired: bool
    severity: DetectionSeverity | None
    metrics: BeaconingMetrics | None
    missing_evidence: list[str]
    explanation: str = ""


# ── Fan-out / Port-scan detection ─────────────────────────────────────────────


def evaluate_fan_out(
    metrics: EntityWindowMetrics,
    baseline: EntityBaseline,
) -> BehaviorDetectionResult:
    """HIGH_FAN_OUT: one src contacting many distinct dst_ips in one window.

    Fires when unique_dst_ips ≥ FAN_OUT_MEDIUM_THRESHOLD (20).
    Severity:
      CRITICAL: ≥ FAN_OUT_HIGH_THRESHOLD (50) AND 2x baseline
      HIGH:     ≥ FAN_OUT_HIGH_THRESHOLD OR 5x baseline
      MEDIUM:   ≥ FAN_OUT_MEDIUM_THRESHOLD
      LOW:      ≥ 0.5 * FAN_OUT_MEDIUM_THRESHOLD AND 3x baseline
    """
    signals: list[BehaviorSignal] = []
    missing: list[str] = []

    if metrics.event_count < MIN_EVENTS_FOR_DETECTION:
        return _no_fire(
            missing=[f"insufficient_events: {metrics.event_count} < {MIN_EVENTS_FOR_DETECTION}"],
            baseline=baseline, metrics=metrics,
        )

    n = metrics.unique_dst_ips
    baseline_n = max(baseline.p75_unique_dst_ips, 1.0)
    deviation = n / baseline_n

    if n >= FAN_OUT_MEDIUM_THRESHOLD:
        signals.append(BehaviorSignal(
            name="unique_dst_ips",
            threshold=FAN_OUT_MEDIUM_THRESHOLD,
            observed=n,
            deviation=deviation,
            detail=(
                f"{n} distinct destination IPs in window "
                f"(baseline p75={baseline.p75_unique_dst_ips:.1f})"
            ),
        ))

    if not signals:
        return _no_fire(missing=missing, baseline=baseline, metrics=metrics)

    if n >= FAN_OUT_HIGH_THRESHOLD and deviation >= 2.0:
        severity = DetectionSeverity.CRITICAL
    elif n >= FAN_OUT_HIGH_THRESHOLD or deviation >= 5.0:
        severity = DetectionSeverity.HIGH
    else:
        severity = DetectionSeverity.MEDIUM

    return BehaviorDetectionResult(
        fired=True,
        detection_type=DetectionType.HIGH_FAN_OUT,
        severity=severity,
        matched_signals=signals,
        missing_evidence=missing,
        baseline=baseline,
        metrics=metrics,
        explanation=(
            f"Source {metrics.src_ip} contacted {n} distinct destination IPs "
            f"within the observation window, compared with a baseline median of "
            f"{baseline.p75_unique_dst_ips:.1f} destinations. "
            f"Deviation: {deviation:.1f}x."
        ),
    )


def evaluate_port_scan(
    metrics: EntityWindowMetrics,
    baseline: EntityBaseline,
) -> BehaviorDetectionResult:
    """PORT_SCAN_SUSPECTED: many distinct dst_ports from one src in one window."""
    signals: list[BehaviorSignal] = []
    missing: list[str] = []

    if metrics.event_count < MIN_EVENTS_FOR_DETECTION:
        return _no_fire(
            missing=[f"insufficient_events: {metrics.event_count}"],
            baseline=baseline, metrics=metrics,
        )

    n = metrics.unique_dst_ports

    if n >= PORT_SCAN_MEDIUM_THRESHOLD:
        signals.append(BehaviorSignal(
            name="unique_dst_ports",
            threshold=PORT_SCAN_MEDIUM_THRESHOLD,
            observed=n,
            deviation=n / PORT_SCAN_MEDIUM_THRESHOLD,
            detail=f"{n} distinct destination ports in window",
        ))

    if not signals:
        return _no_fire(missing=missing, baseline=baseline, metrics=metrics)

    severity = DetectionSeverity.HIGH if n >= PORT_SCAN_HIGH_THRESHOLD else DetectionSeverity.MEDIUM

    return BehaviorDetectionResult(
        fired=True,
        detection_type=DetectionType.PORT_SCAN_SUSPECTED,
        severity=severity,
        matched_signals=signals,
        missing_evidence=[
            "failed_connection_ratio: not available in telemetry schema",
            "connection_success: TCP state not stored",
        ],
        baseline=baseline,
        metrics=metrics,
        explanation=(
            f"Source {metrics.src_ip} contacted {n} distinct destination ports "
            f"in the observation window. Consistent with port scanning or discovery "
            f"behavior. Evidence is inferential — failed-connection ratio unavailable."
        ),
    )


def evaluate_new_destinations(
    metrics: EntityWindowMetrics,
    baseline: EntityBaseline,
) -> list[BehaviorDetectionResult]:
    """NEW_DESTINATION and RARE_DESTINATION for each qualifying dst_ip."""
    results: list[BehaviorDetectionResult] = []

    for dst_ip in metrics.new_dst_ips:
        results.append(BehaviorDetectionResult(
            fired=True,
            detection_type=DetectionType.NEW_DESTINATION,
            severity=DetectionSeverity.INFORMATIONAL,
            matched_signals=[BehaviorSignal(
                name="first_seen_destination",
                threshold=0,
                observed=1,
                deviation=1.0,
                detail=(
                    f"{metrics.src_ip} → {dst_ip}: "
                    f"destination not seen in baseline period "
                    f"({baseline.window_count} windows)"
                ),
            )],
            missing_evidence=[],
            baseline=baseline,
            metrics=metrics,
            explanation=(
                f"Source {metrics.src_ip} initiated a connection to {dst_ip}, "
                f"which has not appeared in any of the {baseline.window_count} "
                f"baseline observation windows."
            ),
        ))

    for dst_ip in metrics.rare_dst_ips:
        results.append(BehaviorDetectionResult(
            fired=True,
            detection_type=DetectionType.RARE_DESTINATION,
            severity=DetectionSeverity.LOW,
            matched_signals=[BehaviorSignal(
                name="rare_destination",
                threshold=RARE_DESTINATION_THRESHOLD,
                observed=1,
                deviation=1.0,
                detail=(
                    f"{metrics.src_ip} → {dst_ip}: "
                    f"seen fewer than {RARE_DESTINATION_THRESHOLD} times in baseline"
                ),
            )],
            missing_evidence=[],
            baseline=baseline,
            metrics=metrics,
            explanation=(
                f"Source {metrics.src_ip} contacted {dst_ip}, which appears "
                f"fewer than {RARE_DESTINATION_THRESHOLD} times in the baseline period."
            ),
        ))

    return results


def evaluate_outbound_transfer(
    metrics: EntityWindowMetrics,
    baseline: EntityBaseline,
) -> BehaviorDetectionResult:
    """ABNORMAL_OUTBOUND_TRANSFER: bytes_out deviation from entity baseline."""
    missing: list[str] = []

    bytes_out = metrics.total_bytes_out
    if bytes_out is None:
        return _no_fire(
            missing=["bytes_out_unavailable: bytes_out fields NULL in this window"],
            baseline=baseline, metrics=metrics,
        )

    baseline_bytes_out = baseline.p75_bytes_out
    if baseline_bytes_out is None:
        return _no_fire(
            missing=["no_bytes_out_baseline: insufficient history with bytes_out data"],
            baseline=baseline, metrics=metrics,
        )

    if baseline_bytes_out == 0:
        return _no_fire(
            missing=["zero_baseline_bytes_out: baseline is zero, cannot compute deviation"],
            baseline=baseline, metrics=metrics,
        )

    deviation = bytes_out / baseline_bytes_out

    if deviation < TRANSFER_LOW_DEVIATION:
        return _no_fire(missing=missing, baseline=baseline, metrics=metrics)

    if deviation >= TRANSFER_CRITICAL_DEVIATION:
        severity = DetectionSeverity.CRITICAL
    elif deviation >= TRANSFER_HIGH_DEVIATION:
        severity = DetectionSeverity.HIGH
    else:
        severity = DetectionSeverity.MEDIUM

    return BehaviorDetectionResult(
        fired=True,
        detection_type=DetectionType.ABNORMAL_OUTBOUND_TRANSFER,
        severity=severity,
        matched_signals=[BehaviorSignal(
            name="bytes_out_deviation",
            threshold=baseline_bytes_out * TRANSFER_LOW_DEVIATION,
            observed=bytes_out,
            deviation=deviation,
            detail=(
                f"{bytes_out:,} bytes out vs baseline p75 "
                f"{baseline_bytes_out:,.0f} bytes ({deviation:.1f}x)"
            ),
        )],
        missing_evidence=[
            "destination_reputation: not correlated in this signal",
        ],
        baseline=baseline,
        metrics=metrics,
        explanation=(
            f"Source {metrics.src_ip} transmitted {bytes_out:,} bytes outbound, "
            f"{deviation:.1f}x above the baseline median of "
            f"{baseline_bytes_out:,.0f} bytes. "
            f"Consistent with abnormal outbound data transfer. "
            f"Evidence is volumetric — destination reputation not included here."
        ),
    )


def evaluate_east_west(
    metrics: EntityWindowMetrics,
    baseline: EntityBaseline,
) -> list[BehaviorDetectionResult]:
    """UNUSUAL_EAST_WEST: first-seen RFC-1918 → RFC-1918 pair in org scope."""
    results: list[BehaviorDetectionResult] = []

    for src_ip, dst_ip in metrics.new_east_west_pairs:
        results.append(BehaviorDetectionResult(
            fired=True,
            detection_type=DetectionType.UNUSUAL_EAST_WEST,
            severity=DetectionSeverity.MEDIUM,
            matched_signals=[BehaviorSignal(
                name="new_internal_pair",
                threshold=0,
                observed=1,
                deviation=1.0,
                detail=(
                    f"New internal communication: {src_ip} → {dst_ip}. "
                    f"Neither endpoint seen communicating before in baseline."
                ),
            )],
            missing_evidence=[
                "administrative_service: cannot confirm protocol intent without service mapping",
                "lateral_movement_confirmed: host-level evidence not available",
            ],
            baseline=baseline,
            metrics=metrics,
            explanation=(
                f"New internal communication pair detected: {src_ip} → {dst_ip}. "
                f"Both endpoints are RFC-1918 addresses. This pair has not "
                f"appeared in any of the {baseline.window_count} baseline windows. "
                f"Consistent with unusual east-west activity. Lateral movement "
                f"cannot be confirmed without host-level evidence."
            ),
        ))

    return results


def evaluate_unusual_service_access(
    metrics: EntityWindowMetrics,
    baseline: EntityBaseline,
) -> list[BehaviorDetectionResult]:
    """UNUSUAL_SERVICE_ACCESS: first-seen (src, dst, port) tuple."""
    results: list[BehaviorDetectionResult] = []

    for dst_ip, port in metrics.new_service_accesses:
        results.append(BehaviorDetectionResult(
            fired=True,
            detection_type=DetectionType.UNUSUAL_SERVICE_ACCESS,
            severity=DetectionSeverity.LOW,
            matched_signals=[BehaviorSignal(
                name="first_seen_service",
                threshold=0,
                observed=1,
                deviation=1.0,
                detail=(
                    f"{metrics.src_ip} → {dst_ip}:{port} "
                    f"not seen in {baseline.window_count} baseline windows"
                ),
            )],
            missing_evidence=[],
            baseline=baseline,
            metrics=metrics,
            explanation=(
                f"Source {metrics.src_ip} accessed service port {port} on "
                f"{dst_ip} for the first time in the observation baseline."
            ),
        ))

    return results


# ── Beaconing analysis ────────────────────────────────────────────────────────


def compute_beaconing(
    src_ip: str,
    dst_ip: str,
    dst_port: int | None,
    event_timestamps_s: list[float],
    window_start_ts: str,
    window_end_ts: str,
) -> BeaconingDetectionResult:
    """Analyze inter-arrival intervals for beaconing indicators.

    Requires ≥ BEACONING_MIN_SAMPLES connection events to the same destination.
    Fires BEACONING_SUSPECTED when:
      - jitter_coefficient (std/mean) ≤ BEACONING_MAX_JITTER_COEFFICIENT
      - median interval ≥ BEACONING_MIN_INTERVAL_SECONDS

    Does NOT claim C2 confirmed.  Evidence is timing-based only.
    False-positive note: monitoring agents, health checks, and backup
    clients produce similar patterns.  Analyst review is required.
    """
    if len(event_timestamps_s) < BEACONING_MIN_SAMPLES:
        return BeaconingDetectionResult(
            fired=False,
            severity=None,
            metrics=None,
            missing_evidence=[
                f"insufficient_samples: {len(event_timestamps_s)} events "
                f"(minimum {BEACONING_MIN_SAMPLES})"
            ],
        )

    sorted_ts = sorted(event_timestamps_s)
    intervals = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]

    if not intervals:
        return BeaconingDetectionResult(
            fired=False, severity=None, metrics=None,
            missing_evidence=["no_intervals_computed"],
        )

    median_iv = statistics.median(intervals)
    mean_iv = statistics.mean(intervals)
    std_iv = statistics.stdev(intervals) if len(intervals) >= 2 else 0.0
    jitter = std_iv / mean_iv if mean_iv > 0 else 1.0

    bm = BeaconingMetrics(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        sample_count=len(event_timestamps_s),
        interval_count=len(intervals),
        median_interval_s=median_iv,
        mean_interval_s=mean_iv,
        std_interval_s=std_iv,
        min_interval_s=min(intervals),
        max_interval_s=max(intervals),
        jitter_coefficient=jitter,
        window_start_ts=window_start_ts,
        window_end_ts=window_end_ts,
    )

    if median_iv < BEACONING_MIN_INTERVAL_SECONDS:
        return BeaconingDetectionResult(
            fired=False, severity=None, metrics=bm,
            missing_evidence=[
                f"interval_too_short: median {median_iv:.1f}s "
                f"< {BEACONING_MIN_INTERVAL_SECONDS}s minimum"
            ],
        )

    if jitter > BEACONING_MAX_JITTER_COEFFICIENT:
        return BeaconingDetectionResult(
            fired=False, severity=None, metrics=bm,
            missing_evidence=[
                f"high_jitter: coefficient {jitter:.3f} "
                f"> {BEACONING_MAX_JITTER_COEFFICIENT} threshold"
            ],
        )

    # Severity: shorter periodic intervals → higher severity
    if median_iv <= 60:
        severity = DetectionSeverity.HIGH
    elif median_iv <= 300:
        severity = DetectionSeverity.MEDIUM
    else:
        severity = DetectionSeverity.LOW

    return BeaconingDetectionResult(
        fired=True,
        severity=severity,
        metrics=bm,
        missing_evidence=[
            "c2_confirmation: timing periodicity alone cannot confirm C2",
            "payload_inspection: DPI not available in telemetry schema",
        ],
        explanation=(
            f"Periodic communication SUSPECTED: {src_ip} → {dst_ip}"
            + (f":{dst_port}" if dst_port else "")
            + f". {bm.sample_count} samples, median interval "
            f"{bm.median_interval_s:.1f}s, jitter coefficient "
            f"{bm.jitter_coefficient:.3f}. "
            f"Consistent with beaconing behavior. "
            f"False positives: monitoring agents, health checks, backup clients."
        ),
    )


# ── Baseline computation ──────────────────────────────────────────────────────


def compute_entity_baseline(
    src_ip: str,
    window_history: list[dict[str, Any]],
    seen_dst_ips: set[str],
    seen_service_pairs: set[tuple[str, str, int]],
    seen_east_west_pairs: set[tuple[str, str]],
) -> EntityBaseline:
    """Compute adaptive baseline from historical window data.

    `window_history` is a list of dicts with keys:
      unique_dst_ips, bytes_out, event_count
    All None values are tolerated (metric was unavailable that window).
    """
    n = len(window_history)

    if n < MIN_BASELINE_WINDOWS:
        confidence = (
            BaselineConfidence.COLD_START if n == 0
            else BaselineConfidence.INSUFFICIENT_DATA
        )
        return EntityBaseline(
            confidence=confidence,
            window_count=n,
            p75_unique_dst_ips=0.0,
            p75_bytes_out=None,
            p75_event_count=0.0,
            seen_dst_ips=seen_dst_ips,
            seen_service_pairs=seen_service_pairs,
            seen_east_west_pairs=seen_east_west_pairs,
        )

    dst_vals = [w["unique_dst_ips"] for w in window_history if w.get("unique_dst_ips") is not None]
    bytes_vals = [w["bytes_out"] for w in window_history if w.get("bytes_out") is not None]
    ev_vals = [w["event_count"] for w in window_history if w.get("event_count") is not None]

    return EntityBaseline(
        confidence=BaselineConfidence.ESTABLISHED,
        window_count=n,
        p75_unique_dst_ips=_p75(dst_vals) or 0.0,
        p75_bytes_out=_p75(bytes_vals),
        p75_event_count=_p75(ev_vals) or 0.0,
        seen_dst_ips=seen_dst_ips,
        seen_service_pairs=seen_service_pairs,
        seen_east_west_pairs=seen_east_west_pairs,
    )


def _p75(values: list[float]) -> float | None:
    if not values:
        return None
    sorted_vals = sorted(values)
    idx = math.ceil(0.75 * len(sorted_vals)) - 1
    return sorted_vals[max(0, idx)]


def _no_fire(
    missing: list[str],
    baseline: EntityBaseline,
    metrics: EntityWindowMetrics,
) -> BehaviorDetectionResult:
    return BehaviorDetectionResult(
        fired=False,
        detection_type=None,
        severity=None,
        matched_signals=[],
        missing_evidence=missing,
        baseline=baseline,
        metrics=metrics,
    )
