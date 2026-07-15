"""DDoS detection engine — deterministic, explainable, evidence-based (M19).

Every detection produces a full evidence record. No magic numbers are
hidden. Every threshold is documented. Every classification states its
confidence level ("SUSPECTED" means inferential, not confirmed).

What this engine CAN detect from M18 telemetry:
  - Volumetric floods (bytes/s, packets/s deviation from baseline)
  - Distributed floods (high unique source IP count + elevated traffic)
  - Protocol floods (UDP or ICMP dominance from protocol field)
  - SYN flood indicators (Suricata alert signatures with SYN patterns)
  - Anomalous traffic surges (significant deviation, insufficient signals
    to classify further)

What this engine CANNOT detect (honestly documented):
  - TCP flag ratios (not stored in telemetry_events schema)
  - True connection-completion ratio (no TCP state machine data)
  - L7 application floods (no reliable HTTP request rate signal)
  - Reflection/amplification confirmation (no packet-size or direction
    data at the required granularity)
  - Sub-minute resolution (telemetry_events is event-time, not sampled)
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from redforge.domain.ddos.value_objects import (
    DISTRIBUTED_THRESHOLD_UNIQUE_SOURCES,
    ICMP_FLOOD_PROTOCOL_FRACTION,
    MIN_BASELINE_WINDOWS,
    MIN_EVENTS_FOR_DETECTION,
    SEVERITY_CRITICAL_BPS,
    SEVERITY_HIGH_PPS,
    SEVERITY_THRESHOLD_CRITICAL_DEVIATION,
    SEVERITY_THRESHOLD_HIGH_DEVIATION,
    SEVERITY_THRESHOLD_LOW_DEVIATION,
    SEVERITY_THRESHOLD_MEDIUM_DEVIATION,
    SYN_FLOOD_ALERT_FRACTION,
    UDP_FLOOD_PROTOCOL_FRACTION,
    AttackClassification,
    BaselineConfidence,
    IncidentSeverity,
)

# ── Window aggregation result ───────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class WindowMetrics:
    """Traffic metrics computed over one time window.

    All values are derived from real telemetry_events rows for the
    organization+resource scope. None means the metric is unavailable
    (e.g. bytes fields were all NULL for this window).
    """

    window_start_ts: str          # ISO-8601 UTC
    window_end_ts: str            # ISO-8601 UTC
    window_seconds: int
    event_count: int
    total_bytes_in: int | None
    total_bytes_out: int | None
    total_packets_in: int | None
    total_packets_out: int | None
    unique_src_ips: int
    unique_dst_ports: int
    # Protocol distribution: {"tcp": N, "udp": M, "icmp": K, ...}
    protocol_counts: dict[str, int]
    # Alert event count from Suricata (event_type starts with "suricata_alert")
    alert_count: int
    # Alert signatures matching SYN-pattern keywords
    syn_pattern_alert_count: int

    @property
    def bytes_per_second(self) -> float | None:
        total = (self.total_bytes_in or 0) + (self.total_bytes_out or 0)
        if total == 0:
            return None
        return total / self.window_seconds

    @property
    def packets_per_second(self) -> float | None:
        total = (self.total_packets_in or 0) + (self.total_packets_out or 0)
        if total == 0:
            return None
        return total / self.window_seconds

    @property
    def flows_per_second(self) -> float:
        return self.event_count / self.window_seconds

    @property
    def total_protocol_events(self) -> int:
        return sum(self.protocol_counts.values())

    def protocol_fraction(self, proto: str) -> float:
        total = self.total_protocol_events
        if total == 0:
            return 0.0
        return self.protocol_counts.get(proto, 0) / total

    @property
    def syn_alert_fraction(self) -> float:
        if self.alert_count == 0:
            return 0.0
        return self.syn_pattern_alert_count / self.alert_count


# ── Baseline ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class BaselineStats:
    """Documented adaptive baseline for a protected resource.

    Computed as the p75 of historical WindowMetrics over a rolling
    7-day lookback. p75 is used rather than the mean to be robust
    against occasional legitimate traffic spikes (marketing campaigns,
    scheduled jobs). When fewer than MIN_BASELINE_WINDOWS windows exist,
    static thresholds are used and confidence is COLD_START.
    """

    confidence: BaselineConfidence
    window_count: int              # number of windows used to compute this
    p75_bytes_per_second: float | None
    p75_packets_per_second: float | None
    p75_flows_per_second: float
    p75_unique_src_ips: float
    # Static fallback thresholds (always present — from policy config)
    static_bps_threshold: float | None
    static_pps_threshold: float | None
    static_fps_threshold: float | None


# ── Signal ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DetectionSignal:
    """One matched signal contributing to a detection.

    threshold: the value that was exceeded
    observed: the value that exceeded it
    deviation_multiplier: observed / threshold (1.0 = at threshold)
    baseline_source: "adaptive" | "static" | "none"
    """

    name: str
    threshold: float
    observed: float
    deviation_multiplier: float
    baseline_source: str
    detail: str = ""


# ── Detection result ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Full evidence-backed detection for one window.

    is_attack is True only when enough signals are matched.
    matched_signals contains ALL signals that crossed their threshold.
    missing_evidence lists what would be needed for higher confidence.
    classification label ends with _SUSPECTED where inferential.
    """

    is_attack: bool
    severity: IncidentSeverity | None
    classification: AttackClassification | None
    matched_signals: list[DetectionSignal]
    missing_evidence: list[str]
    baseline: BaselineStats
    metrics: WindowMetrics

    @property
    def primary_deviation(self) -> float:
        """Highest deviation multiplier across all matched signals."""
        if not self.matched_signals:
            return 1.0
        return max(s.deviation_multiplier for s in self.matched_signals)


# ── Detection engine ────────────────────────────────────────────────────────


def evaluate_window(
    metrics: WindowMetrics,
    baseline: BaselineStats,
) -> DetectionResult:
    """Evaluate one time window against baseline and thresholds.

    Pure function — no I/O, no state. Safe to call in tight loops.
    Returns a full DetectionResult regardless of whether a detection fires.

    DETECTION LOGIC (documented, deterministic):
    1. Skip if event_count < MIN_EVENTS_FOR_DETECTION (noise filter).
    2. Evaluate each signal independently, record all that breach threshold.
    3. Attack fires when ≥ 1 signal breaches at SEVERITY_THRESHOLD_LOW_DEVIATION (2x).
    4. Severity determined by highest matched deviation + absolute thresholds.
    5. Classification chosen from matched signal types, highest priority first.
    """
    signals: list[DetectionSignal] = []
    missing: list[str] = []

    # Noise gate
    if metrics.event_count < MIN_EVENTS_FOR_DETECTION:
        return DetectionResult(
            is_attack=False,
            severity=None,
            classification=None,
            matched_signals=[],
            missing_evidence=[
                f"insufficient_events: only {metrics.event_count} events in window "
                f"(minimum {MIN_EVENTS_FOR_DETECTION})"
            ],
            baseline=baseline,
            metrics=metrics,
        )

    # ── Signal 1: bytes-per-second deviation ───────────────────────────────
    bps = metrics.bytes_per_second
    if bps is not None:
        threshold_bps = _effective_threshold(
            baseline.p75_bytes_per_second, baseline.static_bps_threshold
        )
        if threshold_bps is not None and threshold_bps > 0:
            deviation = bps / threshold_bps
            if deviation >= SEVERITY_THRESHOLD_LOW_DEVIATION:
                source = (
                    "adaptive"
                    if baseline.p75_bytes_per_second is not None
                    else "static"
                )
                signals.append(DetectionSignal(
                    name="bytes_per_second_deviation",
                    threshold=threshold_bps,
                    observed=bps,
                    deviation_multiplier=deviation,
                    baseline_source=source,
                    detail=f"{bps:.0f} B/s vs baseline {threshold_bps:.0f} B/s ({deviation:.1f}x)",
                ))
        elif threshold_bps is None:
            missing.append("no_bps_baseline_or_static_threshold_configured")
    else:
        missing.append("bytes_unavailable: no bytes_in/bytes_out in this window's events")

    # ── Signal 2: packets-per-second deviation ─────────────────────────────
    pps = metrics.packets_per_second
    if pps is not None:
        threshold_pps = _effective_threshold(
            baseline.p75_packets_per_second, baseline.static_pps_threshold
        )
        if threshold_pps is not None and threshold_pps > 0:
            deviation = pps / threshold_pps
            if deviation >= SEVERITY_THRESHOLD_LOW_DEVIATION:
                source = (
                    "adaptive"
                    if baseline.p75_packets_per_second is not None
                    else "static"
                )
                signals.append(DetectionSignal(
                    name="packets_per_second_deviation",
                    threshold=threshold_pps,
                    observed=pps,
                    deviation_multiplier=deviation,
                    baseline_source=source,
                    detail=f"{pps:.0f} PPS vs baseline {threshold_pps:.0f} PPS ({deviation:.1f}x)",
                ))
    else:
        missing.append("packets_unavailable: no packets_in/packets_out in this window's events")

    # ── Signal 3: flows-per-second deviation ───────────────────────────────
    fps = metrics.flows_per_second
    threshold_fps = _effective_threshold(
        baseline.p75_flows_per_second or None, baseline.static_fps_threshold
    )
    if threshold_fps is not None and threshold_fps > 0:
        deviation = fps / threshold_fps
        if deviation >= SEVERITY_THRESHOLD_LOW_DEVIATION:
            source = (
                "adaptive"
                if baseline.p75_flows_per_second > 0
                else "static"
            )
            signals.append(DetectionSignal(
                name="flows_per_second_deviation",
                threshold=threshold_fps,
                observed=fps,
                deviation_multiplier=deviation,
                baseline_source=source,
                detail=f"{fps:.1f} FPS vs baseline {threshold_fps:.1f} FPS ({deviation:.1f}x)",
            ))

    # ── Signal 4: unique source IP diversity (distributed behavior) ────────
    unique_srcs = metrics.unique_src_ips
    baseline_srcs = baseline.p75_unique_src_ips or 0.0
    if unique_srcs >= DISTRIBUTED_THRESHOLD_UNIQUE_SOURCES:
        deviation = unique_srcs / max(baseline_srcs, 1.0)
        signals.append(DetectionSignal(
            name="unique_source_ips",
            threshold=max(baseline_srcs, DISTRIBUTED_THRESHOLD_UNIQUE_SOURCES),
            observed=unique_srcs,
            deviation_multiplier=deviation,
            baseline_source="adaptive" if baseline_srcs > 0 else "absolute",
            detail=(
                f"{unique_srcs} unique source IPs"
                f" (threshold {DISTRIBUTED_THRESHOLD_UNIQUE_SOURCES})"
            ),
        ))

    # ── Signal 5: UDP protocol dominance ──────────────────────────────────
    udp_frac = metrics.protocol_fraction("udp")
    if udp_frac >= UDP_FLOOD_PROTOCOL_FRACTION:
        signals.append(DetectionSignal(
            name="udp_protocol_dominance",
            threshold=UDP_FLOOD_PROTOCOL_FRACTION,
            observed=udp_frac,
            deviation_multiplier=udp_frac / UDP_FLOOD_PROTOCOL_FRACTION,
            baseline_source="absolute",
            detail=f"UDP is {udp_frac:.1%} of protocol events",
        ))

    # ── Signal 6: ICMP protocol dominance ─────────────────────────────────
    icmp_frac = metrics.protocol_fraction("icmp")
    if icmp_frac >= ICMP_FLOOD_PROTOCOL_FRACTION:
        signals.append(DetectionSignal(
            name="icmp_protocol_dominance",
            threshold=ICMP_FLOOD_PROTOCOL_FRACTION,
            observed=icmp_frac,
            deviation_multiplier=icmp_frac / ICMP_FLOOD_PROTOCOL_FRACTION,
            baseline_source="absolute",
            detail=f"ICMP is {icmp_frac:.1%} of protocol events",
        ))

    # ── Signal 7: SYN flood alert pattern (Suricata alert events only) ────
    # We detect "SYN_FLOOD_SUSPECTED" when Suricata alert signatures
    # containing SYN-flood-pattern keywords make up a majority of alerts.
    # This is inferential — Suricata's signature matches are not guaranteed.
    syn_frac = metrics.syn_alert_fraction
    if syn_frac >= SYN_FLOOD_ALERT_FRACTION and metrics.alert_count >= 5:
        signals.append(DetectionSignal(
            name="syn_flood_alert_signatures",
            threshold=SYN_FLOOD_ALERT_FRACTION,
            observed=syn_frac,
            deviation_multiplier=syn_frac / SYN_FLOOD_ALERT_FRACTION,
            baseline_source="absolute",
            detail=(
                f"{metrics.syn_pattern_alert_count}/{metrics.alert_count} "
                f"alerts matched SYN-flood signature patterns ({syn_frac:.1%})"
            ),
        ))
    else:
        missing.append(
            "tcp_flags_unavailable: TCP flag counters not stored in telemetry schema; "
            "SYN flood inference relies on Suricata alert signatures only"
        )

    # ── No signals fired ──────────────────────────────────────────────────
    if not signals:
        return DetectionResult(
            is_attack=False,
            severity=None,
            classification=None,
            matched_signals=[],
            missing_evidence=missing,
            baseline=baseline,
            metrics=metrics,
        )

    # ── Determine severity ─────────────────────────────────────────────────
    max_deviation = max(s.deviation_multiplier for s in signals)
    severity = _compute_severity(max_deviation, bps, pps, len(signals))

    # ── Determine classification ──────────────────────────────────────────
    classification = _classify(signals, metrics)

    return DetectionResult(
        is_attack=True,
        severity=severity,
        classification=classification,
        matched_signals=signals,
        missing_evidence=missing,
        baseline=baseline,
        metrics=metrics,
    )


# ── Helpers ─────────────────────────────────────────────────────────────────


def _effective_threshold(
    adaptive: float | None, static: float | None
) -> float | None:
    """Return adaptive if it exists and is positive, else static."""
    if adaptive is not None and adaptive > 0:
        return adaptive
    return static


def _compute_severity(
    max_deviation: float,
    bps: float | None,
    pps: float | None,
    signal_count: int,
) -> IncidentSeverity:
    """Deterministic severity from deviation + absolute thresholds.

    CRITICAL: deviation ≥ 20x  OR  BPS ≥ 1 Gbps  OR  3+ signals
    HIGH:     deviation ≥ 10x  OR  PPS ≥ 1 Mpps  OR  2+ signals
    MEDIUM:   deviation ≥ 5x
    LOW:      deviation ≥ 2x   (minimum detection threshold)
    """
    if (
        max_deviation >= SEVERITY_THRESHOLD_CRITICAL_DEVIATION
        or (bps is not None and bps >= SEVERITY_CRITICAL_BPS)
        or signal_count >= 3
    ):
        return IncidentSeverity.CRITICAL
    if (
        max_deviation >= SEVERITY_THRESHOLD_HIGH_DEVIATION
        or (pps is not None and pps >= SEVERITY_HIGH_PPS)
        or signal_count >= 2
    ):
        return IncidentSeverity.HIGH
    if max_deviation >= SEVERITY_THRESHOLD_MEDIUM_DEVIATION:
        return IncidentSeverity.MEDIUM
    return IncidentSeverity.LOW


def _classify(
    signals: list[DetectionSignal],
    metrics: WindowMetrics,
) -> AttackClassification:
    """Classification priority (highest evidence quality first):

    1. SYN_FLOOD_SUSPECTED — Suricata SYN pattern alerts
    2. UDP_FLOOD_SUSPECTED — UDP protocol dominance
    3. ICMP_FLOOD_SUSPECTED — ICMP protocol dominance
    4. DISTRIBUTED_FLOOD — high unique source IPs + volume signals
    5. VOLUMETRIC_FLOOD — pure volume signals (bytes/packets)
    6. ANOMALOUS_TRAFFIC_SURGE — volume signal but without bytes/packets
    7. UNCLASSIFIED_DDOS_SUSPECTED — only FPS or other weak signals
    """
    names = {s.name for s in signals}

    if "syn_flood_alert_signatures" in names:
        return AttackClassification.SYN_FLOOD_SUSPECTED

    if "udp_protocol_dominance" in names:
        return AttackClassification.UDP_FLOOD_SUSPECTED

    if "icmp_protocol_dominance" in names:
        return AttackClassification.ICMP_FLOOD_SUSPECTED

    has_distributed = "unique_source_ips" in names
    has_volume = (
        "bytes_per_second_deviation" in names or "packets_per_second_deviation" in names
    )

    if has_distributed and has_volume:
        return AttackClassification.DISTRIBUTED_FLOOD

    if has_volume:
        return AttackClassification.VOLUMETRIC_FLOOD

    if "flows_per_second_deviation" in names:
        return AttackClassification.ANOMALOUS_TRAFFIC_SURGE

    if has_distributed:
        # Distributed source count alone without volume signals — weak
        return AttackClassification.DISTRIBUTED_FLOOD

    return AttackClassification.UNCLASSIFIED_DDOS_SUSPECTED


def compute_baseline(
    window_history: list[dict[str, float | None]],
    static_bps_threshold: float | None,
    static_pps_threshold: float | None,
    static_fps_threshold: float | None,
) -> BaselineStats:
    """Compute an adaptive baseline from historical window metrics.

    `window_history` is a list of dicts with keys:
      bytes_per_second, packets_per_second, flows_per_second, unique_src_ips
    All values may be None if the metric was unavailable in that window.

    Returns BaselineStats with p75 values and documented confidence level.
    """
    n = len(window_history)

    if n < MIN_BASELINE_WINDOWS:
        confidence = (
            BaselineConfidence.COLD_START
            if n == 0
            else BaselineConfidence.INSUFFICIENT_DATA
        )
        return BaselineStats(
            confidence=confidence,
            window_count=n,
            p75_bytes_per_second=None,
            p75_packets_per_second=None,
            p75_flows_per_second=0.0,
            p75_unique_src_ips=0.0,
            static_bps_threshold=static_bps_threshold,
            static_pps_threshold=static_pps_threshold,
            static_fps_threshold=static_fps_threshold,
        )

    bps_vals = [
        w["bytes_per_second"] for w in window_history if w.get("bytes_per_second") is not None
    ]
    pps_vals = [
        w["packets_per_second"] for w in window_history if w.get("packets_per_second") is not None
    ]
    fps_vals = [
        w["flows_per_second"] for w in window_history if w.get("flows_per_second") is not None
    ]
    src_vals = [w["unique_src_ips"] for w in window_history if w.get("unique_src_ips") is not None]

    return BaselineStats(
        confidence=BaselineConfidence.ESTABLISHED,
        window_count=n,
        p75_bytes_per_second=_p75(bps_vals),  # type: ignore[arg-type]
        p75_packets_per_second=_p75(pps_vals),  # type: ignore[arg-type]
        p75_flows_per_second=_p75(fps_vals) or 0.0,  # type: ignore[arg-type]
        p75_unique_src_ips=_p75(src_vals) or 0.0,  # type: ignore[arg-type]
        static_bps_threshold=static_bps_threshold,
        static_pps_threshold=static_pps_threshold,
        static_fps_threshold=static_fps_threshold,
    )


def _p75(values: list[float]) -> float | None:
    if not values:
        return None
    sorted_vals = sorted(values)
    idx = math.ceil(0.75 * len(sorted_vals)) - 1
    return sorted_vals[max(0, idx)]
