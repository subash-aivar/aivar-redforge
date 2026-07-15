"""DDoS domain value objects — M19.

All enums are closed (StrEnum + @unique) so that an unrecognised
value in a database row surfaces as a KeyError at deserialization
time rather than silently becoming a valid enum member.

Classification labels end in _SUSPECTED where the evidence is
inferential rather than conclusive — callers must never strip that
qualifier from UI-visible text.
"""

from __future__ import annotations

from enum import StrEnum, unique


@unique
class IncidentStatus(StrEnum):
    """DDoS incident lifecycle states.

    Transitions:
      DETECTED → ACTIVE (first window confirms)
      ACTIVE → ESCALATED (severity worsens / multiple resources)
      ACTIVE | ESCALATED → MITIGATING (recommendation approved + executing)
      MITIGATING → MONITORING (traffic trending toward baseline)
      MONITORING → RESOLVED (traffic within baseline for quiet_period_s)
      MONITORING | RESOLVED → ACTIVE (recurrence detected)
      RESOLVED → CLOSED (explicitly closed by operator)
    """

    DETECTED = "DETECTED"
    ACTIVE = "ACTIVE"
    ESCALATED = "ESCALATED"
    MITIGATING = "MITIGATING"
    MONITORING = "MONITORING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

    @property
    def is_open(self) -> bool:
        return self in (
            IncidentStatus.DETECTED,
            IncidentStatus.ACTIVE,
            IncidentStatus.ESCALATED,
            IncidentStatus.MITIGATING,
            IncidentStatus.MONITORING,
        )

    @property
    def is_terminal(self) -> bool:
        return self in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED)


@unique
class IncidentSeverity(StrEnum):
    """Incident severity — deterministic, documented logic in detection.py.

    CRITICAL: deviation ≥ 20x AND absolute BPS ≥ 1 Gbps  OR ≥ 5 affected resources
    HIGH:     deviation ≥ 10x  OR absolute PPS ≥ 1 Mpps
    MEDIUM:   deviation ≥ 5x   OR absolute bytes/s threshold breached
    LOW:      deviation ≥ 2x   (minimum detection threshold)
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@unique
class AttackClassification(StrEnum):
    """Attack classification labels.

    Rules are evaluated in priority order — only the highest-confidence
    label is attached; all matched signals are preserved in evidence.
    """

    VOLUMETRIC_FLOOD = "VOLUMETRIC_FLOOD"
    DISTRIBUTED_FLOOD = "DISTRIBUTED_FLOOD"
    SYN_FLOOD_SUSPECTED = "SYN_FLOOD_SUSPECTED"
    UDP_FLOOD_SUSPECTED = "UDP_FLOOD_SUSPECTED"
    ICMP_FLOOD_SUSPECTED = "ICMP_FLOOD_SUSPECTED"
    ANOMALOUS_TRAFFIC_SURGE = "ANOMALOUS_TRAFFIC_SURGE"
    UNCLASSIFIED_DDOS_SUSPECTED = "UNCLASSIFIED_DDOS_SUSPECTED"


@unique
class BaselineConfidence(StrEnum):
    """Confidence state of the adaptive baseline for a protected resource.

    COLD_START:          fewer than MIN_BASELINE_WINDOWS observation windows exist;
                         using configured static thresholds only.
    INSUFFICIENT_DATA:   some history but below the MIN_BASELINE_WINDOWS threshold;
                         adaptive baseline computed but has low confidence.
    ESTABLISHED:         ≥ MIN_BASELINE_WINDOWS windows with consistent data;
                         adaptive baseline is the primary detection signal.
    DEGRADED:            baseline history exists but has large gaps (telemetry
                         outage); adaptive values are preserved but flagged stale.
    """

    COLD_START = "COLD_START"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    ESTABLISHED = "ESTABLISHED"
    DEGRADED = "DEGRADED"


@unique
class MitigationMode(StrEnum):
    """How the detection policy handles mitigation."""

    RECOMMEND_ONLY = "RECOMMEND_ONLY"       # default: no auto-execution
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"  # approval unlocks execution
    NOT_CONFIGURED = "NOT_CONFIGURED"        # no mitigation provider registered


@unique
class MitigationRecommendationType(StrEnum):
    RATE_LIMIT = "RATE_LIMIT"
    FIREWALL_BLOCK = "FIREWALL_BLOCK"
    UPSTREAM_ESCALATION = "UPSTREAM_ESCALATION"
    SCRUBBING_CENTER = "SCRUBBING_CENTER"
    WAF_RATE_CONTROL = "WAF_RATE_CONTROL"
    CLOUD_DDOS_ACTIVATION = "CLOUD_DDOS_ACTIVATION"


@unique
class MitigationApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


@unique
class MitigationExecutionStatus(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


# ── Detection constants ─────────────────────────────────────────────────────

# Minimum observation windows before switching from COLD_START to adaptive baseline.
MIN_BASELINE_WINDOWS = 20

# Default detection window duration in seconds.
DEFAULT_WINDOW_SECONDS = 60

# Quiet period: consecutive windows within baseline before RESOLVED.
QUIET_PERIOD_WINDOWS = 3

# Minimum window count before an incident transitions from DETECTED → ACTIVE.
MIN_ACTIVE_WINDOWS = 1

# Deviation multiplier thresholds for severity classification.
SEVERITY_THRESHOLD_CRITICAL_DEVIATION = 20.0
SEVERITY_THRESHOLD_HIGH_DEVIATION = 10.0
SEVERITY_THRESHOLD_MEDIUM_DEVIATION = 5.0
SEVERITY_THRESHOLD_LOW_DEVIATION = 2.0

# Absolute traffic thresholds (bytes/s) for severity adjustment.
SEVERITY_CRITICAL_BPS = 1_000_000_000  # 1 Gbps
SEVERITY_HIGH_PPS = 1_000_000          # 1 Mpps

# Unique source IP count thresholds.
DISTRIBUTED_THRESHOLD_UNIQUE_SOURCES = 50
HIGH_DISTRIBUTED_THRESHOLD = 200

# Protocol concentration thresholds (fraction of total events).
UDP_FLOOD_PROTOCOL_FRACTION = 0.80
ICMP_FLOOD_PROTOCOL_FRACTION = 0.80

# SYN flood: fraction of Suricata alerts with SYN-pattern signatures.
SYN_FLOOD_ALERT_FRACTION = 0.60

# Minimum events in a window for detection to run (avoids false positives from noise).
MIN_EVENTS_FOR_DETECTION = 10
