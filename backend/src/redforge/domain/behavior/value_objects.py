"""Behavioral Security value objects — M20.

All enums are closed (StrEnum + @unique).  Detection labels end with
_SUSPECTED where evidence is inferential rather than conclusive.

Supported detections (from canonical telemetry_events schema):
  NEW_DESTINATION            — first-ever dst_ip for this source
  RARE_DESTINATION           — dst_ip seen < RARE_THRESHOLD times in baseline
  HIGH_FAN_OUT               — one src_ip → many distinct dst_ips per window
  PORT_SCAN_SUSPECTED        — one src_ip → many distinct dst_ports per window
  BEACONING_SUSPECTED        — periodic inter-arrival timing to fixed destination
  ABNORMAL_OUTBOUND_TRANSFER — bytes_out deviation from entity baseline
  UNUSUAL_EAST_WEST          — new RFC-1918 → RFC-1918 pair
  UNUSUAL_SERVICE_ACCESS     — first-seen dst_port for this src→dst pair

Not supported (honestly documented):
  User/identity behavior     — no authentication events in telemetry_events
  Impossible travel          — no session-level geo data
  Failed-connection ratio    — no TCP state machine data
  Lateral movement confirmed — cannot confirm without host-level evidence
  MFA anomalies              — not in telemetry
"""

from __future__ import annotations

from enum import StrEnum, unique


@unique
class DetectionType(StrEnum):
    NEW_DESTINATION = "NEW_DESTINATION"
    RARE_DESTINATION = "RARE_DESTINATION"
    HIGH_FAN_OUT = "HIGH_FAN_OUT"
    PORT_SCAN_SUSPECTED = "PORT_SCAN_SUSPECTED"
    BEACONING_SUSPECTED = "BEACONING_SUSPECTED"
    ABNORMAL_OUTBOUND_TRANSFER = "ABNORMAL_OUTBOUND_TRANSFER"
    UNUSUAL_EAST_WEST = "UNUSUAL_EAST_WEST"
    UNUSUAL_SERVICE_ACCESS = "UNUSUAL_SERVICE_ACCESS"


@unique
class DetectionSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@unique
class DetectionStatus(StrEnum):
    """Behavioral detection lifecycle states.

    DETECTED  → ACTIVE (confirmed across ≥ 1 observation window)
    ACTIVE    → INVESTIGATING (analyst assignment)
    ACTIVE | INVESTIGATING → MONITORING (quiet period observed)
    MONITORING → RESOLVED (quiet_period_windows elapsed)
    MONITORING | RESOLVED → ACTIVE (recurrence)
    RESOLVED  → CLOSED (explicit operator closure)
    """

    DETECTED = "DETECTED"
    ACTIVE = "ACTIVE"
    INVESTIGATING = "INVESTIGATING"
    MONITORING = "MONITORING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

    @property
    def is_open(self) -> bool:
        return self in (
            DetectionStatus.DETECTED,
            DetectionStatus.ACTIVE,
            DetectionStatus.INVESTIGATING,
            DetectionStatus.MONITORING,
        )

    @property
    def is_terminal(self) -> bool:
        return self in (DetectionStatus.RESOLVED, DetectionStatus.CLOSED)


@unique
class EntityType(StrEnum):
    IP_ADDRESS = "IP_ADDRESS"
    COMMUNICATION_PAIR = "COMMUNICATION_PAIR"


@unique
class BaselineConfidence(StrEnum):
    COLD_START = "COLD_START"           # zero history
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"  # < MIN_BASELINE_WINDOWS
    ESTABLISHED = "ESTABLISHED"         # ≥ MIN_BASELINE_WINDOWS
    DEGRADED = "DEGRADED"               # gaps detected in history


@unique
class RiskLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


# ── Detection thresholds (all documented, deterministic) ───────────────────

# Minimum telemetry events in a window before detection runs.
MIN_EVENTS_FOR_DETECTION = 5

# Number of history windows required before adaptive baseline is ESTABLISHED.
MIN_BASELINE_WINDOWS = 10

# Fan-out: distinct destination IPs from one source in one window.
FAN_OUT_MEDIUM_THRESHOLD = 20
FAN_OUT_HIGH_THRESHOLD = 50

# Port scan: distinct destination ports from one source in one window.
PORT_SCAN_MEDIUM_THRESHOLD = 15
PORT_SCAN_HIGH_THRESHOLD = 40

# Beaconing: minimum number of connection samples to compute periodicity.
BEACONING_MIN_SAMPLES = 8
# Maximum jitter coefficient (std / mean) to classify as periodic.
BEACONING_MAX_JITTER_COEFFICIENT = 0.25
# Minimum interval (seconds) — avoids classifying burst traffic.
BEACONING_MIN_INTERVAL_SECONDS = 20.0

# Outbound transfer: deviation multiplier from baseline to detect.
TRANSFER_LOW_DEVIATION = 3.0
TRANSFER_HIGH_DEVIATION = 10.0
TRANSFER_CRITICAL_DEVIATION = 25.0

# Rare destination: seen fewer than this many times in baseline period.
RARE_DESTINATION_THRESHOLD = 3

# East-west: both IPs must be RFC-1918 for UNUSUAL_EAST_WEST.
RFC1918_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.")


def is_rfc1918(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in RFC1918_PREFIXES)
