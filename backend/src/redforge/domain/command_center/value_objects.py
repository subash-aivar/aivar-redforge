"""Closed, server-owned value objects for the Command Center — M18.

Every enum here is closed: a client may filter by these values but can
never define a new one. An unrecognized persisted value degrades to the
enum's UNKNOWN member (where one exists) rather than crashing.
"""

from __future__ import annotations

from enum import StrEnum, unique


@unique
class IntegrationType(StrEnum):
    """The six external-telemetry integration boundaries the command
    center exposes. NONE of these has a data source inside the platform;
    each is a provider seam that reports NOT_CONFIGURED until a real
    provider is wired. The platform never fabricates their telemetry."""

    FIREWALL = "firewall"
    NETWORK_TELEMETRY = "network_telemetry"  # bandwidth / flow volume
    CONNECTIVITY = "connectivity"  # ISP / link monitoring
    BACKUP_DR = "backup_dr"
    THREAT_INTEL = "threat_intel"
    GEOLOCATION = "geolocation"


@unique
class IntegrationStatus(StrEnum):
    """NOT_CONFIGURED: no provider descriptor registered — the default,
    and what every integration reports out of the box.
    AWAITING_TELEMETRY: a provider descriptor is registered but no
    telemetry has been received yet (last_telemetry_at is null) — an
    honest distinct state, still shows no fabricated values.
    ACTIVE: a provider is registered AND telemetry has been received.
    ERROR: a provider is registered but reported an error state."""

    NOT_CONFIGURED = "not_configured"
    AWAITING_TELEMETRY = "awaiting_telemetry"
    ACTIVE = "active"
    ERROR = "error"


@unique
class NetworkZoneType(StrEnum):
    """Explicit, admin-authored network segmentation classification.

    Per the M18 brief, an asset is NEVER auto-classified from an
    RFC1918/public-IP heuristic — a zone is a deliberate organization-
    administration assignment. Absence of an assignment = UNKNOWN.
    """

    INTERNET_EDGE = "internet_edge"
    DMZ = "dmz"
    INTERNAL = "internal"
    MANAGEMENT = "management"
    CLOUD = "cloud"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


@unique
class BehaviorDomain(StrEnum):
    """Which behavior-analytics lens a signal belongs to. All three are
    DETERMINISTIC rule evaluations over real persisted rows — never ML
    or opaque scoring."""

    USER = "user"  # UEBA — over the organization admin audit log
    HOST = "host"  # HBA — over network_drift_events (host/service diff)
    NETWORK = "network"  # NBA — over network_drift_events (port/proto diff)


@unique
class BehaviorSeverity(StrEnum):
    """Deterministic severity of a behavior signal — assigned by a fixed
    rule table, never inferred."""

    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    HIGH = "high"


@unique
class PostureBand(StrEnum):
    """Coarse band derived deterministically from the numeric posture
    score. Documented thresholds; not a probability."""

    STRONG = "strong"
    MODERATE = "moderate"
    AT_RISK = "at_risk"
    CRITICAL = "critical"
