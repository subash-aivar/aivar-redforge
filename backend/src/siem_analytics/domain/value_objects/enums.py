"""Closed enums for the siem_analytics bounded context (M37 §11's
implicit "thin, mostly infrastructure" treatment, consistent with
M38 §15's equivalent read-side reporting contexts)."""

from __future__ import annotations

from enum import StrEnum


class MetricCategory(StrEnum):
    """The metric categories M42 Phase 11 aggregates over (ingestion,
    normalization health, detection/correlation rates, alert queue
    depth) — enumerated now so Phase 11's read-models have a closed,
    non-ad-hoc category vocabulary to target from day one."""

    INGESTION_VOLUME = "ingestion_volume"
    NORMALIZATION_HEALTH = "normalization_health"
    DETECTION_RATE = "detection_rate"
    CORRELATION_RATE = "correlation_rate"
    ALERT_QUEUE_DEPTH = "alert_queue_depth"


class AnalyticsEntityType(StrEnum):
    """Which SIEM read-model an analytics query aggregates over (M44F
    §1) — mirrors `SearchEntityType` (M44E §1): one closed vocabulary
    instead of duplicated query classes, since validation/orchestration
    is identical across entity types and only the registry key (this
    value) differs."""

    EVENTS = "events"
    ALERTS = "alerts"
    INVESTIGATIONS = "investigations"
    DETECTIONS = "detections"
    CORRELATION_SESSIONS = "correlation_sessions"


class AnalyticsAggregationType(StrEnum):
    """The closed set of aggregation operations the Analytics Engine
    supports (M44F §1). Selecting the operation is a query concern;
    computing it is always the registered `IAnalyticsProvider`'s job —
    this context never computes an aggregate itself."""

    COUNT = "count"
    SUM = "sum"
    AVG = "avg"
    MIN = "min"
    MAX = "max"


class AnalyticsRole(StrEnum):
    """RBAC scopes for siem_analytics's application layer (M37 §16 —
    extends the existing platform RBAC, no parallel model). Only
    `VIEWER`/`ADMIN` — analytics remains read-only by construction
    (M44F's own special review requirement)."""

    VIEWER = "siem_analytics:viewer"
    ADMIN = "siem_analytics:admin"
