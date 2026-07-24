"""Closed enums for the siem_search bounded context (M37 §10)."""

from __future__ import annotations

from enum import StrEnum


class SearchQueryShape(StrEnum):
    """Each shape is a distinct query-handler (M37 §10) — never one
    generic "search everything" endpoint."""

    FULL_TEXT = "full_text"
    STRUCTURED = "structured"
    AGGREGATION = "aggregation"
    TIME_SERIES = "time_series"


class SearchEntityType(StrEnum):
    """Which SIEM read-model a query targets (M44E §1) — one closed
    vocabulary instead of five duplicated query classes, since
    validation/execution is identical across entity types and only the
    registry key (this value) differs."""

    EVENTS = "events"
    ALERTS = "alerts"
    INVESTIGATIONS = "investigations"
    DETECTIONS = "detections"
    CORRELATION_SESSIONS = "correlation_sessions"


class SortDirection(StrEnum):
    ASC = "asc"
    DESC = "desc"


class SearchRole(StrEnum):
    """RBAC scopes for siem_search's application layer (M37 §16 —
    extends the existing platform RBAC, no parallel model). Only
    `VIEWER`/`ADMIN` — there is no write-capable role, since search is
    read-only by construction (M44E's own special review requirement)."""

    VIEWER = "siem_search:viewer"
    ADMIN = "siem_search:admin"
