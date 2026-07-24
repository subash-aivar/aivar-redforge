"""Closed enums for the siem_ingestion bounded context (M37 §3)."""

from __future__ import annotations

from enum import StrEnum


class IngestionSourceType(StrEnum):
    """M37 §2.1 `EventSource.source_type` — mirrored here for Phase 1's
    provisional batch envelope, ahead of the full CEM (M42 Phase 2)."""

    CONNECTOR = "connector"
    AGENT = "agent"
    CLOUD = "cloud"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    IDENTITY = "identity"
    AI = "ai"
    CUSTOM = "custom"


class BatchStatus(StrEnum):
    """An admission decision for an `IngestedEventBatch` (M37 §2.2).

    `THROTTLED` is a first-class outcome, not an error — high-volume
    sources must degrade gracefully rather than the ingestion path
    ever blocking or crashing (M37 §3).
    """

    PENDING = "pending"
    ACCEPTED = "accepted"
    THROTTLED = "throttled"
    REJECTED = "rejected"


class IngestionRole(StrEnum):
    """RBAC scopes for siem_ingestion's application layer (M37 §16 —
    extends the existing platform RBAC, no parallel model)."""

    VIEWER = "siem_ingestion:viewer"
    SUBMITTER = "siem_ingestion:submit"
    ADMIN = "siem_ingestion:admin"
