"""Domain events for the Connector & Discovery bounded context."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _make_event_id() -> str:
    from ulid import ULID
    return str(ULID())


@dataclass(frozen=True, slots=True)
class ConnectorDomainEvent:
    """Base for all connector domain events."""

    organization_id: str
    connector_id: str
    event_id: str = field(default_factory=_make_event_id)
    occurred_at_iso: str = field(default_factory=_now_iso)


@dataclass(frozen=True, slots=True)
class ConnectorRegistered(ConnectorDomainEvent):
    connector_type: str = ""
    name: str = ""


@dataclass(frozen=True, slots=True)
class ConnectorConfigured(ConnectorDomainEvent):
    base_url: str = ""


@dataclass(frozen=True, slots=True)
class ConnectorValidated(ConnectorDomainEvent):
    latency_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class ConnectorEnabled(ConnectorDomainEvent):
    actor_id: str = ""


@dataclass(frozen=True, slots=True)
class ConnectorDisabled(ConnectorDomainEvent):
    reason: str = ""
    actor_id: str = ""


@dataclass(frozen=True, slots=True)
class ConnectorArchived(ConnectorDomainEvent):
    reason: str = ""
    actor_id: str = ""


@dataclass(frozen=True, slots=True)
class ConnectorHealthUpdated(ConnectorDomainEvent):
    old_health_status: str = ""
    new_health_status: str = ""
    consecutive_failures: int = 0


@dataclass(frozen=True, slots=True)
class DiscoveryJobStarted(ConnectorDomainEvent):
    job_id: str = ""
    filters: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class DiscoveryJobCompleted(ConnectorDomainEvent):
    job_id: str = ""
    assets_discovered: int = 0
    assets_normalized: int = 0
    assets_failed: int = 0
    duration_seconds: float = 0.0


@dataclass(frozen=True, slots=True)
class DiscoveryJobFailed(ConnectorDomainEvent):
    job_id: str = ""
    error_message: str = ""


@dataclass(frozen=True, slots=True)
class SyncJobStarted(ConnectorDomainEvent):
    job_id: str = ""
    is_full_sync: bool = False


@dataclass(frozen=True, slots=True)
class SyncJobCompleted(ConnectorDomainEvent):
    job_id: str = ""
    assets_added: int = 0
    assets_updated: int = 0
    assets_unchanged: int = 0


@dataclass(frozen=True, slots=True)
class SyncJobFailed(ConnectorDomainEvent):
    job_id: str = ""
    error_message: str = ""


@dataclass(frozen=True, slots=True)
class SyncPolicyChanged(ConnectorDomainEvent):
    enabled: bool = False
    cron_expression: str = ""


@dataclass(frozen=True, slots=True)
class CredentialReferenceUpdated(ConnectorDomainEvent):
    reference_id: str = ""
    credential_type: str = ""
