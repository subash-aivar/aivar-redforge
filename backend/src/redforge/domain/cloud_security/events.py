"""Domain events for M26 Cloud Security foundation aggregates."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class CloudProviderRegistered:
    provider_id: str
    organization_id: str
    provider_type: str
    display_name: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class CloudProviderUpdated:
    provider_id: str
    organization_id: str
    display_name: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class CloudProviderDisabled:
    provider_id: str
    organization_id: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class CloudAccountDiscovered:
    account_id: str
    cloud_provider_id: str
    organization_id: str
    external_id: str
    account_type: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class CloudAccountSyncStarted:
    account_id: str
    organization_id: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class CloudAccountSyncCompleted:
    account_id: str
    organization_id: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class CloudAccountSyncFailed:
    account_id: str
    organization_id: str
    error: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class CloudAccountCredentialRotated:
    account_id: str
    organization_id: str
    credential_reference_id: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


CloudSecurityDomainEvent = (
    CloudProviderRegistered
    | CloudProviderUpdated
    | CloudProviderDisabled
    | CloudAccountDiscovered
    | CloudAccountSyncStarted
    | CloudAccountSyncCompleted
    | CloudAccountSyncFailed
    | CloudAccountCredentialRotated
)
