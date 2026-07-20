"""Domain events for CSPM."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class CSPMFindingCreated:
    finding_id: str
    organization_id: str
    cloud_asset_id: str
    policy_id: str
    severity: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class CSPMFindingUpdated:
    finding_id: str
    organization_id: str
    status: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class CSPMFindingResolved:
    finding_id: str
    organization_id: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class CSPMFindingReopened:
    finding_id: str
    organization_id: str
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class CSPMPolicyEvaluated:
    evaluation_id: str
    organization_id: str
    policy_id: str
    findings_opened: int
    findings_resolved: int
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class ComplianceStateChanged:
    organization_id: str
    framework_key: str
    open_findings: int
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


CSPMDomainEvent = (
    CSPMFindingCreated
    | CSPMFindingUpdated
    | CSPMFindingResolved
    | CSPMFindingReopened
    | CSPMPolicyEvaluated
    | ComplianceStateChanged
)
