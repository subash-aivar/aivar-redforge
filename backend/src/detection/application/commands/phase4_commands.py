"""Commands for Phase 4 pack / exception / evidence / correlation / coverage."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID


@dataclass(frozen=True, slots=True)
class CreateDetectionPack:
    tenant_id: UUID
    pack_key: str
    title: str
    category: str
    maintainer: str
    rule_ids: list[str] = field(default_factory=list)
    description: str = ""
    compliance_framework_id: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class PublishDetectionPack:
    tenant_id: UUID
    pack_id: UUID


@dataclass(frozen=True, slots=True)
class SubscribePackToTenant:
    tenant_id: UUID
    pack_id: UUID
    subscriber_tenant_id: str


@dataclass(frozen=True, slots=True)
class RequestDetectionException:
    tenant_id: UUID
    exception_type: str
    scope_kind: str
    justification: str
    requester: str
    valid_until: str
    affected_rule_ids: list[str]
    finding_id: str | None = None
    rule_id: str | None = None
    classification: str = "operational"
    compliance_mapped: bool = False
    compliance_impact_acknowledged: bool = False
    asset_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ApproveDetectionException:
    tenant_id: UUID
    exception_id: UUID
    approver: str


@dataclass(frozen=True, slots=True)
class RejectDetectionException:
    tenant_id: UUID
    exception_id: UUID
    rejector: str
    reason: str


@dataclass(frozen=True, slots=True)
class ExpireDetectionException:
    tenant_id: UUID
    exception_id: UUID


@dataclass(frozen=True, slots=True)
class RenewDetectionException:
    tenant_id: UUID
    exception_id: UUID
    renewer: str
    new_valid_until: str


@dataclass(frozen=True, slots=True)
class RevokeDetectionException:
    tenant_id: UUID
    exception_id: UUID
    revoker: str
    reason: str


@dataclass(frozen=True, slots=True)
class SubmitEvidence:
    tenant_id: UUID
    evidence_type: str
    payload: bytes
    collected_by: str
    finding_id: str | None = None
    exception_id: str | None = None
    simulation_id: str | None = None
    storage_uri: str | None = None


@dataclass(frozen=True, slots=True)
class VerifyEvidenceIntegrity:
    tenant_id: UUID
    evidence_id: UUID


@dataclass(frozen=True, slots=True)
class CorrelateFinding:
    tenant_id: UUID
    finding_id: UUID
    refresh: bool = False


@dataclass(frozen=True, slots=True)
class RefreshCorrelation:
    tenant_id: UUID
    finding_id: UUID


@dataclass(frozen=True, slots=True)
class ComputeDetectionCoverage:
    tenant_id: UUID
    in_scope_techniques: list[str] = field(default_factory=list)
