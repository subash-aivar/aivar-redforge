"""DTOs for Phase 4 pack / exception / evidence / coverage."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class DetectionPackDTO:
    pack_id: str
    pack_key: str
    title: str
    category: str
    lifecycle_state: str
    semver: str
    rule_ids: list[str]
    subscribed_tenants: list[str]
    compliance_framework_id: str | None = None
    coverage: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PackPageDTO:
    items: list[DetectionPackDTO]
    total: int
    limit: int
    offset: int


@dataclass(frozen=True, slots=True)
class DetectionExceptionDTO:
    exception_id: str
    exception_type: str
    state: str
    requester: str
    valid_until: str
    affected_rule_ids: list[str]
    compliance_impact_acknowledged: bool
    approver: str | None = None
    justification: str = ""


@dataclass(frozen=True, slots=True)
class ExceptionPageDTO:
    items: list[DetectionExceptionDTO]
    total: int
    limit: int
    offset: int


@dataclass(frozen=True, slots=True)
class DetectionEvidenceDTO:
    evidence_id: str
    evidence_type: str
    payload_hash: str
    storage_ref: str
    integrity_status: str
    collected_by: str
    finding_id: str | None = None
    exception_id: str | None = None
    simulation_id: str | None = None


@dataclass(frozen=True, slots=True)
class CoverageTechniqueDTO:
    technique_id: str
    rule_count: int
    rule_ids: list[str]
    covered: bool


@dataclass(frozen=True, slots=True)
class DetectionCoverageReportDTO:
    tenant_id: str
    techniques: list[CoverageTechniqueDTO]
    covered_count: int
    gap_count: int
    gaps: list[str]
    total_in_scope: int
