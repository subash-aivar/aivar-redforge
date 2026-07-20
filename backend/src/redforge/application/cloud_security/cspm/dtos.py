"""DTOs and commands/queries for CSPM assessment APIs."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class TriggerCSPMEvaluationCommand:
    organization_id: str
    cloud_account_id: str | None = None
    triggered_by: str = "api"
    policy_ids: tuple[str, ...] = ()
    incremental: bool = False


@dataclass(frozen=True, slots=True)
class EvaluateAssetCommand:
    organization_id: str
    cloud_asset_id: str
    triggered_by: str = "api"
    policy_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class UpdateFindingStatusCommand:
    organization_id: str
    finding_id: str
    status: str
    changed_by: str
    reason: str = ""
    suppressed_until: datetime | None = None
    accepted_by: str | None = None


@dataclass(frozen=True, slots=True)
class ListFindingsQuery:
    organization_id: str
    page: int = 1
    size: int = 50
    status: str | None = None
    cloud_asset_id: str | None = None
    severity: str | None = None


@dataclass(frozen=True, slots=True)
class GetFindingQuery:
    organization_id: str
    finding_id: str


@dataclass(frozen=True, slots=True)
class ListPoliciesQuery:
    enabled_only: bool = False


@dataclass(frozen=True, slots=True)
class GetPolicyQuery:
    policy_id: str


@dataclass(frozen=True, slots=True)
class ListEvaluationsQuery:
    organization_id: str
    page: int = 1
    size: int = 50


@dataclass(frozen=True, slots=True)
class GetEvaluationQuery:
    organization_id: str
    evaluation_id: str


@dataclass(frozen=True, slots=True)
class SummaryQuery:
    organization_id: str


@dataclass(frozen=True, slots=True)
class ComplianceRefDTO:
    framework_key: str
    requirement_ref: str
    resolved: bool = False


@dataclass(frozen=True, slots=True)
class FindingEvidenceDTO:
    evidence_id: str
    path: str
    expected: str
    actual: str
    message: str


@dataclass(frozen=True, slots=True)
class CSPMFindingDTO:
    finding_id: str
    organization_id: str
    cloud_asset_id: str
    policy_id: str
    rule_id: str
    severity: str
    confidence: str
    title: str
    description: str
    status: str
    config_hash: str
    fingerprint: str
    first_seen_at: datetime
    last_seen_at: datetime
    detected_at: datetime
    resolved_at: datetime | None
    reopened_at: datetime | None
    suppressed_until: datetime | None
    accepted_by: str | None
    accepted_reason: str | None
    created_at: datetime
    updated_at: datetime
    version: int
    compliance_mapping: list[ComplianceRefDTO] = field(default_factory=list)
    evidence: list[FindingEvidenceDTO] = field(default_factory=list)
    remediation: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CSPMFindingPageDTO:
    items: list[CSPMFindingDTO]
    page: int
    size: int
    total: int


@dataclass(frozen=True, slots=True)
class CSPMPolicyDTO:
    policy_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    version: str
    provider_types: list[str]
    asset_types: list[str]
    enabled: bool
    evaluation_strategy: str
    inherits_from: str | None
    metadata: dict[str, Any]
    remediation: dict[str, Any]
    compliance_mapping: list[ComplianceRefDTO]
    rule: dict[str, Any]
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class EvaluationResultDTO:
    policy_id: str
    rule_id: str
    cloud_asset_id: str
    passed: bool
    severity: str
    title: str
    message: str
    duration_ms: int


@dataclass(frozen=True, slots=True)
class CSPMEvaluationDTO:
    evaluation_id: str
    organization_id: str
    cloud_account_id: str | None
    status: str
    assets_evaluated: int
    policies_evaluated: int
    findings_opened: int
    findings_resolved: int
    diagnostics: dict[str, Any]
    started_at: datetime
    completed_at: datetime | None
    error_message: str | None
    results: list[EvaluationResultDTO] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class CSPMEvaluationPageDTO:
    items: list[CSPMEvaluationDTO]
    page: int
    size: int
    total: int


@dataclass(frozen=True, slots=True)
class FindingSummaryDTO:
    organization_id: str
    open_by_severity: dict[str, int]
    total_open: int


@dataclass(frozen=True, slots=True)
class ComplianceSummaryDTO:
    organization_id: str
    mapped_frameworks: list[str]
    mapped_controls: int
    unresolved_refs: int
    open_findings_with_mapping: int
