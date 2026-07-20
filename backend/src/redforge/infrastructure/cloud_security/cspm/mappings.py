"""Domain ↔ ORM mapping for CSPM aggregates."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from redforge.domain.cloud_security.cspm.entities import (
    CSPMDriftBaseline,
    EvaluationResult,
    FindingEvidence,
    FindingHistory,
    RemediationReference,
)
from redforge.domain.cloud_security.cspm.evaluation import CSPMEvaluation
from redforge.domain.cloud_security.cspm.finding import CSPMFinding
from redforge.domain.cloud_security.cspm.policy import CSPMPolicy
from redforge.domain.cloud_security.cspm.value_objects import (
    ComplianceRef,
    CSPMEvaluationId,
    CSPMFindingId,
    CSPMPolicyId,
    CSPMRuleId,
    EvaluationContext,
    EvaluationStatus,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    PolicyVersion,
    RuleMetadata,
)
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId
from redforge.infrastructure.database.models.cloud_security import (
    CSPMDriftBaselineModel,
    CSPMEvaluationModel,
    CSPMFindingModel,
    CSPMPolicyModel,
)


def policy_to_model(
    policy: CSPMPolicy, model: CSPMPolicyModel | None = None
) -> CSPMPolicyModel:
    target = model or CSPMPolicyModel(id=str(policy.id))
    target.id = str(policy.id)
    target.rule_id = str(policy.rule_id)
    target.title = policy.title
    target.description = policy.description
    target.severity = policy.severity.value
    target.version = policy.version.to_dict()
    target.provider_types = list(policy.provider_types)
    target.asset_types = list(policy.asset_types)
    target.metadata_ = policy.metadata.to_dict()
    target.remediation = policy.remediation.to_dict()
    target.compliance_mapping = [ref.to_dict() for ref in policy.compliance_mapping]
    target.rule = dict(policy.rule)
    target.inherits_from = policy.inherits_from
    target.enabled = policy.enabled
    target.evaluation_strategy = policy.evaluation_strategy
    target.created_at = policy.created_at
    target.updated_at = policy.updated_at
    target.row_version = policy.row_version
    return target


def policy_from_model(model: CSPMPolicyModel) -> CSPMPolicy:
    version_raw = model.version or {}
    if isinstance(version_raw, dict) and "major" in version_raw:
        version = PolicyVersion(
            major=int(version_raw["major"]),
            minor=int(version_raw["minor"]),
            patch=int(version_raw.get("patch", 0)),
        )
    else:
        version = PolicyVersion.parse(str(version_raw) if version_raw else "1.0.0")
    return CSPMPolicy(
        id=CSPMPolicyId(model.id),
        rule_id=CSPMRuleId(model.rule_id),
        title=model.title,
        description=model.description,
        severity=FindingSeverity(model.severity),
        version=version,
        provider_types=tuple(str(x) for x in (model.provider_types or [])),
        asset_types=tuple(str(x) for x in (model.asset_types or [])),
        metadata=RuleMetadata.from_dict(dict(model.metadata_ or {})),
        remediation=RemediationReference.from_dict(dict(model.remediation or {})),
        compliance_mapping=[
            ComplianceRef.from_dict(item)
            for item in (model.compliance_mapping or [])
            if isinstance(item, dict)
        ],
        rule=dict(model.rule or {}),
        inherits_from=model.inherits_from,
        enabled=bool(model.enabled),
        evaluation_strategy=model.evaluation_strategy or "boolean",
        created_at=model.created_at,
        updated_at=model.updated_at,
        row_version=model.row_version,
    )


def finding_to_model(
    finding: CSPMFinding, model: CSPMFindingModel | None = None
) -> CSPMFindingModel:
    target = model or CSPMFindingModel(id=finding.id.value)
    target.id = finding.id.value
    target.organization_id = str(finding.organization_id)
    target.cloud_asset_id = finding.cloud_asset_id.value
    target.policy_id = str(finding.policy_id)
    target.rule_id = str(finding.rule_id)
    target.severity = finding.severity.value
    target.confidence = finding.confidence.value
    target.title = finding.title
    target.description = finding.description
    target.remediation = finding.remediation.to_dict()
    target.compliance_mapping = [ref.to_dict() for ref in finding.compliance_mapping]
    target.status = finding.status.value
    target.evidence = [e.to_dict() for e in finding.evidence]
    target.history = [h.to_dict() for h in finding.history]
    target.first_seen_at = finding.first_seen_at
    target.last_seen_at = finding.last_seen_at
    target.detected_at = finding.detected_at
    target.resolved_at = finding.resolved_at
    target.reopened_at = finding.reopened_at
    target.suppressed_until = finding.suppressed_until
    target.accepted_by = finding.accepted_by
    target.accepted_reason = finding.accepted_reason
    target.config_hash = finding.config_hash
    target.fingerprint = finding.fingerprint
    target.created_at = finding.created_at
    target.updated_at = finding.updated_at
    target.version = finding.version
    target.row_version = finding.version
    return target


def finding_from_model(model: CSPMFindingModel) -> CSPMFinding:
    return CSPMFinding(
        id=CSPMFindingId(model.id),
        cloud_asset_id=CloudAssetId(model.cloud_asset_id),
        organization_id=OrganizationId(model.organization_id),
        policy_id=CSPMPolicyId(model.policy_id),
        rule_id=CSPMRuleId(model.rule_id),
        severity=FindingSeverity(model.severity),
        confidence=FindingConfidence(model.confidence),
        title=model.title,
        description=model.description,
        remediation=RemediationReference.from_dict(dict(model.remediation or {})),
        compliance_mapping=[
            ComplianceRef.from_dict(item)
            for item in (model.compliance_mapping or [])
            if isinstance(item, dict)
        ],
        status=FindingStatus(model.status),
        evidence=[
            FindingEvidence.from_dict(item)
            for item in (model.evidence or [])
            if isinstance(item, dict)
        ],
        history=[
            FindingHistory.from_dict(item)
            for item in (model.history or [])
            if isinstance(item, dict)
        ],
        first_seen_at=model.first_seen_at,
        last_seen_at=model.last_seen_at,
        detected_at=model.detected_at,
        resolved_at=model.resolved_at,
        reopened_at=model.reopened_at,
        suppressed_until=model.suppressed_until,
        accepted_by=model.accepted_by,
        accepted_reason=model.accepted_reason,
        config_hash=model.config_hash,
        fingerprint=model.fingerprint,
        created_at=model.created_at,
        updated_at=model.updated_at,
        version=model.version,
    )


def _parse_context(raw: dict[str, Any]) -> EvaluationContext:
    started_raw = raw.get("started_at")
    started_at: datetime | None = None
    if isinstance(started_raw, str) and started_raw:
        started_at = datetime.fromisoformat(started_raw)
    elif isinstance(started_raw, datetime):
        started_at = started_raw
    return EvaluationContext(
        organization_id=str(raw.get("organization_id", "")),
        cloud_account_id=(
            str(raw["cloud_account_id"]) if raw.get("cloud_account_id") is not None else None
        ),
        evaluation_id=str(raw.get("evaluation_id", "")),
        triggered_by=str(raw.get("triggered_by", "")),
        incremental=bool(raw.get("incremental", False)),
        policy_ids=tuple(str(x) for x in (raw.get("policy_ids") or [])),
        started_at=started_at,
    )


def evaluation_to_model(
    evaluation: CSPMEvaluation, model: CSPMEvaluationModel | None = None
) -> CSPMEvaluationModel:
    target = model or CSPMEvaluationModel(id=evaluation.id.value)
    target.id = evaluation.id.value
    target.organization_id = str(evaluation.organization_id)
    account_raw = evaluation.cloud_account_id
    target.cloud_account_id = UUID(account_raw) if account_raw else None
    target.status = evaluation.status.value
    target.context = evaluation.context.to_dict()
    target.results = [r.to_dict() for r in evaluation.results]
    target.assets_evaluated = evaluation.assets_evaluated
    target.policies_evaluated = evaluation.policies_evaluated
    target.findings_opened = evaluation.findings_opened
    target.findings_resolved = evaluation.findings_resolved
    target.diagnostics = dict(evaluation.diagnostics)
    target.started_at = evaluation.started_at
    target.completed_at = evaluation.completed_at
    target.error_message = evaluation.error_message
    target.row_version = evaluation.version
    return target


def evaluation_from_model(model: CSPMEvaluationModel) -> CSPMEvaluation:
    return CSPMEvaluation(
        id=CSPMEvaluationId(model.id),
        organization_id=OrganizationId(model.organization_id),
        cloud_account_id=str(model.cloud_account_id) if model.cloud_account_id else None,
        status=EvaluationStatus(model.status),
        context=_parse_context(dict(model.context or {})),
        results=[
            EvaluationResult.from_dict(item)
            for item in (model.results or [])
            if isinstance(item, dict)
        ],
        assets_evaluated=model.assets_evaluated,
        policies_evaluated=model.policies_evaluated,
        findings_opened=model.findings_opened,
        findings_resolved=model.findings_resolved,
        diagnostics=dict(model.diagnostics or {}),
        started_at=model.started_at,
        completed_at=model.completed_at,
        error_message=model.error_message,
        version=model.row_version,
    )


def drift_baseline_to_model(
    baseline: CSPMDriftBaseline, model: CSPMDriftBaselineModel | None = None
) -> CSPMDriftBaselineModel:
    target = model or CSPMDriftBaselineModel(id=baseline.id)
    target.id = baseline.id
    target.organization_id = baseline.organization_id
    target.cloud_asset_id = baseline.cloud_asset_id
    target.drift_kind = baseline.drift_kind
    target.baseline_hash = baseline.baseline_hash
    target.baseline_snapshot = dict(baseline.baseline_snapshot)
    target.captured_at = baseline.captured_at
    target.updated_at = baseline.updated_at
    return target


def drift_baseline_from_model(model: CSPMDriftBaselineModel) -> CSPMDriftBaseline:
    return CSPMDriftBaseline(
        id=model.id,
        organization_id=model.organization_id,
        cloud_asset_id=model.cloud_asset_id,
        drift_kind=model.drift_kind,
        baseline_hash=model.baseline_hash,
        baseline_snapshot=dict(model.baseline_snapshot or {}),
        captured_at=model.captured_at,
        updated_at=model.updated_at,
    )
