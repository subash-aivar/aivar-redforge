"""Domain ↔ ORM mapping for cloud risk aggregates."""

from __future__ import annotations

from uuid import UUID, uuid4

from redforge.domain.cloud_security.risk.entities import (
    RiskContribution,
    RiskEvidence,
    RiskException,
    RiskHistoryEntry,
)
from redforge.domain.cloud_security.risk.factor import (
    CloudRiskAssessment,
    CloudRiskAssessmentId,
    CloudRiskExposure,
    CloudRiskExposureId,
    CloudRiskFactor,
    CloudRiskFactorId,
)
from redforge.domain.cloud_security.risk.score import CloudRiskScore
from redforge.domain.cloud_security.risk.value_objects import (
    CloudRiskScoreId,
    RiskCalculationVersion,
    RiskCategory,
    RiskConfidence,
    RiskSeverity,
    RiskSource,
    RiskState,
    RiskTrend,
    RiskWeightProfile,
)
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId
from redforge.infrastructure.database.models.cloud_security import (
    CloudRiskAssessmentModel,
    CloudRiskExposureModel,
    CloudRiskFactorModel,
    CloudRiskHistoryModel,
    CloudRiskScoreModel,
)


def score_to_model(
    score: CloudRiskScore, model: CloudRiskScoreModel | None = None
) -> CloudRiskScoreModel:
    target = model or CloudRiskScoreModel(id=score.id.value)
    target.id = score.id.value
    target.organization_id = str(score.organization_id)
    target.cloud_asset_id = score.cloud_asset_id.value
    target.overall_score = score.overall_score
    target.threat_intel_score = score.threat_intel_score
    target.compliance_score = score.compliance_score
    target.identity_score = score.identity_score
    target.exposure_score = score.exposure_score
    target.business_criticality_score = score.business_criticality_score
    target.attack_path_score = score.attack_path_score
    target.cspm_score = score.cspm_score
    target.kubernetes_score = score.kubernetes_score
    target.runtime_score = score.runtime_score
    target.score_components = [c.to_dict() for c in score.score_components]
    target.evidence = [e.to_dict() for e in score.evidence]
    target.history = [h.to_dict() for h in score.history]
    target.exceptions = [x.to_dict() for x in score.exceptions]
    target.weight_profile = score.weight_profile.to_dict()
    target.calculation_version = score.calculation_version.to_dict()
    target.confidence = score.confidence.value
    target.trend = score.trend.value
    target.state = score.state.value
    target.threshold = score.threshold
    target.computed_at = score.computed_at
    target.valid_until = score.valid_until
    target.created_at = score.created_at
    target.updated_at = score.updated_at
    target.row_version = score.row_version
    return target


def score_from_model(model: CloudRiskScoreModel) -> CloudRiskScore:
    components = [
        RiskContribution.from_dict(item)
        for item in (model.score_components or [])
        if isinstance(item, dict)
    ]
    evidence = [
        RiskEvidence.from_dict(item)
        for item in (model.evidence or [])
        if isinstance(item, dict)
    ]
    history = [
        RiskHistoryEntry.from_dict(item)
        for item in (model.history or [])
        if isinstance(item, dict)
    ]
    exceptions: list[RiskException] = []
    for item in model.exceptions or []:
        if not isinstance(item, dict):
            continue
        expires = item.get("expires_at")
        expires_at = None
        if isinstance(expires, str) and expires:
            from datetime import datetime

            expires_at = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        exceptions.append(
            RiskException(
                exception_id=str(item.get("exception_id") or uuid4()),
                reason=str(item.get("reason", "")),
                approved_by=str(item.get("approved_by", "")),
                expires_at=expires_at,
            )
        )
    return CloudRiskScore(
        id=CloudRiskScoreId(model.id),
        organization_id=OrganizationId(model.organization_id),
        cloud_asset_id=CloudAssetId(model.cloud_asset_id),
        overall_score=float(model.overall_score),
        threat_intel_score=float(model.threat_intel_score),
        compliance_score=float(model.compliance_score),
        identity_score=float(model.identity_score),
        exposure_score=float(model.exposure_score),
        business_criticality_score=float(model.business_criticality_score),
        attack_path_score=float(model.attack_path_score),
        cspm_score=float(model.cspm_score),
        kubernetes_score=float(model.kubernetes_score),
        runtime_score=float(model.runtime_score),
        score_components=components,
        evidence=evidence,
        history=history,
        exceptions=exceptions,
        confidence=RiskConfidence(model.confidence),
        trend=RiskTrend(model.trend),
        state=RiskState(model.state),
        calculation_version=RiskCalculationVersion.from_dict(
            dict(model.calculation_version or {})
        ),
        weight_profile=RiskWeightProfile.from_dict(dict(model.weight_profile or {})),
        computed_at=model.computed_at,
        valid_until=model.valid_until,
        threshold=float(model.threshold),
        created_at=model.created_at,
        updated_at=model.updated_at,
        row_version=model.row_version,
    )


def history_row_from_score(score: CloudRiskScore) -> CloudRiskHistoryModel:
    latest = score.history[-1] if score.history else None
    reason = latest.reason if latest else "calculated"
    dims = (
        latest.dimensions
        if latest and latest.dimensions
        else {
            "threat_intel": score.threat_intel_score,
            "compliance": score.compliance_score,
            "identity": score.identity_score,
            "exposure": score.exposure_score,
            "attack_path": score.attack_path_score,
            "cspm": score.cspm_score,
            "criticality": score.business_criticality_score,
            "kubernetes": score.kubernetes_score,
            "runtime": score.runtime_score,
        }
    )
    history_id = UUID(latest.history_id) if latest else uuid4()
    return CloudRiskHistoryModel(
        id=history_id,
        organization_id=str(score.organization_id),
        cloud_asset_id=score.cloud_asset_id.value,
        risk_score_id=score.id.value,
        overall_score=score.overall_score,
        dimensions=dict(dims),
        calculation_version=str(score.calculation_version),
        recorded_at=score.computed_at,
        reason=reason,
    )


def factor_to_model(
    factor: CloudRiskFactor, model: CloudRiskFactorModel | None = None
) -> CloudRiskFactorModel:
    target = model or CloudRiskFactorModel(id=factor.id.value)
    target.id = factor.id.value
    target.organization_id = str(factor.organization_id)
    target.cloud_asset_id = factor.cloud_asset_id.value
    target.category = factor.category.value
    target.source = factor.source.value
    target.title = factor.title
    target.description = factor.description
    target.score = factor.score
    target.severity = factor.severity.value
    target.confidence = factor.confidence.value
    target.evidence = [e.to_dict() for e in factor.evidence]
    target.metadata_ = dict(factor.metadata)
    target.created_at = factor.created_at
    target.updated_at = factor.updated_at
    target.row_version = factor.row_version
    return target


def factor_from_model(model: CloudRiskFactorModel) -> CloudRiskFactor:
    return CloudRiskFactor(
        id=CloudRiskFactorId(model.id),
        organization_id=OrganizationId(model.organization_id),
        cloud_asset_id=CloudAssetId(model.cloud_asset_id),
        category=RiskCategory(model.category),
        source=RiskSource(model.source),
        title=model.title,
        description=model.description or "",
        score=float(model.score),
        severity=RiskSeverity(model.severity),
        confidence=RiskConfidence(model.confidence),
        evidence=tuple(
            RiskEvidence.from_dict(item)
            for item in (model.evidence or [])
            if isinstance(item, dict)
        ),
        metadata=dict(model.metadata_ or {}),
        created_at=model.created_at,
        updated_at=model.updated_at,
        row_version=model.row_version,
    )


def exposure_to_model(
    exposure: CloudRiskExposure, model: CloudRiskExposureModel | None = None
) -> CloudRiskExposureModel:
    target = model or CloudRiskExposureModel(id=exposure.id.value)
    target.id = exposure.id.value
    target.organization_id = str(exposure.organization_id)
    target.cloud_asset_id = exposure.cloud_asset_id.value
    target.public_accessibility = exposure.public_accessibility
    target.internet_exposure = exposure.internet_exposure
    target.encryption_at_rest = exposure.encryption_at_rest
    target.privilege_level = exposure.privilege_level
    target.lateral_movement_potential = exposure.lateral_movement_potential
    target.exposure_score = exposure.exposure_score
    target.details = dict(exposure.details)
    target.created_at = exposure.created_at
    target.updated_at = exposure.updated_at
    target.row_version = exposure.row_version
    return target


def exposure_from_model(model: CloudRiskExposureModel) -> CloudRiskExposure:
    return CloudRiskExposure(
        id=CloudRiskExposureId(model.id),
        organization_id=OrganizationId(model.organization_id),
        cloud_asset_id=CloudAssetId(model.cloud_asset_id),
        public_accessibility=bool(model.public_accessibility),
        internet_exposure=bool(model.internet_exposure),
        encryption_at_rest=bool(model.encryption_at_rest),
        privilege_level=model.privilege_level,
        lateral_movement_potential=model.lateral_movement_potential,
        exposure_score=float(model.exposure_score),
        details=dict(model.details or {}),
        created_at=model.created_at,
        updated_at=model.updated_at,
        row_version=model.row_version,
    )


def assessment_to_model(
    assessment: CloudRiskAssessment, model: CloudRiskAssessmentModel | None = None
) -> CloudRiskAssessmentModel:
    target = model or CloudRiskAssessmentModel(id=assessment.id.value)
    target.id = assessment.id.value
    target.organization_id = str(assessment.organization_id)
    target.scope = assessment.scope
    target.target_id = assessment.target_id
    target.status = assessment.status
    target.assets_evaluated = assessment.assets_evaluated
    target.risks_created = assessment.risks_created
    target.risks_updated = assessment.risks_updated
    target.calculation_version = assessment.calculation_version
    target.diagnostics = dict(assessment.diagnostics)
    target.started_at = assessment.started_at
    target.completed_at = assessment.completed_at
    target.created_at = assessment.created_at
    target.row_version = assessment.row_version
    return target


def assessment_from_model(model: CloudRiskAssessmentModel) -> CloudRiskAssessment:
    return CloudRiskAssessment(
        id=CloudRiskAssessmentId(model.id),
        organization_id=OrganizationId(model.organization_id),
        scope=model.scope,
        target_id=model.target_id,
        status=model.status,
        assets_evaluated=model.assets_evaluated,
        risks_created=model.risks_created,
        risks_updated=model.risks_updated,
        calculation_version=model.calculation_version,
        diagnostics=dict(model.diagnostics or {}),
        started_at=model.started_at,
        completed_at=model.completed_at,
        created_at=model.created_at,
        row_version=model.row_version,
    )
