"""Evidence Recommendation API — M24 Phase 3.

Org-scoped routes (COMPLIANCE_READ / COMPLIANCE_MANAGE):
  Generate, list, accept, reject, link, history, statistics.

Recommendations assist human reviewers. They NEVER certify compliance
and NEVER create evidence links without explicit accept → link.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_evidence_recommendation_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.compliance.recommendation_dtos import (
    AcceptRecommendationCommand,
    GenerateRecommendationsCommand,
    LinkRecommendationCommand,
    RejectRecommendationCommand,
)
from redforge.domain.compliance.exceptions import (
    AssessmentPeriodNotFoundError,
    AssessmentPeriodNotOpenError,
    ComplianceDomainError,
    ControlAssessmentNotFoundError,
    DuplicateEvidenceLinkError,
    DuplicateRecommendationError,
    EvidenceReferenceNotFoundError,
    InvalidRecommendationTransitionError,
    RecommendationNotAcceptedError,
    RecommendationNotFoundError,
    RecommendationNotLinkableError,
)
from redforge.domain.identity.value_objects import Permission
from redforge.shared.identifiers import EntityId

router = APIRouter(tags=["compliance-recommendations"])


class EvidenceReferenceSchema(BaseModel):
    source_kind: str
    source_entity_id: str


class EvidenceCandidateSchema(BaseModel):
    reference: EvidenceReferenceSchema
    raw_score: float
    rationale: str
    signals: list[str]


class RecommendationDecisionSchema(BaseModel):
    decided_by: str
    decided_at: datetime
    rationale: str


class EvidenceRecommendationSchema(BaseModel):
    id: str
    organization_id: str
    batch_id: str
    assessment_id: str
    period_id: str
    requirement_id: str
    framework_key: str
    primary_reference: EvidenceReferenceSchema
    candidates: list[EvidenceCandidateSchema]
    confidence: str
    score: float
    rationale: str
    status: str
    dedup_key: str
    decision: RecommendationDecisionSchema | None
    linked_evidence_id: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class RecommendationBatchSchema(BaseModel):
    id: str
    organization_id: str
    period_id: str
    assessment_id: str | None
    generation_fingerprint: str
    recommendation_ids: list[str]
    created_count: int
    updated_count: int
    skipped_duplicate_count: int
    generated_by: str
    created_at: datetime


class RecommendationListSchema(BaseModel):
    items: list[EvidenceRecommendationSchema]
    total: int


class RecommendationStatisticsSchema(BaseModel):
    recommended: int = 0
    accepted: int = 0
    linked: int = 0
    rejected: int = 0
    total: int = 0


class GenerateRecommendationsBody(BaseModel):
    assessment_id: str | None = None


class DecisionBody(BaseModel):
    rationale: str = Field(default="", max_length=2000)


def _parse_entity_id(raw: str, label: str) -> EntityId:
    try:
        return EntityId.from_string(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {label}") from exc


def _map_error(exc: ComplianceDomainError) -> HTTPException:
    if isinstance(
        exc,
        (
            RecommendationNotFoundError,
            AssessmentPeriodNotFoundError,
            ControlAssessmentNotFoundError,
            EvidenceReferenceNotFoundError,
        ),
    ):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(
        exc,
        (
            InvalidRecommendationTransitionError,
            RecommendationNotAcceptedError,
            RecommendationNotLinkableError,
            AssessmentPeriodNotOpenError,
            DuplicateRecommendationError,
            DuplicateEvidenceLinkError,
        ),
    ):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


def _rec_to_schema(rec: Any) -> EvidenceRecommendationSchema:
    decision = None
    if rec.decision is not None:
        decision = RecommendationDecisionSchema(
            decided_by=rec.decision.decided_by,
            decided_at=rec.decision.decided_at,
            rationale=rec.decision.rationale,
        )
    return EvidenceRecommendationSchema(
        id=str(rec.id),
        organization_id=rec.organization_id,
        batch_id=str(rec.batch_id),
        assessment_id=str(rec.assessment_id),
        period_id=str(rec.period_id),
        requirement_id=str(rec.requirement_id),
        framework_key=rec.framework_key,
        primary_reference=EvidenceReferenceSchema(
            source_kind=rec.primary_reference.source_kind.value,
            source_entity_id=rec.primary_reference.source_entity_id,
        ),
        candidates=[
            EvidenceCandidateSchema(
                reference=EvidenceReferenceSchema(
                    source_kind=c.reference.source_kind.value,
                    source_entity_id=c.reference.source_entity_id,
                ),
                raw_score=c.raw_score,
                rationale=c.rationale,
                signals=list(c.signals),
            )
            for c in rec.candidates
        ],
        confidence=rec.confidence.value,
        score=rec.score,
        rationale=rec.rationale,
        status=rec.status.value,
        dedup_key=rec.dedup_key,
        decision=decision,
        linked_evidence_id=rec.linked_evidence_id,
        created_by=rec.created_by,
        created_at=rec.created_at,
        updated_at=rec.updated_at,
    )


def _batch_to_schema(batch: Any) -> RecommendationBatchSchema:
    return RecommendationBatchSchema(
        id=str(batch.id),
        organization_id=batch.organization_id,
        period_id=str(batch.period_id),
        assessment_id=str(batch.assessment_id) if batch.assessment_id else None,
        generation_fingerprint=batch.generation_fingerprint,
        recommendation_ids=[str(i) for i in batch.recommendation_ids],
        created_count=batch.created_count,
        updated_count=batch.updated_count,
        skipped_duplicate_count=batch.skipped_duplicate_count,
        generated_by=batch.generated_by,
        created_at=batch.created_at,
    )


@router.post(
    "/compliance/periods/{period_id}/recommendations/generate",
    response_model=RecommendationBatchSchema,
    status_code=201,
)
async def generate_recommendations(
    period_id: str,
    body: GenerateRecommendationsBody,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_evidence_recommendation_service),
) -> RecommendationBatchSchema:
    try:
        batch = await svc.generate(
            GenerateRecommendationsCommand(
                organization_id=tenant.organization_id,
                period_id=_parse_entity_id(period_id, "period_id"),
                assessment_id=(
                    _parse_entity_id(body.assessment_id, "assessment_id")
                    if body.assessment_id
                    else None
                ),
                generated_by=tenant.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_error(exc) from exc
    return _batch_to_schema(batch)


@router.get(
    "/compliance/periods/{period_id}/recommendations",
    response_model=RecommendationListSchema,
)
async def list_period_recommendations(
    period_id: str,
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_evidence_recommendation_service),
) -> RecommendationListSchema:
    items, total = await svc.list_recommendations(
        tenant.organization_id,
        period_id=_parse_entity_id(period_id, "period_id"),
        status=status,
        limit=limit,
        offset=offset,
    )
    return RecommendationListSchema(
        items=[_rec_to_schema(i) for i in items], total=total
    )


@router.get(
    "/compliance/assessments/{assessment_id}/recommendations",
    response_model=RecommendationListSchema,
)
async def list_assessment_recommendations(
    assessment_id: str,
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_evidence_recommendation_service),
) -> RecommendationListSchema:
    items, total = await svc.list_recommendations(
        tenant.organization_id,
        assessment_id=_parse_entity_id(assessment_id, "assessment_id"),
        status=status,
        limit=limit,
        offset=offset,
    )
    return RecommendationListSchema(
        items=[_rec_to_schema(i) for i in items], total=total
    )


@router.get(
    "/compliance/recommendations/history",
    response_model=RecommendationListSchema,
)
async def recommendation_history(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_evidence_recommendation_service),
) -> RecommendationListSchema:
    items, total = await svc.history(
        tenant.organization_id, limit=limit, offset=offset
    )
    return RecommendationListSchema(
        items=[_rec_to_schema(i) for i in items], total=total
    )


@router.get(
    "/compliance/recommendations/statistics",
    response_model=RecommendationStatisticsSchema,
)
async def recommendation_statistics(
    period_id: str | None = Query(default=None),
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_evidence_recommendation_service),
) -> RecommendationStatisticsSchema:
    stats = await svc.statistics(
        tenant.organization_id,
        period_id=_parse_entity_id(period_id, "period_id") if period_id else None,
    )
    return RecommendationStatisticsSchema(
        recommended=stats.get("recommended", 0),
        accepted=stats.get("accepted", 0),
        linked=stats.get("linked", 0),
        rejected=stats.get("rejected", 0),
        total=stats.get("total", 0),
    )


@router.get(
    "/compliance/recommendations/{recommendation_id}",
    response_model=EvidenceRecommendationSchema,
)
async def get_recommendation(
    recommendation_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_evidence_recommendation_service),
) -> EvidenceRecommendationSchema:
    try:
        rec = await svc.get_recommendation(
            tenant.organization_id,
            _parse_entity_id(recommendation_id, "recommendation_id"),
        )
    except ComplianceDomainError as exc:
        raise _map_error(exc) from exc
    return _rec_to_schema(rec)


@router.post(
    "/compliance/recommendations/{recommendation_id}/accept",
    response_model=EvidenceRecommendationSchema,
)
async def accept_recommendation(
    recommendation_id: str,
    body: DecisionBody,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_evidence_recommendation_service),
) -> EvidenceRecommendationSchema:
    try:
        rec = await svc.accept(
            AcceptRecommendationCommand(
                organization_id=tenant.organization_id,
                recommendation_id=_parse_entity_id(
                    recommendation_id, "recommendation_id"
                ),
                accepted_by=tenant.user_id,
                rationale=body.rationale,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_error(exc) from exc
    return _rec_to_schema(rec)


@router.post(
    "/compliance/recommendations/{recommendation_id}/reject",
    response_model=EvidenceRecommendationSchema,
)
async def reject_recommendation(
    recommendation_id: str,
    body: DecisionBody,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_evidence_recommendation_service),
) -> EvidenceRecommendationSchema:
    try:
        rec = await svc.reject(
            RejectRecommendationCommand(
                organization_id=tenant.organization_id,
                recommendation_id=_parse_entity_id(
                    recommendation_id, "recommendation_id"
                ),
                rejected_by=tenant.user_id,
                rationale=body.rationale,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_error(exc) from exc
    return _rec_to_schema(rec)


@router.post(
    "/compliance/recommendations/{recommendation_id}/link",
    response_model=EvidenceRecommendationSchema,
)
async def link_recommendation(
    recommendation_id: str,
    body: DecisionBody,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_evidence_recommendation_service),
) -> EvidenceRecommendationSchema:
    try:
        rec = await svc.link_accepted(
            LinkRecommendationCommand(
                organization_id=tenant.organization_id,
                recommendation_id=_parse_entity_id(
                    recommendation_id, "recommendation_id"
                ),
                linked_by=tenant.user_id,
                rationale=body.rationale,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_error(exc) from exc
    return _rec_to_schema(rec)
