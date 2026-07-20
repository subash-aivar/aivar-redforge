"""Compliance Operations Console read APIs — M24 Phase 4 (enterprise scale).

Additive endpoints under /api/v1/compliance/console/*.
Existing Phase 1-3 APIs are unchanged. Permission: COMPLIANCE_READ.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from redforge.api.dependencies import get_compliance_console_query_service
from redforge.api.security import TenantContext, require_permission
from redforge.api.v1.compliance_recommendations import (
    EvidenceRecommendationSchema,
    _rec_to_schema,
)
from redforge.domain.identity.value_objects import Permission

router = APIRouter(tags=["compliance-console"])

SortDir = Literal["asc", "desc"]


# ── Schemas ──────────────────────────────────────────────────────────────────


class ConfirmedEvidenceLinkSchema(BaseModel):
    evidence_id: str
    confirmed_by: str
    confirmed_at: datetime
    rationale: str = ""


class ConsoleAssessmentSchema(BaseModel):
    id: str
    organization_id: str
    profile_id: str
    period_id: str
    requirement_id: str
    framework_key: str
    status: str
    evidence_links: list[ConfirmedEvidenceLinkSchema]
    notes: str
    created_by: str
    created_at: datetime
    updated_at: datetime


class PaginatedAssessmentsSchema(BaseModel):
    items: list[ConsoleAssessmentSchema]
    total: int
    limit: int
    offset: int


class PaginatedRecommendationsSchema(BaseModel):
    items: list[EvidenceRecommendationSchema]
    total: int
    limit: int
    offset: int


class ConsoleEvidenceRowSchema(BaseModel):
    id: str
    category: str
    source_kind: str
    entity_id: str
    assessment_id: str | None
    recommendation_id: str | None
    status: str
    confidence: str | None
    updated_at: datetime | None
    rationale: str = ""


class PaginatedEvidenceSchema(BaseModel):
    items: list[ConsoleEvidenceRowSchema]
    total: int
    limit: int
    offset: int


class ConsoleTimelineEventSchema(BaseModel):
    id: str
    at: datetime | None
    kind: str
    title: str
    detail: str
    href: str | None = None


class PaginatedTimelineSchema(BaseModel):
    items: list[ConsoleTimelineEventSchema]
    total: int
    limit: int
    offset: int


class FrameworkProgressSchema(BaseModel):
    framework_key: str
    total: int
    validated: int
    coverage_pct: int


class OpenPeriodSummarySchema(BaseModel):
    id: str
    name: str
    framework_key: str
    period_start: datetime
    period_end: datetime
    status: str


class RecentlyValidatedSchema(BaseModel):
    id: str
    framework_key: str
    requirement_id: str
    status: str
    evidence_count: int
    updated_at: datetime


class RecommendationCountsSchema(BaseModel):
    recommended: int = 0
    accepted: int = 0
    linked: int = 0
    rejected: int = 0
    total: int = 0


class ConsoleOverviewSchema(BaseModel):
    profiles: int
    open_periods: int
    assessments_total: int
    validated_count: int
    posture_score: int
    posture_band: str
    status_counts: dict[str, int]
    evidence_link_count: int
    assessments_with_evidence: int
    recommendation_counts: RecommendationCountsSchema
    acceptance_pct: int = 0
    framework_progress: list[FrameworkProgressSchema]
    open_period_summaries: list[OpenPeriodSummarySchema]
    recently_validated: list[RecentlyValidatedSchema]


class ChartPointSchema(BaseModel):
    label: str
    value: int


class ConsoleAnalyticsSchema(BaseModel):
    posture_score: int
    posture_band: str
    validated_count: int
    assessments_total: int
    evidence_link_count: int
    acceptance_pct: int
    status_distribution: list[ChartPointSchema]
    framework_coverage: list[ChartPointSchema]
    recommendation_acceptance_mix: list[ChartPointSchema]
    evidence_growth: list[ChartPointSchema]
    validation_velocity: list[ChartPointSchema]
    compliance_trend: list[ChartPointSchema]
    recommendation_counts: RecommendationCountsSchema


def _clamp_limit(limit: int, *, default: int = 50, max_limit: int = 200) -> int:
    if limit < 1:
        return default
    return min(limit, max_limit)


def _assessment_to_schema(row: dict[str, Any]) -> ConsoleAssessmentSchema:
    links = []
    for link in row.get("evidence_links") or []:
        if not isinstance(link, dict):
            continue
        confirmed_at = link.get("confirmed_at")
        if confirmed_at is None:
            continue
        links.append(
            ConfirmedEvidenceLinkSchema(
                evidence_id=str(link.get("evidence_id", "")),
                confirmed_by=str(link.get("confirmed_by", "")),
                confirmed_at=confirmed_at,
                rationale=str(link.get("rationale", "")),
            )
        )
    return ConsoleAssessmentSchema(
        id=row["id"],
        organization_id=row["organization_id"],
        profile_id=row["profile_id"],
        period_id=row["period_id"],
        requirement_id=row["requirement_id"],
        framework_key=row["framework_key"],
        status=row["status"],
        evidence_links=links,
        notes=row.get("notes") or "",
        created_by=row["created_by"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get(
    "/compliance/console/overview",
    response_model=ConsoleOverviewSchema,
)
async def get_console_overview(
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_compliance_console_query_service),
) -> ConsoleOverviewSchema:
    data = await svc.overview(tenant.organization_id)
    return ConsoleOverviewSchema.model_validate(data)


@router.get(
    "/compliance/console/assessments",
    response_model=PaginatedAssessmentsSchema,
)
async def list_console_assessments(
    period_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    framework_key: str | None = Query(default=None),
    search: str | None = Query(default=None),
    sort: str = Query(default="updated_at"),
    sort_dir: SortDir = Query(default="desc"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_compliance_console_query_service),
) -> PaginatedAssessmentsSchema:
    lim = _clamp_limit(limit)
    items, total = await svc.list_assessments(
        tenant.organization_id,
        period_id=period_id,
        status=status,
        framework_key=framework_key,
        search=search,
        sort=sort,
        sort_dir=sort_dir,
        limit=lim,
        offset=offset,
    )
    return PaginatedAssessmentsSchema(
        items=[_assessment_to_schema(i) for i in items],
        total=total,
        limit=lim,
        offset=offset,
    )


@router.get(
    "/compliance/console/recommendations",
    response_model=PaginatedRecommendationsSchema,
)
async def list_console_recommendations(
    status: str | None = Query(default=None),
    confidence: str | None = Query(default=None),
    framework_key: str | None = Query(default=None),
    assessment_id: str | None = Query(default=None),
    period_id: str | None = Query(default=None),
    search: str | None = Query(default=None),
    sort: str = Query(default="updated_at"),
    sort_dir: SortDir = Query(default="desc"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_compliance_console_query_service),
) -> PaginatedRecommendationsSchema:
    lim = _clamp_limit(limit)
    items, total = await svc.list_recommendations(
        tenant.organization_id,
        status=status,
        confidence=confidence,
        framework_key=framework_key,
        assessment_id=assessment_id,
        period_id=period_id,
        search=search,
        sort=sort,
        sort_dir=sort_dir,
        limit=lim,
        offset=offset,
    )
    return PaginatedRecommendationsSchema(
        items=[_rec_to_schema(i) for i in items],
        total=total,
        limit=lim,
        offset=offset,
    )


@router.get(
    "/compliance/console/evidence",
    response_model=PaginatedEvidenceSchema,
)
async def list_console_evidence(
    category: str | None = Query(default=None),
    search: str | None = Query(default=None),
    sort: str = Query(default="updated_at"),
    sort_dir: SortDir = Query(default="desc"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_compliance_console_query_service),
) -> PaginatedEvidenceSchema:
    lim = _clamp_limit(limit)
    items, total = await svc.list_evidence(
        tenant.organization_id,
        category=category,
        search=search,
        sort=sort,
        sort_dir=sort_dir,
        limit=lim,
        offset=offset,
    )
    return PaginatedEvidenceSchema(
        items=[ConsoleEvidenceRowSchema.model_validate(i) for i in items],
        total=total,
        limit=lim,
        offset=offset,
    )


@router.get(
    "/compliance/console/timeline",
    response_model=PaginatedTimelineSchema,
)
async def list_console_timeline(
    kind: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_compliance_console_query_service),
) -> PaginatedTimelineSchema:
    lim = _clamp_limit(limit)
    items, total = await svc.list_timeline(
        tenant.organization_id,
        kind=kind,
        search=search,
        limit=lim,
        offset=offset,
    )
    return PaginatedTimelineSchema(
        items=[ConsoleTimelineEventSchema.model_validate(i) for i in items],
        total=total,
        limit=lim,
        offset=offset,
    )


@router.get(
    "/compliance/console/analytics",
    response_model=ConsoleAnalyticsSchema,
)
async def get_console_analytics(
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_compliance_console_query_service),
) -> ConsoleAnalyticsSchema:
    data = await svc.analytics(tenant.organization_id)
    return ConsoleAnalyticsSchema.model_validate(data)
