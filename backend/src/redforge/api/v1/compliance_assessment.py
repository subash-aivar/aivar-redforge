"""Organization Assessment API — M24 Phase 2.

Org-scoped routes (require Permission.COMPLIANCE_READ / COMPLIANCE_MANAGE):
  Profiles, AssessmentPeriods, ControlAssessments, confirmed evidence links.

SYSTEM INVARIANT: the strings "CERTIFIED" and "COMPLIANT" are NEVER
returned as ControlStatus values.
"""

from __future__ import annotations

from datetime import datetime  # noqa: TC003
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_organization_assessment_service
from redforge.api.security import TenantContext, require_permission
from redforge.domain.compliance.exceptions import (
    AssessmentPeriodCloseBlockedError,
    AssessmentPeriodNotFoundError,
    AssessmentPeriodNotOpenError,
    ComplianceDomainError,
    ControlAssessmentNotFoundError,
    ControlRequirementNotFoundError,
    DuplicateActiveProfileFrameworkError,
    DuplicateControlAssessmentError,
    DuplicateEvidenceLinkError,
    EvidenceReferenceNotFoundError,
    FrameworkAlreadyPublishedError,
    FrameworkNotFoundError,
    FrameworkNotInProfileError,
    InvalidControlStatusTransitionError,
    ProfileNotActiveError,
    ProfileNotFoundError,
)
from redforge.domain.compliance.value_objects import FrameworkKey
from redforge.domain.identity.value_objects import Permission
from redforge.shared.identifiers import EntityId

router = APIRouter(tags=["compliance-assessment"])


class ConfirmedEvidenceLinkSchema(BaseModel):
    evidence_id: str
    confirmed_by: str
    confirmed_at: datetime
    rationale: str


class ComplianceProfileSchema(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str
    framework_keys: list[str]
    status: str
    created_by: str
    created_at: datetime
    updated_at: datetime


class AssessmentPeriodSchema(BaseModel):
    id: str
    organization_id: str
    profile_id: str
    name: str
    framework_key: str
    period_start: datetime
    period_end: datetime
    status: str
    created_by: str
    created_at: datetime
    updated_at: datetime


class ControlAssessmentSchema(BaseModel):
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


class CreateProfileBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    framework_keys: list[str] = Field(default_factory=list)


class UpdateProfileFrameworksBody(BaseModel):
    framework_keys: list[str] = Field(default_factory=list)


class CreatePeriodBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    framework_key: str
    period_start: datetime
    period_end: datetime


class CreateAssessmentBody(BaseModel):
    requirement_id: str
    notes: str = Field(default="", max_length=4000)


class ConfirmEvidenceLinkBody(BaseModel):
    evidence_id: str = Field(..., min_length=1, max_length=26)
    rationale: str = Field(default="", max_length=2000)


def _parse_framework_key(raw: str) -> FrameworkKey:
    try:
        return FrameworkKey(raw)
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail=f"Unknown framework key: '{raw}'"
        ) from exc


def _parse_entity_id(raw: str, label: str) -> EntityId:
    try:
        return EntityId.from_string(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {label}") from exc


def _profile_to_schema(profile: Any) -> ComplianceProfileSchema:
    return ComplianceProfileSchema(
        id=str(profile.id),
        organization_id=profile.organization_id,
        name=profile.name,
        description=profile.description,
        framework_keys=[k.value for k in profile.framework_keys],
        status=profile.status.value,
        created_by=profile.created_by,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


def _period_to_schema(period: Any) -> AssessmentPeriodSchema:
    return AssessmentPeriodSchema(
        id=str(period.id),
        organization_id=period.organization_id,
        profile_id=str(period.profile_id),
        name=period.name,
        framework_key=period.framework_key.value,
        period_start=period.period_start,
        period_end=period.period_end,
        status=period.status.value,
        created_by=period.created_by,
        created_at=period.created_at,
        updated_at=period.updated_at,
    )


def _assessment_to_schema(assessment: Any) -> ControlAssessmentSchema:
    status_value = assessment.status.value
    if status_value.upper() in {"CERTIFIED", "COMPLIANT"}:
        raise HTTPException(
            status_code=500,
            detail="Invariant violation: forbidden compliance label in status",
        )
    return ControlAssessmentSchema(
        id=str(assessment.id),
        organization_id=assessment.organization_id,
        profile_id=str(assessment.profile_id),
        period_id=str(assessment.period_id),
        requirement_id=str(assessment.requirement_id),
        framework_key=assessment.framework_key.value,
        status=status_value,
        evidence_links=[
            ConfirmedEvidenceLinkSchema(
                evidence_id=link.evidence_id,
                confirmed_by=link.confirmed_by,
                confirmed_at=link.confirmed_at,
                rationale=link.rationale,
            )
            for link in assessment.evidence_links
        ],
        notes=assessment.notes,
        created_by=assessment.created_by,
        created_at=assessment.created_at,
        updated_at=assessment.updated_at,
    )


def _map_assessment_error(exc: ComplianceDomainError) -> HTTPException:
    if isinstance(
        exc,
        (
            ProfileNotFoundError,
            AssessmentPeriodNotFoundError,
            ControlAssessmentNotFoundError,
            EvidenceReferenceNotFoundError,
            FrameworkNotFoundError,
            ControlRequirementNotFoundError,
        ),
    ):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(
        exc,
        (
            DuplicateControlAssessmentError,
            DuplicateEvidenceLinkError,
            DuplicateActiveProfileFrameworkError,
            InvalidControlStatusTransitionError,
            ProfileNotActiveError,
            AssessmentPeriodNotOpenError,
            AssessmentPeriodCloseBlockedError,
            FrameworkNotInProfileError,
            FrameworkAlreadyPublishedError,
        ),
    ):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=422, detail=str(exc))


@router.post("/compliance/profiles", response_model=ComplianceProfileSchema)
async def create_profile(
    body: CreateProfileBody,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_organization_assessment_service),
) -> ComplianceProfileSchema:
    from redforge.application.compliance.assessment_dtos import CreateProfileCommand

    keys = tuple(_parse_framework_key(k) for k in body.framework_keys)
    try:
        profile = await svc.create_profile(
            CreateProfileCommand(
                organization_id=tenant.organization_id,
                name=body.name,
                description=body.description,
                framework_keys=keys,
                created_by=tenant.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _profile_to_schema(profile)


@router.get("/compliance/profiles", response_model=list[ComplianceProfileSchema])
async def list_profiles(
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_organization_assessment_service),
) -> list[ComplianceProfileSchema]:
    profiles = await svc.list_profiles(tenant.organization_id)
    return [_profile_to_schema(p) for p in profiles]


@router.get(
    "/compliance/profiles/{profile_id}", response_model=ComplianceProfileSchema
)
async def get_profile(
    profile_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_organization_assessment_service),
) -> ComplianceProfileSchema:
    pid = _parse_entity_id(profile_id, "profile ID")
    try:
        profile = await svc.get_profile(tenant.organization_id, pid)
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _profile_to_schema(profile)


@router.put(
    "/compliance/profiles/{profile_id}/frameworks",
    response_model=ComplianceProfileSchema,
)
async def update_profile_frameworks(
    profile_id: str,
    body: UpdateProfileFrameworksBody,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_organization_assessment_service),
) -> ComplianceProfileSchema:
    from redforge.application.compliance.assessment_dtos import (
        UpdateProfileFrameworksCommand,
    )

    pid = _parse_entity_id(profile_id, "profile ID")
    keys = tuple(_parse_framework_key(k) for k in body.framework_keys)
    try:
        profile = await svc.update_profile_frameworks(
            UpdateProfileFrameworksCommand(
                organization_id=tenant.organization_id,
                profile_id=pid,
                framework_keys=keys,
                actor_id=tenant.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _profile_to_schema(profile)


@router.post(
    "/compliance/profiles/{profile_id}/activate",
    response_model=ComplianceProfileSchema,
)
async def activate_profile(
    profile_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_organization_assessment_service),
) -> ComplianceProfileSchema:
    from redforge.application.compliance.assessment_dtos import ActivateProfileCommand

    pid = _parse_entity_id(profile_id, "profile ID")
    try:
        profile = await svc.activate_profile(
            ActivateProfileCommand(
                organization_id=tenant.organization_id,
                profile_id=pid,
                activated_by=tenant.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _profile_to_schema(profile)


@router.post(
    "/compliance/profiles/{profile_id}/periods",
    response_model=AssessmentPeriodSchema,
)
async def create_period(
    profile_id: str,
    body: CreatePeriodBody,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_organization_assessment_service),
) -> AssessmentPeriodSchema:
    from redforge.application.compliance.assessment_dtos import CreatePeriodCommand

    pid = _parse_entity_id(profile_id, "profile ID")
    try:
        period = await svc.create_period(
            CreatePeriodCommand(
                organization_id=tenant.organization_id,
                profile_id=pid,
                name=body.name,
                framework_key=_parse_framework_key(body.framework_key),
                period_start=body.period_start,
                period_end=body.period_end,
                created_by=tenant.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _period_to_schema(period)


@router.get(
    "/compliance/profiles/{profile_id}/periods",
    response_model=list[AssessmentPeriodSchema],
)
async def list_periods_for_profile(
    profile_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_organization_assessment_service),
) -> list[AssessmentPeriodSchema]:
    pid = _parse_entity_id(profile_id, "profile ID")
    periods = await svc.list_periods(tenant.organization_id, profile_id=pid)
    return [_period_to_schema(p) for p in periods]


@router.get("/compliance/periods/{period_id}", response_model=AssessmentPeriodSchema)
async def get_period(
    period_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_organization_assessment_service),
) -> AssessmentPeriodSchema:
    pid = _parse_entity_id(period_id, "period ID")
    try:
        period = await svc.get_period(tenant.organization_id, pid)
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _period_to_schema(period)


@router.post(
    "/compliance/periods/{period_id}/open", response_model=AssessmentPeriodSchema
)
async def open_period(
    period_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_organization_assessment_service),
) -> AssessmentPeriodSchema:
    from redforge.application.compliance.assessment_dtos import OpenPeriodCommand

    pid = _parse_entity_id(period_id, "period ID")
    try:
        period = await svc.open_period(
            OpenPeriodCommand(
                organization_id=tenant.organization_id,
                period_id=pid,
                opened_by=tenant.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _period_to_schema(period)


@router.post(
    "/compliance/periods/{period_id}/close", response_model=AssessmentPeriodSchema
)
async def close_period(
    period_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_organization_assessment_service),
) -> AssessmentPeriodSchema:
    from redforge.application.compliance.assessment_dtos import ClosePeriodCommand

    pid = _parse_entity_id(period_id, "period ID")
    try:
        period = await svc.close_period(
            ClosePeriodCommand(
                organization_id=tenant.organization_id,
                period_id=pid,
                closed_by=tenant.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _period_to_schema(period)


@router.post(
    "/compliance/periods/{period_id}/assessments",
    response_model=ControlAssessmentSchema,
)
async def create_assessment(
    period_id: str,
    body: CreateAssessmentBody,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_organization_assessment_service),
) -> ControlAssessmentSchema:
    from redforge.application.compliance.assessment_dtos import CreateAssessmentCommand

    pid = _parse_entity_id(period_id, "period ID")
    rid = _parse_entity_id(body.requirement_id, "requirement ID")
    try:
        assessment = await svc.create_assessment(
            CreateAssessmentCommand(
                organization_id=tenant.organization_id,
                period_id=pid,
                requirement_id=rid,
                created_by=tenant.user_id,
                notes=body.notes,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _assessment_to_schema(assessment)


@router.get(
    "/compliance/periods/{period_id}/assessments",
    response_model=list[ControlAssessmentSchema],
)
async def list_assessments(
    period_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_organization_assessment_service),
) -> list[ControlAssessmentSchema]:
    pid = _parse_entity_id(period_id, "period ID")
    items = await svc.list_assessments(tenant.organization_id, period_id=pid)
    return [_assessment_to_schema(a) for a in items]


@router.get(
    "/compliance/assessments/{assessment_id}",
    response_model=ControlAssessmentSchema,
)
async def get_assessment(
    assessment_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_READ)),
    svc: Any = Depends(get_organization_assessment_service),
) -> ControlAssessmentSchema:
    aid = _parse_entity_id(assessment_id, "assessment ID")
    try:
        assessment = await svc.get_assessment(tenant.organization_id, aid)
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _assessment_to_schema(assessment)


@router.post(
    "/compliance/assessments/{assessment_id}/evidence-links",
    response_model=ControlAssessmentSchema,
)
async def confirm_evidence_link(
    assessment_id: str,
    body: ConfirmEvidenceLinkBody,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_organization_assessment_service),
) -> ControlAssessmentSchema:
    from redforge.application.compliance.assessment_dtos import ConfirmEvidenceLinkCommand

    aid = _parse_entity_id(assessment_id, "assessment ID")
    try:
        assessment = await svc.confirm_evidence_link(
            ConfirmEvidenceLinkCommand(
                organization_id=tenant.organization_id,
                assessment_id=aid,
                evidence_id=body.evidence_id,
                confirmed_by=tenant.user_id,
                rationale=body.rationale,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _assessment_to_schema(assessment)


@router.post(
    "/compliance/assessments/{assessment_id}/begin-collection",
    response_model=ControlAssessmentSchema,
)
async def begin_collection(
    assessment_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_organization_assessment_service),
) -> ControlAssessmentSchema:
    from redforge.application.compliance.assessment_dtos import TransitionAssessmentCommand

    aid = _parse_entity_id(assessment_id, "assessment ID")
    try:
        assessment = await svc.begin_evidence_collection(
            TransitionAssessmentCommand(
                organization_id=tenant.organization_id,
                assessment_id=aid,
                actor_id=tenant.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _assessment_to_schema(assessment)


@router.post(
    "/compliance/assessments/{assessment_id}/submit-for-confirmation",
    response_model=ControlAssessmentSchema,
)
async def submit_for_confirmation(
    assessment_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_organization_assessment_service),
) -> ControlAssessmentSchema:
    from redforge.application.compliance.assessment_dtos import TransitionAssessmentCommand

    aid = _parse_entity_id(assessment_id, "assessment ID")
    try:
        assessment = await svc.submit_for_confirmation(
            TransitionAssessmentCommand(
                organization_id=tenant.organization_id,
                assessment_id=aid,
                actor_id=tenant.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _assessment_to_schema(assessment)


@router.post(
    "/compliance/assessments/{assessment_id}/technically-validate",
    response_model=ControlAssessmentSchema,
)
async def technically_validate(
    assessment_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.COMPLIANCE_MANAGE)),
    svc: Any = Depends(get_organization_assessment_service),
) -> ControlAssessmentSchema:
    from redforge.application.compliance.assessment_dtos import TransitionAssessmentCommand

    aid = _parse_entity_id(assessment_id, "assessment ID")
    try:
        assessment = await svc.technically_validate(
            TransitionAssessmentCommand(
                organization_id=tenant.organization_id,
                assessment_id=aid,
                actor_id=tenant.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _map_assessment_error(exc) from exc
    return _assessment_to_schema(assessment)
