"""Compliance Control Catalog API — M24 Phase 1.

Platform admin routes (require PlatformPermission):
  GET  /platform/compliance/frameworks              — list all frameworks
  GET  /platform/compliance/frameworks/{key}        — framework detail
  POST /platform/compliance/frameworks/{key}/publish  — publish DRAFT
  POST /platform/compliance/frameworks/{key}/retire   — retire PUBLISHED
  GET  /platform/compliance/requirements/{key}      — list requirements
  GET  /platform/compliance/requirements/{key}/{id} — requirement detail
  GET  /platform/compliance/mappings                — list mappings
  POST /platform/compliance/mappings                — define mapping
  DELETE /platform/compliance/mappings/{id}         — revoke mapping
  POST /platform/compliance/seed                    — trigger catalog seed

Org read-only routes (require Permission):
  GET  /compliance/frameworks            — published frameworks only
  GET  /compliance/frameworks/{key}      — published framework detail
  GET  /compliance/requirements/{key}    — requirements for a framework
  GET  /compliance/requirements/{key}/{id} — single requirement
  GET  /compliance/mappings              — active mappings

SYSTEM INVARIANT: the strings "CERTIFIED" and "COMPLIANT" are NEVER
returned by any endpoint in this file or any value in any enum.
"""

from __future__ import annotations

from datetime import datetime  # noqa: TC003
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from redforge.api.dependencies import (
    get_catalog_publishing_service,
    get_catalog_query_service,
    get_mapping_service,
)
from redforge.api.security import (
    PlatformContext,
    TenantContext,
    require_permission,
    require_platform_permission,
)
from redforge.application.compliance.catalog_service import CatalogPublishingService  # noqa: TC001
from redforge.application.compliance.mapping_service import (  # noqa: TC001
    CatalogQueryService,
    MappingService,
)
from redforge.domain.compliance.exceptions import (
    ComplianceDomainError,
    ControlMappingNotFoundError,
    ControlRequirementNotFoundError,
    DuplicateControlMappingError,
    FrameworkAlreadyPublishedError,
    FrameworkNotFoundError,
    FrameworkRetiredError,
)
from redforge.domain.compliance.value_objects import FrameworkKey, FrameworkStatus
from redforge.domain.identity.value_objects import Permission
from redforge.domain.platform_identity.value_objects import PlatformPermission
from redforge.shared.identifiers import EntityId

router = APIRouter()


# ─── Response schemas ─────────────────────────────────────────────────────────


class FrameworkMetadataSchema(BaseModel):
    name: str
    version: str
    issuing_body: str
    description: str
    effective_date: str
    tags: list[str]
    external_url: str


class FrameworkSummarySchema(BaseModel):
    id: str
    key: str
    status: str
    metadata: FrameworkMetadataSchema
    requirement_count: int
    created_at: datetime
    updated_at: datetime


class ControlRequirementSchema(BaseModel):
    id: str
    framework_key: str
    requirement_ref: str
    title: str
    description: str
    domain: str
    severity: str
    guidance: str
    policy_threshold: int
    tags: list[str]
    external_ref: str
    created_at: datetime
    updated_at: datetime


class ControlMappingSchema(BaseModel):
    id: str
    source_requirement_id: str
    target_requirement_id: str
    source_framework_key: str
    target_framework_key: str
    confidence: str
    rationale: str
    version: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


class PaginatedRequirementsSchema(BaseModel):
    items: list[ControlRequirementSchema]
    total: int
    limit: int
    offset: int


class PaginatedMappingsSchema(BaseModel):
    items: list[ControlMappingSchema]
    total: int
    limit: int
    offset: int


# ─── Request schemas ──────────────────────────────────────────────────────────


class RetireFrameworkBody(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)


class DefineMappingBody(BaseModel):
    source_requirement_id: str
    target_requirement_id: str
    source_framework_key: str
    target_framework_key: str
    confidence: str
    rationale: str = Field(default="", max_length=2000)


class RevokeMappingBody(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)


class SeedCatalogBody(BaseModel):
    auto_publish: bool = True


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _framework_to_schema(framework: Any) -> FrameworkSummarySchema:
    return FrameworkSummarySchema(
        id=str(framework.id),
        key=framework.key.value,
        status=framework.status.value,
        metadata=FrameworkMetadataSchema(
            name=framework.metadata.name,
            version=framework.metadata.version,
            issuing_body=framework.metadata.issuing_body,
            description=framework.metadata.description,
            effective_date=framework.metadata.effective_date,
            tags=list(framework.metadata.tags),
            external_url=framework.metadata.external_url,
        ),
        requirement_count=framework.requirement_count(),
        created_at=framework.created_at,
        updated_at=framework.updated_at,
    )


def _requirement_to_schema(req: Any) -> ControlRequirementSchema:
    return ControlRequirementSchema(
        id=str(req.id),
        framework_key=req.framework_key.value,
        requirement_ref=req.requirement_ref,
        title=req.title,
        description=req.description,
        domain=req.domain.value,
        severity=req.severity.value,
        guidance=req.guidance,
        policy_threshold=req.policy_threshold.value,
        tags=list(req.tags),
        external_ref=req.external_ref,
        created_at=req.created_at,
        updated_at=req.updated_at,
    )


def _mapping_to_schema(mapping: Any) -> ControlMappingSchema:
    return ControlMappingSchema(
        id=str(mapping.id),
        source_requirement_id=str(mapping.source_requirement_id),
        target_requirement_id=str(mapping.target_requirement_id),
        source_framework_key=mapping.source_framework_key.value,
        target_framework_key=mapping.target_framework_key.value,
        confidence=mapping.confidence.value,
        rationale=mapping.rationale,
        version=str(mapping.version),
        is_active=mapping.is_active,
        created_at=mapping.created_at,
        updated_at=mapping.updated_at,
    )


def _parse_framework_key(key: str) -> FrameworkKey:
    try:
        return FrameworkKey(key)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown framework key: '{key}'") from exc


def _parse_entity_id(id_str: str, label: str = "ID") -> EntityId:
    try:
        return EntityId.from_string(id_str)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {label}: '{id_str}'") from exc


_NOT_FOUND = (FrameworkNotFoundError, ControlRequirementNotFoundError, ControlMappingNotFoundError)
_CONFLICT = (FrameworkAlreadyPublishedError, DuplicateControlMappingError)


def _compliance_error_to_http(exc: ComplianceDomainError) -> HTTPException:
    if isinstance(exc, _NOT_FOUND):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, _CONFLICT):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, FrameworkRetiredError):
        return HTTPException(status_code=422, detail=str(exc))
    return HTTPException(status_code=422, detail=str(exc))


# ─── Platform Admin Routes ────────────────────────────────────────────────────


@router.get(
    "/platform/compliance/frameworks",
    response_model=list[FrameworkSummarySchema],
    tags=["compliance-platform"],
    summary="List all compliance frameworks (platform admin)",
)
async def platform_list_frameworks(
    status: str | None = Query(default=None),
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_READ)
    ),
    svc: CatalogQueryService = Depends(get_catalog_query_service),
) -> list[FrameworkSummarySchema]:
    frameworks = await svc.list_frameworks(status_filter=status)
    return [_framework_to_schema(f) for f in frameworks]


@router.get(
    "/platform/compliance/frameworks/{key}",
    response_model=FrameworkSummarySchema,
    tags=["compliance-platform"],
    summary="Get a compliance framework by key (platform admin)",
)
async def platform_get_framework(
    key: str,
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_READ)
    ),
    svc: CatalogQueryService = Depends(get_catalog_query_service),
) -> FrameworkSummarySchema:
    fw_key = _parse_framework_key(key)
    framework = await svc.get_framework(fw_key)
    if framework is None:
        raise HTTPException(status_code=404, detail=f"Framework '{key}' not found")
    return _framework_to_schema(framework)


@router.post(
    "/platform/compliance/frameworks/{key}/publish",
    status_code=200,
    response_model=FrameworkSummarySchema,
    tags=["compliance-platform"],
    summary="Publish a DRAFT framework (platform admin)",
)
async def platform_publish_framework(
    key: str,
    platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_MANAGE)
    ),
    publishing_svc: CatalogPublishingService = Depends(get_catalog_publishing_service),
    query_svc: CatalogQueryService = Depends(get_catalog_query_service),
) -> FrameworkSummarySchema:
    from redforge.application.compliance.dtos import PublishFrameworkCommand

    fw_key = _parse_framework_key(key)
    try:
        await publishing_svc.publish_framework(
            PublishFrameworkCommand(
                framework_key=fw_key,
                published_by=platform.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _compliance_error_to_http(exc) from exc

    framework = await query_svc.get_framework(fw_key)
    if framework is None:
        raise HTTPException(status_code=404, detail=f"Framework '{key}' not found")
    return _framework_to_schema(framework)


@router.post(
    "/platform/compliance/frameworks/{key}/retire",
    status_code=200,
    response_model=FrameworkSummarySchema,
    tags=["compliance-platform"],
    summary="Retire a PUBLISHED framework (platform admin)",
)
async def platform_retire_framework(
    key: str,
    body: RetireFrameworkBody,
    platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_MANAGE)
    ),
    publishing_svc: CatalogPublishingService = Depends(get_catalog_publishing_service),
    query_svc: CatalogQueryService = Depends(get_catalog_query_service),
) -> FrameworkSummarySchema:
    from redforge.application.compliance.dtos import RetireFrameworkCommand

    fw_key = _parse_framework_key(key)
    try:
        await publishing_svc.retire_framework(
            RetireFrameworkCommand(
                framework_key=fw_key,
                reason=body.reason,
                retired_by=platform.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _compliance_error_to_http(exc) from exc

    framework = await query_svc.get_framework(fw_key)
    if framework is None:
        raise HTTPException(status_code=404, detail=f"Framework '{key}' not found")
    return _framework_to_schema(framework)


@router.get(
    "/platform/compliance/requirements/{key}",
    response_model=PaginatedRequirementsSchema,
    tags=["compliance-platform"],
    summary="List requirements for a framework (platform admin)",
)
async def platform_list_requirements(
    key: str,
    search: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_READ)
    ),
    svc: CatalogQueryService = Depends(get_catalog_query_service),
) -> PaginatedRequirementsSchema:
    fw_key = _parse_framework_key(key)
    items, total = await svc.list_requirements(
        fw_key, search=search, limit=limit, offset=offset
    )
    return PaginatedRequirementsSchema(
        items=[_requirement_to_schema(r) for r in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/platform/compliance/requirements/{key}/{requirement_id}",
    response_model=ControlRequirementSchema,
    tags=["compliance-platform"],
    summary="Get a single control requirement (platform admin)",
)
async def platform_get_requirement(
    key: str,
    requirement_id: str,
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_READ)
    ),
    svc: CatalogQueryService = Depends(get_catalog_query_service),
) -> ControlRequirementSchema:
    _parse_framework_key(key)
    req_id = _parse_entity_id(requirement_id, "requirement ID")
    req = await svc.get_requirement(req_id)
    if req is None:
        raise HTTPException(status_code=404, detail=f"Requirement '{requirement_id}' not found")
    return _requirement_to_schema(req)


@router.get(
    "/platform/compliance/mappings",
    response_model=PaginatedMappingsSchema,
    tags=["compliance-platform"],
    summary="List cross-framework control mappings (platform admin)",
)
async def platform_list_mappings(
    source_framework: str | None = Query(default=None),
    target_framework: str | None = Query(default=None),
    active_only: bool = Query(default=True),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_READ)
    ),
    svc: MappingService = Depends(get_mapping_service),
) -> PaginatedMappingsSchema:
    from redforge.application.compliance.dtos import ListMappingsQuery

    src_key = _parse_framework_key(source_framework) if source_framework else None
    tgt_key = _parse_framework_key(target_framework) if target_framework else None

    items, total = await svc.list_mappings(
        ListMappingsQuery(
            source_framework_key=src_key,
            target_framework_key=tgt_key,
            active_only=active_only,
            limit=limit,
            offset=offset,
        )
    )
    return PaginatedMappingsSchema(
        items=[_mapping_to_schema(m) for m in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/platform/compliance/mappings",
    status_code=201,
    response_model=ControlMappingSchema,
    tags=["compliance-platform"],
    summary="Define a new cross-framework mapping (platform admin)",
)
async def platform_define_mapping(
    body: DefineMappingBody,
    platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_MANAGE)
    ),
    svc: MappingService = Depends(get_mapping_service),
) -> ControlMappingSchema:
    from redforge.application.compliance.dtos import DefineMappingCommand
    from redforge.domain.compliance.value_objects import MappingConfidenceHint

    try:
        src_key = FrameworkKey(body.source_framework_key)
        tgt_key = FrameworkKey(body.target_framework_key)
        confidence = MappingConfidenceHint(body.confidence)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    src_req_id = _parse_entity_id(body.source_requirement_id, "source_requirement_id")
    tgt_req_id = _parse_entity_id(body.target_requirement_id, "target_requirement_id")

    try:
        mapping = await svc.define_mapping(
            DefineMappingCommand(
                source_requirement_id=src_req_id,
                target_requirement_id=tgt_req_id,
                source_framework_key=src_key,
                target_framework_key=tgt_key,
                confidence=confidence,
                rationale=body.rationale,
                defined_by=platform.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _compliance_error_to_http(exc) from exc

    return _mapping_to_schema(mapping)


@router.delete(
    "/platform/compliance/mappings/{mapping_id}",
    status_code=200,
    tags=["compliance-platform"],
    summary="Revoke an active control mapping (platform admin)",
)
async def platform_revoke_mapping(
    mapping_id: str,
    body: RevokeMappingBody,
    platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_MANAGE)
    ),
    svc: MappingService = Depends(get_mapping_service),
) -> dict[str, str]:
    from redforge.application.compliance.dtos import RevokeMappingCommand

    mid = _parse_entity_id(mapping_id, "mapping ID")
    try:
        await svc.revoke_mapping(
            RevokeMappingCommand(
                mapping_id=mid,
                reason=body.reason,
                revoked_by=platform.user_id,
            )
        )
    except ComplianceDomainError as exc:
        raise _compliance_error_to_http(exc) from exc

    return {"mapping_id": mapping_id, "status": "revoked"}


@router.post(
    "/platform/compliance/seed",
    status_code=200,
    tags=["compliance-platform"],
    summary="Trigger idempotent catalog seed from framework adapters (platform admin)",
)
async def platform_seed_catalog(
    body: SeedCatalogBody,
    platform: PlatformContext = Depends(
        require_platform_permission(PlatformPermission.PLATFORM_COMPLIANCE_CATALOG_MANAGE)
    ),
    svc: CatalogPublishingService = Depends(get_catalog_publishing_service),
) -> dict[str, dict[str, str]]:
    from redforge.application.compliance.dtos import SeedCatalogCommand

    summary = await svc.seed_catalog(
        SeedCatalogCommand(
            published_by=platform.user_id,
            auto_publish=body.auto_publish,
        )
    )
    return {"outcomes": summary}


# ─── Org Read-Only Routes ─────────────────────────────────────────────────────


@router.get(
    "/compliance/frameworks",
    response_model=list[FrameworkSummarySchema],
    tags=["compliance"],
    summary="List published compliance frameworks",
)
async def org_list_frameworks(
    _tenant: TenantContext = Depends(
        require_permission(Permission.FINDINGS_READ)
    ),
    svc: CatalogQueryService = Depends(get_catalog_query_service),
) -> list[FrameworkSummarySchema]:
    frameworks = await svc.list_frameworks(status_filter=FrameworkStatus.PUBLISHED.value)
    return [_framework_to_schema(f) for f in frameworks]


@router.get(
    "/compliance/frameworks/{key}",
    response_model=FrameworkSummarySchema,
    tags=["compliance"],
    summary="Get a published compliance framework",
)
async def org_get_framework(
    key: str,
    _tenant: TenantContext = Depends(
        require_permission(Permission.FINDINGS_READ)
    ),
    svc: CatalogQueryService = Depends(get_catalog_query_service),
) -> FrameworkSummarySchema:
    fw_key = _parse_framework_key(key)
    framework = await svc.get_framework(fw_key)
    if framework is None or framework.status.value != FrameworkStatus.PUBLISHED.value:
        raise HTTPException(status_code=404, detail=f"Framework '{key}' not found")
    return _framework_to_schema(framework)


@router.get(
    "/compliance/requirements/{key}",
    response_model=PaginatedRequirementsSchema,
    tags=["compliance"],
    summary="List control requirements for a framework",
)
async def org_list_requirements(
    key: str,
    search: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(
        require_permission(Permission.FINDINGS_READ)
    ),
    svc: CatalogQueryService = Depends(get_catalog_query_service),
) -> PaginatedRequirementsSchema:
    fw_key = _parse_framework_key(key)
    items, total = await svc.list_requirements(
        fw_key, search=search, limit=limit, offset=offset
    )
    return PaginatedRequirementsSchema(
        items=[_requirement_to_schema(r) for r in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/compliance/requirements/{key}/{requirement_id}",
    response_model=ControlRequirementSchema,
    tags=["compliance"],
    summary="Get a single control requirement",
)
async def org_get_requirement(
    key: str,
    requirement_id: str,
    _tenant: TenantContext = Depends(
        require_permission(Permission.FINDINGS_READ)
    ),
    svc: CatalogQueryService = Depends(get_catalog_query_service),
) -> ControlRequirementSchema:
    _parse_framework_key(key)
    req_id = _parse_entity_id(requirement_id, "requirement ID")
    req = await svc.get_requirement(req_id)
    if req is None:
        raise HTTPException(status_code=404, detail=f"Requirement '{requirement_id}' not found")
    return _requirement_to_schema(req)


@router.get(
    "/compliance/mappings",
    response_model=PaginatedMappingsSchema,
    tags=["compliance"],
    summary="Browse active cross-framework control mappings",
)
async def org_list_mappings(
    source_framework: str | None = Query(default=None),
    target_framework: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _tenant: TenantContext = Depends(
        require_permission(Permission.FINDINGS_READ)
    ),
    svc: MappingService = Depends(get_mapping_service),
) -> PaginatedMappingsSchema:
    from redforge.application.compliance.dtos import ListMappingsQuery

    src_key = _parse_framework_key(source_framework) if source_framework else None
    tgt_key = _parse_framework_key(target_framework) if target_framework else None

    items, total = await svc.list_mappings(
        ListMappingsQuery(
            source_framework_key=src_key,
            target_framework_key=tgt_key,
            active_only=True,
            limit=limit,
            offset=offset,
        )
    )
    return PaginatedMappingsSchema(
        items=[_mapping_to_schema(m) for m in items],
        total=total,
        limit=limit,
        offset=offset,
    )
