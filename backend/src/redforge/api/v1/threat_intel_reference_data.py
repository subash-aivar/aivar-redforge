"""Threat Intelligence Reference Data — internal administration API.

M22 Phase 1 only. These endpoints let a platform administrator load
and verify the global ATT&CK / CVE reference catalog. They are NOT
public Threat Intelligence APIs (those live in `api/v1/threat_intel.py`,
M18, tenant-scoped) — every endpoint here requires a
`PlatformPermission`, never a tenant `Permission`, and every table
touched is global (no `organization_id`).

Deliberately excluded from Phase 1 (per the architecture freeze/
hardening review, later M22 phases): fetching from MITRE ATT&CK's STIX
bundle, NVD, EPSS, or CISA KEV; STIX/TAXII parsing; the Fusion Engine;
the Attack Path Engine; and any Investigation integration. Callers of
these endpoints supply already-fetched, already-parsed records.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from redforge.api.security import PlatformContext, require_platform_permission
from redforge.core.exceptions import ValidationError
from redforge.domain.platform_identity.value_objects import PlatformPermission
from redforge.domain.threat_intel.reference_data_value_objects import (
    AttackRelationshipType,
    ReferenceDataSource,
)

if TYPE_CHECKING:
    from redforge.application.threat_intel.reference_data_admin_service import (
        BatchUpsertResult,
    )
    from redforge.domain.threat_intel.attack_technique_entity import (
        AttackTactic,
        AttackTechnique,
        AttackTechniqueRelationship,
    )
    from redforge.domain.threat_intel.reference_data_ingestion import (
        ReferenceDataIngestionRecord,
    )
    from redforge.domain.threat_intel.vulnerability_entity import Vulnerability

router = APIRouter(prefix="/threat-intel/reference-data", tags=["threat-intel-reference-data"])


def _get_session_factory() -> object:
    from redforge.api.dependencies import get_session_factory

    return get_session_factory()


# ─── Request models ─────────────────────────────────────────────────────────


class TacticItem(BaseModel):
    tactic_id: str = Field(..., min_length=1, max_length=32)
    name: str = Field(..., min_length=1, max_length=256)
    shortname: str = Field(..., min_length=1, max_length=128)
    stix_id: str = Field(..., min_length=1, max_length=128)
    description: str = Field(default="", max_length=8000)
    url: str | None = Field(default=None, max_length=1024)


class TacticBatchRequest(BaseModel):
    tactics: list[TacticItem] = Field(..., min_length=1, max_length=200)
    batch_id: str | None = None


class TechniqueItem(BaseModel):
    technique_id: str = Field(..., min_length=1, max_length=32)
    name: str = Field(..., min_length=1, max_length=256)
    stix_id: str = Field(..., min_length=1, max_length=128)
    description: str = Field(default="", max_length=16000)
    is_sub_technique: bool = False
    parent_technique_id: str | None = Field(default=None, max_length=32)
    tactic_ids: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    is_deprecated: bool = False
    is_revoked: bool = False
    framework_version: str | None = Field(default=None, max_length=32)


class TechniqueBatchRequest(BaseModel):
    techniques: list[TechniqueItem] = Field(..., min_length=1, max_length=500)
    batch_id: str | None = None


class RelationshipItem(BaseModel):
    stix_id: str = Field(..., min_length=1, max_length=128)
    relationship_type: str = Field(..., min_length=1, max_length=64)
    source_ref: str = Field(..., min_length=1, max_length=128)
    target_ref: str = Field(..., min_length=1, max_length=128)
    source_technique_id: str | None = Field(default=None, max_length=32)
    target_technique_id: str | None = Field(default=None, max_length=32)
    description: str = Field(default="", max_length=8000)


class RelationshipBatchRequest(BaseModel):
    relationships: list[RelationshipItem] = Field(..., min_length=1, max_length=1000)
    batch_id: str | None = None


class VulnerabilityItem(BaseModel):
    cve_id: str = Field(..., min_length=1, max_length=32)
    description: str = Field(default="", max_length=16000)
    cvss_v3_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_v3_vector: str | None = Field(default=None, max_length=256)
    cvss_v3_version: str | None = Field(default=None, max_length=16)
    cvss_v2_score: float | None = Field(default=None, ge=0.0, le=10.0)
    epss_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_model_date: str | None = None
    is_kev: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_vulnerability_name: str | None = Field(default=None, max_length=256)
    kev_short_description: str | None = Field(default=None, max_length=4000)
    kev_required_action: str | None = Field(default=None, max_length=4000)
    kev_known_ransomware_use: bool = False
    published_at: str | None = None
    last_modified_at: str | None = None


class VulnerabilityBatchRequest(BaseModel):
    vulnerabilities: list[VulnerabilityItem] = Field(..., min_length=1, max_length=500)
    source_system: str = Field(default=ReferenceDataSource.NVD_CVE.value)
    batch_id: str | None = None


# ─── Response models ────────────────────────────────────────────────────────


class ItemErrorResponse(BaseModel):
    index: int
    identifier: str
    message: str


class BatchUpsertResultResponse(BaseModel):
    source_system: str
    object_type: str
    batch_id: str
    total: int
    created: int
    updated: int
    unchanged: int
    failed: int
    errors: list[ItemErrorResponse]

    @classmethod
    def from_domain(cls, result: BatchUpsertResult) -> BatchUpsertResultResponse:
        return cls(
            source_system=result.source_system,
            object_type=result.object_type,
            batch_id=result.batch_id,
            total=result.total,
            created=result.created,
            updated=result.updated,
            unchanged=result.unchanged,
            failed=result.failed,
            errors=[
                ItemErrorResponse(index=e.index, identifier=e.identifier, message=e.message)
                for e in result.errors
            ],
        )


class AttackTacticResponse(BaseModel):
    tactic_id: str
    name: str
    shortname: str
    description: str
    stix_id: str
    url: str | None
    created_at: str
    updated_at: str

    @classmethod
    def from_domain(cls, tactic: AttackTactic) -> AttackTacticResponse:
        return cls(
            tactic_id=tactic.tactic_id.value,
            name=tactic.name,
            shortname=tactic.shortname,
            description=tactic.description,
            stix_id=tactic.stix_id,
            url=tactic.url,
            created_at=tactic.created_at.isoformat(),
            updated_at=tactic.updated_at.isoformat(),
        )


class AttackTechniqueResponse(BaseModel):
    technique_id: str
    name: str
    description: str
    stix_id: str
    is_sub_technique: bool
    parent_technique_id: str | None
    tactic_ids: list[str]
    platforms: list[str]
    data_sources: list[str]
    is_deprecated: bool
    is_revoked: bool
    framework_version: str | None
    created_at: str | None
    updated_at: str | None

    @classmethod
    def from_domain(cls, technique: AttackTechnique) -> AttackTechniqueResponse:
        return cls(
            technique_id=technique.technique_id.value,
            name=technique.name,
            description=technique.description,
            stix_id=technique.stix_id,
            is_sub_technique=technique.is_sub_technique,
            parent_technique_id=(
                technique.parent_technique_id.value if technique.parent_technique_id else None
            ),
            tactic_ids=[t.value for t in technique.tactic_ids],
            platforms=list(technique.platforms),
            data_sources=list(technique.data_sources),
            is_deprecated=technique.is_deprecated,
            is_revoked=technique.is_revoked,
            framework_version=technique.framework_version,
            created_at=technique.created_at.isoformat() if technique.created_at else None,
            updated_at=technique.updated_at.isoformat() if technique.updated_at else None,
        )


class AttackTechniqueRelationshipResponse(BaseModel):
    stix_id: str
    relationship_type: str
    source_ref: str
    target_ref: str
    source_technique_id: str | None
    target_technique_id: str | None
    description: str
    created_at: str
    updated_at: str

    @classmethod
    def from_domain(
        cls, relationship: AttackTechniqueRelationship
    ) -> AttackTechniqueRelationshipResponse:
        return cls(
            stix_id=relationship.stix_id,
            relationship_type=relationship.relationship_type.value,
            source_ref=relationship.source_ref,
            target_ref=relationship.target_ref,
            source_technique_id=(
                relationship.source_technique_id.value
                if relationship.source_technique_id
                else None
            ),
            target_technique_id=(
                relationship.target_technique_id.value
                if relationship.target_technique_id
                else None
            ),
            description=relationship.description,
            created_at=relationship.created_at.isoformat(),
            updated_at=relationship.updated_at.isoformat(),
        )


class CvssScoreResponse(BaseModel):
    version: str
    base_score: float
    vector: str
    severity: str


class EpssScoreResponse(BaseModel):
    probability: float
    percentile: float
    model_date: str


class VulnerabilityResponse(BaseModel):
    cve_id: str
    description: str
    cvss_v3: CvssScoreResponse | None
    cvss_v2_score: float | None
    epss: EpssScoreResponse | None
    is_kev: bool
    kev_date_added: str | None
    kev_due_date: str | None
    kev_vulnerability_name: str | None
    kev_short_description: str | None
    kev_required_action: str | None
    kev_known_ransomware_use: bool
    published_at: str | None
    last_modified_at: str | None
    source_last_synced_at: str | None
    created_at: str
    updated_at: str

    @classmethod
    def from_domain(cls, vulnerability: Vulnerability) -> VulnerabilityResponse:
        cvss_v3 = None
        if vulnerability.cvss_v3 is not None:
            cvss_v3 = CvssScoreResponse(
                version=vulnerability.cvss_v3.version,
                base_score=vulnerability.cvss_v3.base_score,
                vector=vulnerability.cvss_v3.vector,
                severity=vulnerability.cvss_v3.severity,
            )
        epss = None
        if vulnerability.epss is not None:
            epss = EpssScoreResponse(
                probability=vulnerability.epss.probability,
                percentile=vulnerability.epss.percentile,
                model_date=vulnerability.epss.model_date.isoformat(),
            )
        return cls(
            cve_id=vulnerability.cve_id.value,
            description=vulnerability.description,
            cvss_v3=cvss_v3,
            cvss_v2_score=vulnerability.cvss_v2_score,
            epss=epss,
            is_kev=vulnerability.is_kev,
            kev_date_added=(
                vulnerability.kev_date_added.isoformat() if vulnerability.kev_date_added else None
            ),
            kev_due_date=(
                vulnerability.kev_due_date.isoformat() if vulnerability.kev_due_date else None
            ),
            kev_vulnerability_name=vulnerability.kev_vulnerability_name,
            kev_short_description=vulnerability.kev_short_description,
            kev_required_action=vulnerability.kev_required_action,
            kev_known_ransomware_use=vulnerability.kev_known_ransomware_use,
            published_at=(
                vulnerability.published_at.isoformat() if vulnerability.published_at else None
            ),
            last_modified_at=(
                vulnerability.last_modified_at.isoformat()
                if vulnerability.last_modified_at
                else None
            ),
            source_last_synced_at=(
                vulnerability.source_last_synced_at.isoformat()
                if vulnerability.source_last_synced_at
                else None
            ),
            created_at=vulnerability.created_at.isoformat(),
            updated_at=vulnerability.updated_at.isoformat(),
        )


class IngestionRecordResponse(BaseModel):
    id: str
    source_system: str
    scope: str
    organization_id: str | None
    object_type: str
    external_id: str
    content_hash: str
    ingested_at: str
    batch_id: str | None

    @classmethod
    def from_domain(cls, record: ReferenceDataIngestionRecord) -> IngestionRecordResponse:
        return cls(
            id=record.id,
            source_system=record.source_system.value,
            scope=record.scope.value,
            organization_id=record.organization_id,
            object_type=record.object_type,
            external_id=record.external_id,
            content_hash=record.content_hash,
            ingested_at=record.ingested_at.isoformat(),
            batch_id=record.batch_id,
        )


# ─── Tactics ─────────────────────────────────────────────────────────────────


@router.post(
    "/tactics",
    response_model=BatchUpsertResultResponse,
    status_code=status.HTTP_200_OK,
)
async def upsert_tactics(
    body: TacticBatchRequest,
    platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_MANAGE)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> BatchUpsertResultResponse:
    from redforge.application.threat_intel.reference_data_admin_service import (
        ReferenceDataAdminService,
        TacticInput,
    )

    service = ReferenceDataAdminService(session_factory)  # type: ignore[arg-type]
    result = await service.upsert_tactics(
        actor_id=platform.user_id,
        tactics=[TacticInput(**item.model_dump()) for item in body.tactics],
        batch_id=body.batch_id,
    )
    return BatchUpsertResultResponse.from_domain(result)


@router.get("/tactics", response_model=list[AttackTacticResponse])
async def list_tactics(
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_READ)),
    ],
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session_factory: object = Depends(_get_session_factory),
) -> list[AttackTacticResponse]:
    from redforge.application.threat_intel.reference_data_query_service import (
        ReferenceDataQueryService,
    )

    async with session_factory() as session, session.begin():  # type: ignore[operator]
        tactics = await ReferenceDataQueryService(session).list_tactics(
            limit=limit, offset=offset
        )
    return [AttackTacticResponse.from_domain(t) for t in tactics]


@router.get("/tactics/{tactic_id}", response_model=AttackTacticResponse)
async def get_tactic(
    tactic_id: str,
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_READ)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> AttackTacticResponse:
    from redforge.application.threat_intel.reference_data_query_service import (
        ReferenceDataQueryService,
    )

    async with session_factory() as session, session.begin():  # type: ignore[operator]
        tactic = await ReferenceDataQueryService(session).get_tactic(tactic_id)
    if tactic is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Tactic {tactic_id!r} not found")
    return AttackTacticResponse.from_domain(tactic)


# ─── Techniques ──────────────────────────────────────────────────────────────


@router.post(
    "/techniques",
    response_model=BatchUpsertResultResponse,
    status_code=status.HTTP_200_OK,
)
async def upsert_techniques(
    body: TechniqueBatchRequest,
    platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_MANAGE)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> BatchUpsertResultResponse:
    from redforge.application.threat_intel.reference_data_admin_service import (
        ReferenceDataAdminService,
        TechniqueInput,
    )

    service = ReferenceDataAdminService(session_factory)  # type: ignore[arg-type]
    result = await service.upsert_techniques(
        actor_id=platform.user_id,
        techniques=[TechniqueInput(**item.model_dump()) for item in body.techniques],
        batch_id=body.batch_id,
    )
    return BatchUpsertResultResponse.from_domain(result)


@router.get("/techniques", response_model=list[AttackTechniqueResponse])
async def list_techniques(
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_READ)),
    ],
    tactic_id: str | None = Query(default=None),
    search: str | None = Query(default=None, min_length=1, max_length=256),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session_factory: object = Depends(_get_session_factory),
) -> list[AttackTechniqueResponse]:
    from redforge.application.threat_intel.reference_data_query_service import (
        ReferenceDataQueryService,
    )

    async with session_factory() as session, session.begin():  # type: ignore[operator]
        query_service = ReferenceDataQueryService(session)
        if search is not None:
            techniques = await query_service.search_techniques(
                search, limit=limit, offset=offset
            )
        elif tactic_id is not None:
            techniques = await query_service.list_techniques_by_tactic(
                tactic_id, limit=limit, offset=offset
            )
        else:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Either 'tactic_id' or 'search' query parameter is required",
            )
    return [AttackTechniqueResponse.from_domain(t) for t in techniques]


@router.get("/techniques/{technique_id}", response_model=AttackTechniqueResponse)
async def get_technique(
    technique_id: str,
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_READ)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> AttackTechniqueResponse:
    from redforge.application.threat_intel.reference_data_query_service import (
        ReferenceDataQueryService,
    )

    async with session_factory() as session, session.begin():  # type: ignore[operator]
        technique = await ReferenceDataQueryService(session).get_technique(technique_id)
    if technique is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail=f"Technique {technique_id!r} not found"
        )
    return AttackTechniqueResponse.from_domain(technique)


@router.get(
    "/techniques/{technique_id}/sub-techniques",
    response_model=list[AttackTechniqueResponse],
)
async def list_sub_techniques(
    technique_id: str,
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_READ)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> list[AttackTechniqueResponse]:
    from redforge.application.threat_intel.reference_data_query_service import (
        ReferenceDataQueryService,
    )

    async with session_factory() as session, session.begin():  # type: ignore[operator]
        sub_techniques = await ReferenceDataQueryService(session).list_sub_techniques(
            technique_id
        )
    return [AttackTechniqueResponse.from_domain(t) for t in sub_techniques]


@router.get(
    "/techniques/{technique_id}/relationships",
    response_model=list[AttackTechniqueRelationshipResponse],
)
async def list_technique_relationships(
    technique_id: str,
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_READ)),
    ],
    relationship_type: str | None = Query(default=None),
    session_factory: object = Depends(_get_session_factory),
) -> list[AttackTechniqueRelationshipResponse]:
    from redforge.application.threat_intel.reference_data_query_service import (
        ReferenceDataQueryService,
    )

    parsed_type: AttackRelationshipType | None = None
    if relationship_type is not None:
        try:
            parsed_type = AttackRelationshipType(relationship_type)
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown relationship_type: {relationship_type!r}",
            ) from exc

    async with session_factory() as session, session.begin():  # type: ignore[operator]
        relationships = await ReferenceDataQueryService(session).list_technique_relationships(
            technique_id, relationship_type=parsed_type
        )
    return [AttackTechniqueRelationshipResponse.from_domain(r) for r in relationships]


@router.post(
    "/techniques/relationships",
    response_model=BatchUpsertResultResponse,
    status_code=status.HTTP_200_OK,
)
async def upsert_technique_relationships(
    body: RelationshipBatchRequest,
    platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_MANAGE)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> BatchUpsertResultResponse:
    from redforge.application.threat_intel.reference_data_admin_service import (
        ReferenceDataAdminService,
        RelationshipInput,
    )

    service = ReferenceDataAdminService(session_factory)  # type: ignore[arg-type]
    result = await service.upsert_technique_relationships(
        actor_id=platform.user_id,
        relationships=[RelationshipInput(**item.model_dump()) for item in body.relationships],
        batch_id=body.batch_id,
    )
    return BatchUpsertResultResponse.from_domain(result)


# ─── Vulnerabilities ─────────────────────────────────────────────────────────


@router.post(
    "/vulnerabilities",
    response_model=BatchUpsertResultResponse,
    status_code=status.HTTP_200_OK,
)
async def upsert_vulnerabilities(
    body: VulnerabilityBatchRequest,
    platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_MANAGE)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> BatchUpsertResultResponse:
    from redforge.application.threat_intel.reference_data_admin_service import (
        ReferenceDataAdminService,
        VulnerabilityInput,
    )

    try:
        source_system = ReferenceDataSource(body.source_system)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown source_system: {body.source_system!r}",
        ) from exc

    service = ReferenceDataAdminService(session_factory)  # type: ignore[arg-type]
    try:
        result = await service.upsert_vulnerabilities(
            actor_id=platform.user_id,
            vulnerabilities=[
                VulnerabilityInput(**item.model_dump()) for item in body.vulnerabilities
            ],
            source_system=source_system,
            batch_id=body.batch_id,
        )
    except ValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.message) from exc
    return BatchUpsertResultResponse.from_domain(result)


@router.get("/vulnerabilities", response_model=list[VulnerabilityResponse])
async def list_vulnerabilities(
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_READ)),
    ],
    kev_only: bool = Query(default=False),
    min_epss_probability: float | None = Query(default=None, ge=0.0, le=1.0),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session_factory: object = Depends(_get_session_factory),
) -> list[VulnerabilityResponse]:
    from redforge.application.threat_intel.reference_data_query_service import (
        ReferenceDataQueryService,
    )

    async with session_factory() as session, session.begin():  # type: ignore[operator]
        query_service = ReferenceDataQueryService(session)
        if kev_only:
            vulnerabilities = await query_service.list_kev_vulnerabilities(
                limit=limit, offset=offset
            )
        elif min_epss_probability is not None:
            vulnerabilities = await query_service.list_high_epss_vulnerabilities(
                min_epss_probability, limit=limit, offset=offset
            )
        else:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Either 'kev_only=true' or 'min_epss_probability' is required",
            )
    return [VulnerabilityResponse.from_domain(v) for v in vulnerabilities]


@router.get("/vulnerabilities/{cve_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    cve_id: str,
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_READ)),
    ],
    session_factory: object = Depends(_get_session_factory),
) -> VulnerabilityResponse:
    from redforge.application.threat_intel.reference_data_query_service import (
        ReferenceDataQueryService,
    )

    async with session_factory() as session, session.begin():  # type: ignore[operator]
        vulnerability = await ReferenceDataQueryService(session).get_vulnerability(cve_id)
    if vulnerability is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"CVE {cve_id!r} not found")
    return VulnerabilityResponse.from_domain(vulnerability)


# ─── Ingestion log (verification) ───────────────────────────────────────────


@router.get("/ingestions", response_model=list[IngestionRecordResponse])
async def list_ingestions(
    _platform: Annotated[
        PlatformContext,
        Depends(require_platform_permission(PlatformPermission.PLATFORM_THREAT_INTEL_READ)),
    ],
    source_system: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session_factory: object = Depends(_get_session_factory),
) -> list[IngestionRecordResponse]:
    from redforge.application.threat_intel.reference_data_query_service import (
        ReferenceDataQueryService,
    )

    parsed_source: ReferenceDataSource | None = None
    if source_system is not None:
        try:
            parsed_source = ReferenceDataSource(source_system)
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown source_system: {source_system!r}",
            ) from exc

    async with session_factory() as session, session.begin():  # type: ignore[operator]
        records = await ReferenceDataQueryService(session).list_recent_ingestions(
            source_system=parsed_source, limit=limit, offset=offset
        )
    return [IngestionRecordResponse.from_domain(r) for r in records]
