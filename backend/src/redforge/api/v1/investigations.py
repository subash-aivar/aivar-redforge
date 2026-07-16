"""Unified Threat Investigation REST API — M21.

All routes are tenant-scoped; organization_id is derived from JWT.

Permission gates:
  INVESTIGATIONS_READ   — all read endpoints
  INVESTIGATIONS_MANAGE — acknowledge / start-investigation / resolve
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission
from redforge.domain.investigations.exceptions import (
    InvalidStatusTransitionError,
    InvestigationNotFoundError,
)

router = APIRouter(prefix="/investigations")


# ── Request models ────────────────────────────────────────────────────────────


class AcknowledgeRequest(BaseModel):
    pass  # no body required


class StartInvestigationRequest(BaseModel):
    pass  # no body required


class ResolveRequest(BaseModel):
    resolution_reason: str = Field(..., min_length=1, max_length=60)
    notes: str = Field("", max_length=2000)


# ── Dependency helpers ────────────────────────────────────────────────────────


def _get_session_factory() -> Any:
    from redforge.api.dependencies import _session_factory
    return _session_factory()


async def _investigation_svc(
    session_factory: Any = Depends(_get_session_factory),
) -> Any:
    from redforge.application.investigations.case_service import InvestigationCaseService
    from redforge.application.security_graph.projector import SecurityGraphProjector
    from redforge.infrastructure.audit.logger import StructlogAuditLog
    from redforge.infrastructure.database.repositories.investigations.case_repository import (
        SqlAlchemyEvidenceLinkRepository,
        SqlAlchemyInvestigationEventRepository,
        SqlAlchemyInvestigationRepository,
    )
    from redforge.infrastructure.database.repositories.security_graph_repository import (
        SecurityGraphRepository,
    )

    async with session_factory() as session, session.begin():
        case_repo = SqlAlchemyInvestigationRepository(session)
        evidence_repo = SqlAlchemyEvidenceLinkRepository(session)
        event_repo = SqlAlchemyInvestigationEventRepository(session)
        audit_log = StructlogAuditLog()
        graph_repo = SecurityGraphRepository(session)
        graph_projector = SecurityGraphProjector(graph_repo)
        yield InvestigationCaseService(
            session, case_repo, evidence_repo, event_repo, audit_log, graph_projector
        )


async def _repos(session_factory: Any = Depends(_get_session_factory)) -> Any:
    from redforge.infrastructure.database.repositories.investigations.case_repository import (
        SqlAlchemyEvidenceLinkRepository,
        SqlAlchemyInvestigationEventRepository,
        SqlAlchemyInvestigationRepository,
    )

    async with session_factory() as session, session.begin():
        yield (
            SqlAlchemyInvestigationRepository(session),
            SqlAlchemyEvidenceLinkRepository(session),
            SqlAlchemyInvestigationEventRepository(session),
        )


# ── Formatters ────────────────────────────────────────────────────────────────


def _fmt_case(case: Any) -> dict[str, Any]:
    return {
        "id": case.id,
        "organization_id": case.organization_id,
        "title": case.title,
        "summary": case.summary,
        "status": case.status,
        "severity": case.severity,
        "confidence": case.confidence,
        "source_domains": case.source_domains or [],
        "involved_entities": case.involved_entities or [],
        "evidence_count": case.evidence_count,
        "first_observed_at": case.first_observed_at.isoformat(),
        "last_observed_at": case.last_observed_at.isoformat(),
        "opened_at": case.opened_at.isoformat(),
        "acknowledged_at": case.acknowledged_at.isoformat() if case.acknowledged_at else None,
        "investigating_at": case.investigating_at.isoformat() if case.investigating_at else None,
        "resolved_at": case.resolved_at.isoformat() if case.resolved_at else None,
        "resolution_reason": case.resolution_reason,
        "resolution_notes": case.resolution_notes,
        "version": case.version,
        "created_at": case.created_at.isoformat(),
        "updated_at": case.updated_at.isoformat(),
    }


def _fmt_evidence(link: Any) -> dict[str, Any]:
    return {
        "id": link.id,
        "case_id": link.case_id,
        "source_domain": link.source_domain,
        "source_entity_type": link.source_entity_type,
        "source_entity_id": link.source_entity_id,
        "event_type": link.event_type,
        "severity": link.severity,
        "observed_at": link.observed_at.isoformat(),
        "evidence_snapshot": link.evidence_snapshot,
        "correlation_reason": link.correlation_reason,
        "relationship_type": link.relationship_type,
        "observability": link.observability,
        "dedup_key": link.dedup_key,
        "created_at": link.created_at.isoformat(),
    }


def _fmt_event(ev: Any) -> dict[str, Any]:
    return {
        "id": ev.id,
        "event_id": ev.event_id,
        "case_id": ev.case_id,
        "event_type": ev.event_type,
        "detail": ev.detail,
        "actor_user_id": ev.actor_user_id,
        "occurred_at": ev.occurred_at.isoformat(),
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/posture")
async def get_investigation_posture(
    tenant: Annotated[
        TenantContext, Depends(require_permission(Permission.INVESTIGATIONS_READ))
    ],
    svc: Any = Depends(_investigation_svc),
) -> dict[str, Any]:
    """Global investigation posture for the organization."""
    return await svc.get_posture(tenant.organization_id)  # type: ignore[no-any-return]


@router.get("")
async def list_investigations(
    tenant: Annotated[
        TenantContext, Depends(require_permission(Permission.INVESTIGATIONS_READ))
    ],
    status: str | None = Query(None),
    severity: str | None = Query(None),
    source_domain: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    repos: Any = Depends(_repos),
) -> list[dict[str, Any]]:
    """List investigation cases with optional filters (paginated)."""
    case_repo, _, _ = repos
    cases = await case_repo.list_cases(
        tenant.organization_id,
        status=status,
        severity=severity,
        source_domain=source_domain,
        limit=limit,
        offset=offset,
    )
    return [_fmt_case(c) for c in cases]


@router.get("/{case_id}")
async def get_investigation(
    case_id: str,
    tenant: Annotated[
        TenantContext, Depends(require_permission(Permission.INVESTIGATIONS_READ))
    ],
    repos: Any = Depends(_repos),
) -> dict[str, Any]:
    """Get a single investigation case."""
    case_repo, evidence_repo, _ = repos
    case = await case_repo.get(tenant.organization_id, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    domain_count = await evidence_repo.count_domains(tenant.organization_id, case_id)
    result = _fmt_case(case)
    result["domain_count"] = domain_count
    return result


@router.get("/{case_id}/timeline")
async def get_investigation_timeline(
    case_id: str,
    tenant: Annotated[
        TenantContext, Depends(require_permission(Permission.INVESTIGATIONS_READ))
    ],
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    repos: Any = Depends(_repos),
) -> list[dict[str, Any]]:
    """Chronological timeline events for an investigation."""
    case_repo, _, event_repo = repos
    case = await case_repo.get(tenant.organization_id, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    events = await event_repo.list_events(
        tenant.organization_id, case_id, limit=limit, offset=offset
    )
    return [_fmt_event(e) for e in events]


@router.get("/{case_id}/evidence")
async def get_investigation_evidence(
    case_id: str,
    tenant: Annotated[
        TenantContext, Depends(require_permission(Permission.INVESTIGATIONS_READ))
    ],
    source_domain: str | None = Query(None),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    repos: Any = Depends(_repos),
) -> list[dict[str, Any]]:
    """Source-domain evidence attached to an investigation."""
    case_repo, evidence_repo, _ = repos
    case = await case_repo.get(tenant.organization_id, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    links = await evidence_repo.list_for_case(
        tenant.organization_id, case_id,
        source_domain=source_domain,
        limit=limit, offset=offset,
    )
    return [_fmt_evidence(lnk) for lnk in links]


@router.get("/{case_id}/graph")
async def get_investigation_graph(
    case_id: str,
    tenant: Annotated[
        TenantContext, Depends(require_permission(Permission.INVESTIGATIONS_READ))
    ],
    repos: Any = Depends(_repos),
) -> dict[str, Any]:
    """Evidence-backed investigation graph (entities + relationships).

    Only returns OBSERVED or INFERRED relationships — never fabricated.
    """
    case_repo, evidence_repo, _ = repos
    case = await case_repo.get(tenant.organization_id, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    links = await evidence_repo.list_for_case(tenant.organization_id, case_id, limit=200)

    nodes = []
    edges = []

    # Investigation case node
    nodes.append({
        "id": case.id,
        "kind": "investigation",
        "label": case.title,
        "severity": case.severity,
        "status": case.status,
    })

    seen_entities: set[str] = set()
    for link in links:
        entity_node_id = f"{link.source_domain}:{link.source_entity_id}"
        if entity_node_id not in seen_entities:
            seen_entities.add(entity_node_id)
            nodes.append({
                "id": entity_node_id,
                "kind": link.source_entity_type,
                "label": link.source_entity_id,
                "source_domain": link.source_domain,
            })

        edges.append({
            "source": entity_node_id,
            "target": case.id,
            "kind": "correlated_with",
            "observability": link.observability,
            "reason": link.correlation_reason[:200] if link.correlation_reason else "",
        })

    # Entity nodes from involved_entities
    for entity in (case.involved_entities or []):
        ent_id = f"entity:{entity.get('type', '')}:{entity.get('id', '')}"
        if ent_id not in seen_entities:
            seen_entities.add(ent_id)
            nodes.append({
                "id": ent_id,
                "kind": entity.get("type", "unknown").lower(),
                "label": entity.get("id", ""),
            })

    return {
        "case_id": case.id,
        "nodes": nodes,
        "edges": edges,
        "ontology_version": 6,
    }


@router.post("/{case_id}/acknowledge")
async def acknowledge_investigation(
    case_id: str,
    tenant: Annotated[
        TenantContext, Depends(require_permission(Permission.INVESTIGATIONS_MANAGE))
    ],
    _body: AcknowledgeRequest = AcknowledgeRequest(),
    svc: Any = Depends(_investigation_svc),
) -> dict[str, Any]:
    """Acknowledge an open investigation case."""
    try:
        await svc.acknowledge(
            organization_id=tenant.organization_id,
            case_id=case_id,
            actor_user_id=tenant.user_id,
        )
    except InvestigationNotFoundError:
        raise HTTPException(status_code=404, detail="Investigation not found") from None
    except InvalidStatusTransitionError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return {"case_id": case_id, "status": "ACKNOWLEDGED"}


@router.post("/{case_id}/start-investigation")
async def start_investigation(
    case_id: str,
    tenant: Annotated[
        TenantContext, Depends(require_permission(Permission.INVESTIGATIONS_MANAGE))
    ],
    _body: StartInvestigationRequest = StartInvestigationRequest(),
    svc: Any = Depends(_investigation_svc),
) -> dict[str, Any]:
    """Move a case into active investigation."""
    try:
        await svc.start_investigation(
            organization_id=tenant.organization_id,
            case_id=case_id,
            actor_user_id=tenant.user_id,
        )
    except InvestigationNotFoundError:
        raise HTTPException(status_code=404, detail="Investigation not found") from None
    except InvalidStatusTransitionError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return {"case_id": case_id, "status": "INVESTIGATING"}


@router.post("/{case_id}/resolve")
async def resolve_investigation(
    case_id: str,
    body: ResolveRequest,
    tenant: Annotated[
        TenantContext, Depends(require_permission(Permission.INVESTIGATIONS_MANAGE))
    ],
    svc: Any = Depends(_investigation_svc),
) -> dict[str, Any]:
    """Resolve an investigation case with a bounded resolution reason."""
    from redforge.domain.investigations.value_objects import ResolutionReason

    try:
        ResolutionReason(body.resolution_reason)  # validate
    except ValueError:
        valid = [r.value for r in ResolutionReason]
        raise HTTPException(  # noqa: B904
            status_code=422,
            detail=f"Invalid resolution_reason. Valid values: {valid}",
        )
    try:
        await svc.resolve(
            organization_id=tenant.organization_id,
            case_id=case_id,
            actor_user_id=tenant.user_id,
            resolution_reason=body.resolution_reason,
            notes=body.notes,
        )
    except InvestigationNotFoundError:
        raise HTTPException(status_code=404, detail="Investigation not found") from None
    except InvalidStatusTransitionError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return {"case_id": case_id, "status": "RESOLVED"}
