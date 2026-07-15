"""DDoS Defense Center REST API — M19.

All routes are tenant-scoped; organization_id is derived from JWT,
never accepted from the client.

Permission gates:
  DDOS_READ              — all read endpoints (GET)
  DDOS_MANAGE            — resource/policy management (POST, PUT, DELETE)
  DDOS_MITIGATION_APPROVE — mitigation approve/reject actions
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/ddos")


# ── Pydantic request/response models ─────────────────────────────────────────


class CreateResourceRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field("", max_length=1000)
    scope_type: str = Field("any")
    scope_value: str | None = None
    criticality: str = Field("MEDIUM")
    monitored_ports: list[int] | None = None


class UpsertPolicyRequest(BaseModel):
    enabled: bool = True
    profile: str = Field("BALANCED")
    static_bps_threshold: float | None = None
    static_pps_threshold: float | None = None
    static_fps_threshold: float | None = None
    window_seconds: int = Field(60, ge=30, le=3600)
    min_breach_windows: int = Field(1, ge=1, le=10)
    quiet_period_windows: int = Field(3, ge=1, le=20)
    mitigation_mode: str = Field("RECOMMEND_ONLY")


class CloseIncidentRequest(BaseModel):
    reason: str = Field("", max_length=500)


class MitigationActionRequest(BaseModel):
    reason: str = Field("", max_length=500)


# ── Dependency helpers ────────────────────────────────────────────────────────


def _get_session_factory() -> Any:
    from redforge.api.dependencies import _session_factory
    return _session_factory()


async def _resource_svc(session_factory: Any = Depends(_get_session_factory)) -> Any:

    from redforge.application.ddos.resource_service import DDoSResourceService

    async with session_factory() as session, session.begin():
        yield DDoSResourceService(session)


async def _incident_svc(session_factory: Any = Depends(_get_session_factory)) -> Any:
    from redforge.application.ddos.incident_service import DDoSIncidentService

    async with session_factory() as session, session.begin():
        yield DDoSIncidentService(session)


# ── Protected Resource Endpoints ──────────────────────────────────────────────


@router.get("/resources")
async def list_protected_resources(
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_READ))],
    session_factory: Any = Depends(_get_session_factory),
) -> list[dict[str, Any]]:
    from redforge.application.ddos.resource_service import DDoSResourceService

    async with session_factory() as session, session.begin():
        svc = DDoSResourceService(session)
        resources = await svc.list_resources(tenant.organization_id)
    return [asdict(r) for r in resources]


@router.post("/resources", status_code=201)
async def create_protected_resource(
    body: CreateResourceRequest,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_MANAGE))],
    session_factory: Any = Depends(_get_session_factory),
) -> dict[str, Any]:
    from redforge.application.ddos.resource_service import DDoSResourceService

    async with session_factory() as session, session.begin():
        svc = DDoSResourceService(session)
        resource = await svc.create_resource(
            organization_id=tenant.organization_id,
            actor_id=tenant.user_id,
            name=body.name,
            description=body.description,
            scope_type=body.scope_type,
            scope_value=body.scope_value,
            criticality=body.criticality,
            monitored_ports=body.monitored_ports,
        )
    return asdict(resource)


@router.get("/resources/{resource_id}")
async def get_protected_resource(
    resource_id: str,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_READ))],
    session_factory: Any = Depends(_get_session_factory),
) -> dict[str, Any]:
    from redforge.application.ddos.resource_service import DDoSResourceService

    async with session_factory() as session, session.begin():
        svc = DDoSResourceService(session)
        resource = await svc.get_resource(tenant.organization_id, resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="Protected resource not found")
    return asdict(resource)


@router.delete("/resources/{resource_id}", status_code=204)
async def delete_protected_resource(
    resource_id: str,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_MANAGE))],
    session_factory: Any = Depends(_get_session_factory),
) -> None:
    from redforge.application.ddos.resource_service import DDoSResourceService

    async with session_factory() as session, session.begin():
        svc = DDoSResourceService(session)
        deleted = await svc.delete_resource(tenant.organization_id, resource_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Protected resource not found")


# ── Detection Policy Endpoints ────────────────────────────────────────────────


@router.get("/resources/{resource_id}/policy")
async def get_detection_policy(
    resource_id: str,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_READ))],
    session_factory: Any = Depends(_get_session_factory),
) -> dict[str, Any]:
    from redforge.application.ddos.resource_service import DDoSResourceService

    async with session_factory() as session, session.begin():
        svc = DDoSResourceService(session)
        policy = await svc.get_policy(tenant.organization_id, resource_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Detection policy not found")
    return asdict(policy)


@router.put("/resources/{resource_id}/policy", status_code=200)
async def upsert_detection_policy(
    resource_id: str,
    body: UpsertPolicyRequest,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_MANAGE))],
    session_factory: Any = Depends(_get_session_factory),
) -> dict[str, Any]:
    from redforge.application.ddos.resource_service import DDoSResourceService

    async with session_factory() as session, session.begin():
        svc = DDoSResourceService(session)
        # Verify resource exists and belongs to org
        resource = await svc.get_resource(tenant.organization_id, resource_id)
        if resource is None:
            raise HTTPException(status_code=404, detail="Protected resource not found")
        policy = await svc.upsert_policy(
            organization_id=tenant.organization_id,
            resource_id=resource_id,
            actor_id=tenant.user_id,
            enabled=body.enabled,
            profile=body.profile,
            static_bps_threshold=body.static_bps_threshold,
            static_pps_threshold=body.static_pps_threshold,
            static_fps_threshold=body.static_fps_threshold,
            window_seconds=body.window_seconds,
            min_breach_windows=body.min_breach_windows,
            quiet_period_windows=body.quiet_period_windows,
            mitigation_mode=body.mitigation_mode,
        )
    return asdict(policy)


# ── Incident Endpoints ────────────────────────────────────────────────────────


@router.get("/incidents")
async def list_incidents(
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_READ))],
    status: list[str] = Query(default=[]),
    resource_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session_factory: Any = Depends(_get_session_factory),
) -> list[dict[str, Any]]:
    from redforge.application.ddos.incident_service import DDoSIncidentService

    async with session_factory() as session, session.begin():
        svc = DDoSIncidentService(session)
        incidents = await svc.list_incidents(
            organization_id=tenant.organization_id,
            status_filter=status or None,
            resource_id=resource_id,
            limit=limit,
            offset=offset,
        )
    return [asdict(i) for i in incidents]


@router.get("/incidents/active")
async def list_active_incidents(
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_READ))],
    session_factory: Any = Depends(_get_session_factory),
) -> list[dict[str, Any]]:
    from redforge.application.ddos.incident_service import DDoSIncidentService

    async with session_factory() as session, session.begin():
        svc = DDoSIncidentService(session)
        incidents = await svc.list_active_incidents(tenant.organization_id)
    return [asdict(i) for i in incidents]


@router.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_READ))],
    session_factory: Any = Depends(_get_session_factory),
) -> dict[str, Any]:
    from redforge.application.ddos.incident_service import DDoSIncidentService

    async with session_factory() as session, session.begin():
        svc = DDoSIncidentService(session)
        incident = await svc.get_incident(tenant.organization_id, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return asdict(incident)


@router.post("/incidents/{incident_id}/close", status_code=200)
async def close_incident(
    incident_id: str,
    body: CloseIncidentRequest,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_MANAGE))],
    session_factory: Any = Depends(_get_session_factory),
) -> dict[str, Any]:
    from redforge.application.ddos.incident_service import DDoSIncidentService

    async with session_factory() as session, session.begin():
        svc = DDoSIncidentService(session)
        incident = await svc.close_incident(
            organization_id=tenant.organization_id,
            incident_id=incident_id,
            actor_id=tenant.user_id,
        )
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return asdict(incident)


@router.get("/incidents/{incident_id}/timeline")
async def get_incident_timeline(
    incident_id: str,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_READ))],
    session_factory: Any = Depends(_get_session_factory),
) -> list[dict[str, Any]]:
    from redforge.application.ddos.incident_service import DDoSIncidentService

    async with session_factory() as session, session.begin():
        svc = DDoSIncidentService(session)
        # Verify incident belongs to org
        incident = await svc.get_incident(tenant.organization_id, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        timeline = await svc.get_timeline(tenant.organization_id, incident_id)
    return [asdict(e) for e in timeline]


@router.get("/incidents/{incident_id}/mitigation")
async def list_incident_recommendations(
    incident_id: str,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_READ))],
    session_factory: Any = Depends(_get_session_factory),
) -> list[dict[str, Any]]:
    from redforge.application.ddos.incident_service import DDoSIncidentService

    async with session_factory() as session, session.begin():
        svc = DDoSIncidentService(session)
        recs = await svc.list_recommendations(tenant.organization_id, incident_id)
    return [asdict(r) for r in recs]


# ── Mitigation Recommendation Approval ───────────────────────────────────────


@router.get("/mitigation/pending")
async def list_pending_recommendations(
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_READ))],
    session_factory: Any = Depends(_get_session_factory),
) -> list[dict[str, Any]]:
    from redforge.application.ddos.incident_service import DDoSIncidentService

    async with session_factory() as session, session.begin():
        svc = DDoSIncidentService(session)
        recs = await svc.list_pending_recommendations(tenant.organization_id)
    return [asdict(r) for r in recs]


@router.post("/mitigation/{recommendation_id}/approve", status_code=200)
async def approve_recommendation(
    recommendation_id: str,
    tenant: Annotated[
        TenantContext, Depends(require_permission(Permission.DDOS_MITIGATION_APPROVE))
    ],
    session_factory: Any = Depends(_get_session_factory),
) -> dict[str, Any]:
    from redforge.application.ddos.incident_service import DDoSIncidentService

    async with session_factory() as session, session.begin():
        svc = DDoSIncidentService(session)
        rec = await svc.approve_recommendation(
            organization_id=tenant.organization_id,
            rec_id=recommendation_id,
            actor_id=tenant.user_id,
        )
    if rec is None:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return asdict(rec)


@router.post("/mitigation/{recommendation_id}/reject", status_code=200)
async def reject_recommendation(
    recommendation_id: str,
    body: MitigationActionRequest,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_MANAGE))],
    session_factory: Any = Depends(_get_session_factory),
) -> dict[str, Any]:
    from redforge.application.ddos.incident_service import DDoSIncidentService

    async with session_factory() as session, session.begin():
        svc = DDoSIncidentService(session)
        rec = await svc.reject_recommendation(
            organization_id=tenant.organization_id,
            rec_id=recommendation_id,
            actor_id=tenant.user_id,
            reason=body.reason,
        )
    if rec is None:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return asdict(rec)


# ── Traffic / Window Analytics ────────────────────────────────────────────────


@router.get("/traffic/windows")
async def list_observation_windows(
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_READ))],
    resource_id: str = Query(...),
    hours: int = Query(default=1, ge=1, le=72),
    session_factory: Any = Depends(_get_session_factory),
) -> list[dict[str, Any]]:
    from datetime import UTC, timedelta

    from redforge.infrastructure.database.repositories.ddos.window_repository import (
        SqlAlchemyObservationWindowRepository,
    )
    since = __import__("datetime").datetime.now(UTC) - timedelta(hours=hours)

    async with session_factory() as session, session.begin():
        repo = SqlAlchemyObservationWindowRepository(session)
        windows = await repo.list_for_resource(
            organization_id=tenant.organization_id,
            resource_id=resource_id,
            since=since,
            limit=min(hours * 60 + 10, 5000),
        )
    return [
        {
            "id": w.id,
            "resource_id": w.resource_id,
            "window_start_ts": w.window_start_ts.isoformat(),
            "window_end_ts": w.window_end_ts.isoformat(),
            "event_count": w.event_count,
            "total_bytes_in": w.total_bytes_in,
            "total_bytes_out": w.total_bytes_out,
            "unique_src_ips": w.unique_src_ips,
            "protocol_counts": w.protocol_counts,
            "alert_count": w.alert_count,
            "detection_fired": w.detection_fired,
            "severity": w.severity,
            "classification": w.classification,
            "incident_id": w.incident_id,
        }
        for w in windows
    ]


# ── Posture Summary ───────────────────────────────────────────────────────────


@router.get("/posture")
async def get_ddos_posture(
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_READ))],
    session_factory: Any = Depends(_get_session_factory),
) -> dict[str, Any]:
    """Return org-level DDoS posture: active incidents, resource count, recent windows."""
    from redforge.application.ddos.incident_service import DDoSIncidentService
    from redforge.application.ddos.resource_service import DDoSResourceService

    async with session_factory() as session, session.begin():
        res_svc = DDoSResourceService(session)
        inc_svc = DDoSIncidentService(session)

        resources = await res_svc.list_resources(tenant.organization_id)
        active_incidents = await inc_svc.list_active_incidents(tenant.organization_id)
        pending_recs = await inc_svc.list_pending_recommendations(tenant.organization_id)

    severity_counts: dict[str, int] = {}
    for inc in active_incidents:
        severity_counts[inc.severity] = severity_counts.get(inc.severity, 0) + 1

    return {
        "protected_resource_count": len(resources),
        "active_incident_count": len(active_incidents),
        "pending_recommendation_count": len(pending_recs),
        "active_incident_severity_counts": severity_counts,
        "active_incidents": [
            {
                "id": i.id,
                "resource_id": i.resource_id,
                "resource_name": i.resource_name,
                "status": i.status,
                "severity": i.severity,
                "classification": i.classification,
                "first_detected_at": i.first_detected_at,
            }
            for i in active_incidents
        ],
    }


# ── Worker Health ─────────────────────────────────────────────────────────────


@router.get("/worker/health")
async def get_worker_health(
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.DDOS_READ))],
    request: Any = None,
) -> dict[str, Any]:
    """Return DDoS detection worker stats from app state."""

    # Worker is stored on app.state by the startup lifecycle
    # Returns empty stats if worker not wired (test/development)
    worker = getattr(request.app.state, "ddos_detection_worker", None) if request else None
    if worker is None:
        return {"status": "not_configured", "stats": {}}
    return {"status": "running" if worker._running else "stopped", "stats": worker.stats()}
