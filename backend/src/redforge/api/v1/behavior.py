"""Behavioral Security NDR REST API — M20.

All routes are tenant-scoped; organization_id is derived from JWT.

Permission gates:
  BEHAVIOR_READ   — all read endpoints
  BEHAVIOR_MANAGE — close/acknowledge/assign detections
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/behavior")


# ── Request models ────────────────────────────────────────────────────────────


class CloseDetectionRequest(BaseModel):
    notes: str = Field("", max_length=1000)


# ── Dependency helpers ────────────────────────────────────────────────────────


def _get_session_factory() -> Any:
    from redforge.api.dependencies import _session_factory
    return _session_factory()


async def _detection_svc(session_factory: Any = Depends(_get_session_factory)) -> Any:
    from redforge.application.behavior.detection_service import BehaviorDetectionService

    async with session_factory() as session, session.begin():
        yield BehaviorDetectionService(session)


async def _det_repo(session_factory: Any = Depends(_get_session_factory)) -> Any:
    from redforge.infrastructure.database.repositories.behavior.detection_repository import (
        SqlAlchemyBehaviorBaselineRepository,
        SqlAlchemyBehaviorDetectionRepository,
    )

    async with session_factory() as session, session.begin():
        yield (
            SqlAlchemyBehaviorDetectionRepository(session),
            SqlAlchemyBehaviorBaselineRepository(session),
            session,
        )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/posture")
async def get_behavioral_posture(
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.BEHAVIOR_READ))],
    svc: Any = Depends(_detection_svc),
) -> dict[str, Any]:
    """Global behavioral security posture for the organization."""
    result: dict[str, Any] = await svc.get_posture(tenant.organization_id)
    return result


@router.get("/detections")
async def list_detections(
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.BEHAVIOR_READ))],
    status: str | None = Query(None),
    entity_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    svc: Any = Depends(_detection_svc),
) -> list[dict[str, Any]]:
    """List behavioral detections with optional filters."""
    from redforge.api.dependencies import _session_factory
    from redforge.infrastructure.database.repositories.behavior.detection_repository import (
        SqlAlchemyBehaviorDetectionRepository,
    )
    sf = _session_factory()
    async with sf() as session, session.begin():
        repo = SqlAlchemyBehaviorDetectionRepository(session)
        detections = await repo.list_detections(
            organization_id=tenant.organization_id,
            status=status,
            entity_id=entity_id,
            limit=limit,
            offset=offset,
        )
    return [_fmt_detection(d) for d in detections]


@router.get("/detections/{detection_id}")
async def get_detection(
    detection_id: str,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.BEHAVIOR_READ))],
    svc: Any = Depends(_detection_svc),
) -> dict[str, Any]:
    from redforge.api.dependencies import _session_factory
    from redforge.infrastructure.database.repositories.behavior.detection_repository import (
        SqlAlchemyBehaviorDetectionRepository,
    )
    sf = _session_factory()
    async with sf() as session, session.begin():
        repo = SqlAlchemyBehaviorDetectionRepository(session)
        detection = await repo.get_detection(tenant.organization_id, detection_id)
        if detection is None:
            raise HTTPException(status_code=404, detail="Detection not found")
        events = await repo.get_detection_events(tenant.organization_id, detection_id)

    return {
        **_fmt_detection(detection),
        "timeline": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "detail": e.detail,
                "actor_user_id": e.actor_user_id,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
    }


@router.post("/detections/{detection_id}/close", status_code=200)
async def close_detection(
    detection_id: str,
    body: CloseDetectionRequest,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.BEHAVIOR_MANAGE))],
) -> dict[str, Any]:
    from redforge.api.dependencies import _session_factory
    from redforge.infrastructure.database.repositories.behavior.detection_repository import (
        SqlAlchemyBehaviorDetectionRepository,
    )
    sf = _session_factory()
    async with sf() as session, session.begin():
        repo = SqlAlchemyBehaviorDetectionRepository(session)
        changed = await repo.close_detection(
            organization_id=tenant.organization_id,
            detection_id=detection_id,
            actor_user_id=tenant.user_id,
            notes=body.notes,
        )
    if not changed:
        raise HTTPException(status_code=404, detail="Detection not found or already closed")
    return {"status": "closed"}


@router.get("/entities")
async def list_entities(
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.BEHAVIOR_READ))],
    limit: int = Query(200, ge=1, le=500),
) -> list[dict[str, Any]]:
    """List monitored entities with risk summary."""
    from redforge.api.dependencies import _session_factory
    from redforge.infrastructure.database.repositories.behavior.detection_repository import (
        SqlAlchemyBehaviorBaselineRepository,
        SqlAlchemyBehaviorDetectionRepository,
    )
    sf = _session_factory()
    async with sf() as session, session.begin():
        base_repo = SqlAlchemyBehaviorBaselineRepository(session)
        det_repo = SqlAlchemyBehaviorDetectionRepository(session)
        baselines = await base_repo.list_baselines(tenant.organization_id, limit=limit)
        open_detections = await det_repo.list_open_detections(
            tenant.organization_id, limit=500
        )

    # Build entity → active detection count map
    entity_det_counts: dict[str, list[Any]] = {}
    for d in open_detections:
        entity_det_counts.setdefault(d.entity_id, []).append(d)

    result = []
    for b in baselines:
        dets = entity_det_counts.get(b.entity_id, [])
        sevs = [d.severity for d in dets]
        risk = _compute_risk_level(sevs)
        result.append({
            "entity_id": b.entity_id,
            "entity_type": b.entity_type,
            "baseline_confidence": b.baseline_confidence,
            "window_count": b.window_count,
            "active_detections": len(dets),
            "risk_level": risk,
            "top_severity": (
                sevs[0] if sevs else None
            ),
            "updated_at": b.updated_at.isoformat(),
        })

    _sev_order: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    result.sort(key=lambda x: (
        _sev_order.get(str(x["risk_level"]), 5),
        -int(x["active_detections"] or 0),
    ))
    return result


@router.get("/entities/{entity_id}")
async def get_entity_behavior(
    entity_id: str,
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.BEHAVIOR_READ))],
) -> dict[str, Any]:
    """Get detailed behavior profile for one entity."""
    from redforge.api.dependencies import _session_factory
    from redforge.infrastructure.database.repositories.behavior.detection_repository import (
        SqlAlchemyBehaviorBaselineRepository,
        SqlAlchemyBehaviorDetectionRepository,
    )
    sf = _session_factory()
    async with sf() as session, session.begin():
        base_repo = SqlAlchemyBehaviorBaselineRepository(session)
        det_repo = SqlAlchemyBehaviorDetectionRepository(session)
        baseline = await base_repo.get_baseline(
            tenant.organization_id, "IP_ADDRESS", entity_id
        )
        observations = await base_repo.get_recent_observations(
            tenant.organization_id, entity_id, limit=20
        )
        detections = await det_repo.list_detections(
            tenant.organization_id, entity_id=entity_id, limit=20
        )

    if baseline is None:
        raise HTTPException(status_code=404, detail="Entity not found in behavior baseline")

    return {
        "entity_id": entity_id,
        "entity_type": baseline.entity_type,
        "baseline_confidence": baseline.baseline_confidence,
        "window_count": baseline.window_count,
        "p75_unique_dst_ips": baseline.p75_unique_dst_ips,
        "p75_bytes_out": baseline.p75_bytes_out,
        "p75_event_count": baseline.p75_event_count,
        "seen_dst_ip_count": len(baseline.seen_dst_ips or []),
        "detections": [_fmt_detection(d) for d in detections],
        "recent_observations": [
            {
                "window_start_ts": obs.window_start_ts.isoformat(),
                "window_end_ts": obs.window_end_ts.isoformat(),
                "event_count": obs.event_count,
                "unique_dst_ips": obs.unique_dst_ips,
                "unique_dst_ports": obs.unique_dst_ports,
                "total_bytes_out": obs.total_bytes_out,
            }
            for obs in observations
        ],
    }


@router.get("/network/relationships")
async def get_network_relationships(
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.BEHAVIOR_READ))],
    limit: int = Query(100, ge=1, le=500),
    hours: int = Query(24, ge=1, le=168),
) -> dict[str, Any]:
    """Recent communication relationships from telemetry."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import func, select

    from redforge.api.dependencies import _session_factory
    from redforge.infrastructure.database.models.telemetry import TelemetryEventModel

    sf = _session_factory()
    since = datetime.now(UTC) - timedelta(hours=hours)

    async with sf() as session, session.begin():
        result = await session.execute(
            select(
                TelemetryEventModel.src_ip,
                TelemetryEventModel.dst_ip,
                TelemetryEventModel.dst_port,
                TelemetryEventModel.protocol,
                func.count(TelemetryEventModel.id).label("event_count"),
                func.sum(TelemetryEventModel.bytes_out).label("total_bytes_out"),
                func.max(TelemetryEventModel.event_ts).label("last_seen"),
            ).where(
                TelemetryEventModel.organization_id == tenant.organization_id,
                TelemetryEventModel.event_ts >= since,
                TelemetryEventModel.src_ip.is_not(None),
                TelemetryEventModel.dst_ip.is_not(None),
            ).group_by(
                TelemetryEventModel.src_ip,
                TelemetryEventModel.dst_ip,
                TelemetryEventModel.dst_port,
                TelemetryEventModel.protocol,
            ).order_by(func.count(TelemetryEventModel.id).desc())
            .limit(limit)
        )
        rows = result.all()

    edges = []
    for row in rows:
        from redforge.domain.behavior.value_objects import is_rfc1918
        src, dst = row.src_ip, row.dst_ip
        relationship_type = "OBSERVED"
        if src and dst and is_rfc1918(src) and is_rfc1918(dst):
            relationship_type = "INTERNAL"

        edges.append({
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": row.dst_port,
            "protocol": row.protocol,
            "event_count": row.event_count,
            "total_bytes_out": int(row.total_bytes_out) if row.total_bytes_out else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "relationship_type": relationship_type,
        })

    return {"edges": edges, "hours": hours, "total": len(edges)}


@router.get("/health")
async def behavior_health(
    tenant: Annotated[TenantContext, Depends(require_permission(Permission.BEHAVIOR_READ))],
) -> dict[str, Any]:
    """Behavioral analysis subsystem health."""
    from redforge.api.dependencies import _session_factory
    from redforge.infrastructure.database.repositories.behavior.detection_repository import (
        SqlAlchemyBehaviorBaselineRepository,
        SqlAlchemyBehaviorDetectionRepository,
    )
    sf = _session_factory()
    async with sf() as session, session.begin():
        base_repo = SqlAlchemyBehaviorBaselineRepository(session)
        det_repo = SqlAlchemyBehaviorDetectionRepository(session)
        baselines = await base_repo.list_baselines(tenant.organization_id, limit=1000)
        severity_counts = await det_repo.count_active_by_severity(tenant.organization_id)

    from redforge.domain.behavior.value_objects import BaselineConfidence
    established = sum(
        1 for b in baselines if b.baseline_confidence == BaselineConfidence.ESTABLISHED
    )
    cold_start = sum(
        1 for b in baselines if b.baseline_confidence == BaselineConfidence.COLD_START
    )

    return {
        "monitored_entities": len(baselines),
        "established_baselines": established,
        "cold_start_entities": cold_start,
        "active_detections": sum(severity_counts.values()),
        "severity_breakdown": severity_counts,
        "supported_detections": [
            "NEW_DESTINATION",
            "RARE_DESTINATION",
            "HIGH_FAN_OUT",
            "PORT_SCAN_SUSPECTED",
            "BEACONING_SUSPECTED",
            "ABNORMAL_OUTBOUND_TRANSFER",
            "UNUSUAL_EAST_WEST",
            "UNUSUAL_SERVICE_ACCESS",
        ],
        "unsupported_detections": [
            "user_authentication_anomalies: no auth events in telemetry_events",
            "impossible_travel: no session geo data",
            "failed_connection_ratio: no TCP state machine data",
            "lateral_movement_confirmed: requires host-level evidence",
        ],
    }


# ── Helpers ───────────────────────────────────────────────────────────────────


def _fmt_detection(d: Any) -> dict[str, Any]:
    return {
        "id": d.id,
        "entity_id": d.entity_id,
        "entity_type": d.entity_type,
        "detection_type": d.detection_type,
        "status": d.status,
        "severity": d.severity,
        "detected_at": d.detected_at.isoformat(),
        "last_seen_at": d.last_seen_at.isoformat(),
        "observation_count": d.observation_count,
        "secondary_entity_id": d.secondary_entity_id,
        "evidence": d.evidence,
        "notes": d.notes,
    }


def _compute_risk_level(severities: list[str]) -> str:
    if not severities:
        return "NONE"
    sev_set = set(severities)
    if "CRITICAL" in sev_set:
        return "CRITICAL"
    if "HIGH" in sev_set:
        return "HIGH"
    if "MEDIUM" in sev_set:
        return "MEDIUM"
    return "LOW"
