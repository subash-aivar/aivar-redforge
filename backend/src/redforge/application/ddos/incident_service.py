"""DDoS incident correlation and lifecycle service — M19.

Correlates successive detection windows into a continuing incident,
manages state transitions, and appends timeline events.

State machine (all transitions are deterministic and logged):
  DETECTED → ACTIVE:      detection confirms (min_breach_windows met)
  ACTIVE → ESCALATED:     severity worsens OR 3+ resources affected
  ACTIVE/ESCALATED → MITIGATING: mitigation approved + executing
  MITIGATING → MONITORING: traffic trending toward baseline
  MONITORING → RESOLVED:  quiet_period_windows consecutive clean windows
  RESOLVED → ACTIVE:      recurrence detected
  RESOLVED/MONITORING → CLOSED: operator closes explicitly
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import text
from ulid import ULID

from redforge.domain.ddos.detection import DetectionResult
from redforge.domain.ddos.value_objects import IncidentSeverity, IncidentStatus

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _advisory_lock_key(organization_id: str, resource_id: str) -> int:
    """Stable 32-bit advisory lock key for a (org, resource) pair.

    Uses SHA-256 of the composite key so the value is deterministic
    across Python processes and replicas (hash() is randomized per process).
    pg_advisory_xact_lock accepts a 64-bit signed integer; we use the
    first 4 bytes interpreted as an unsigned int (always positive, fits in int4).
    """
    digest = hashlib.sha256(
        f"ddos_incident:{organization_id}:{resource_id}".encode()
    ).digest()
    return int(struct.unpack(">I", digest[:4])[0])


@dataclass(slots=True)
class IncidentDTO:
    id: str
    resource_id: str
    resource_name: str
    status: str
    severity: str
    classification: str
    first_detected_at: str
    last_updated_at: str
    peak_at: str | None
    resolved_at: str | None
    peak_bytes_per_second: float | None
    peak_packets_per_second: float | None
    peak_flows_per_second: float | None
    peak_unique_src_ips: int | None
    peak_deviation_multiplier: float | None
    consecutive_quiet_windows: int
    opening_evidence: dict[str, Any]
    latest_evidence: dict[str, Any]


@dataclass(slots=True)
class IncidentTimelineEventDTO:
    id: str
    event_type: str
    occurred_at: str
    description: str
    payload: dict[str, Any]
    actor_id: str | None


@dataclass(slots=True)
class MitigationRecommendationDTO:
    id: str
    incident_id: str
    recommendation_type: str
    description: str
    recommendation_detail: dict[str, Any]
    approval_status: str
    approved_by: str | None
    approved_at: str | None
    rejected_by: str | None
    rejection_reason: str | None
    execution_status: str
    executed_at: str | None
    provider_type: str | None
    expires_at: str | None
    created_at: str


def _detection_to_evidence(result: DetectionResult) -> dict[str, Any]:
    """Serialize a DetectionResult to a JSON-serializable evidence dict."""
    return {
        "is_attack": result.is_attack,
        "severity": result.severity.value if result.severity else None,
        "classification": result.classification.value if result.classification else None,
        "primary_deviation": result.primary_deviation,
        "matched_signals": [
            {
                "name": s.name,
                "threshold": s.threshold,
                "observed": s.observed,
                "deviation_multiplier": s.deviation_multiplier,
                "baseline_source": s.baseline_source,
                "detail": s.detail,
            }
            for s in result.matched_signals
        ],
        "missing_evidence": result.missing_evidence,
        "baseline": {
            "confidence": result.baseline.confidence.value,
            "window_count": result.baseline.window_count,
            "p75_bytes_per_second": result.baseline.p75_bytes_per_second,
            "p75_packets_per_second": result.baseline.p75_packets_per_second,
            "p75_flows_per_second": result.baseline.p75_flows_per_second,
            "p75_unique_src_ips": result.baseline.p75_unique_src_ips,
        },
        "metrics": {
            "window_start_ts": result.metrics.window_start_ts,
            "window_end_ts": result.metrics.window_end_ts,
            "event_count": result.metrics.event_count,
            "unique_src_ips": result.metrics.unique_src_ips,
            "bytes_per_second": result.metrics.bytes_per_second,
            "packets_per_second": result.metrics.packets_per_second,
            "flows_per_second": result.metrics.flows_per_second,
            "protocol_counts": result.metrics.protocol_counts,
        },
    }


class DDoSIncidentService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def open_or_update_incident(
        self,
        organization_id: str,
        resource_id: str,
        resource_name: str,
        detection: DetectionResult,
        policy_quiet_period: int = 3,
    ) -> IncidentDTO:
        """Correlate a detection into an existing incident or open a new one.

        If an open incident exists for this resource, update its metrics,
        reset the quiet counter, escalate severity if needed, and append
        a timeline event. Otherwise open a new DETECTED incident.
        """
        from redforge.infrastructure.database.models.ddos import (
            DDoSIncidentEventModel,
            DDoSIncidentModel,
        )
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyDDoSIncidentEventRepository,
            SqlAlchemyDDoSIncidentRepository,
        )

        repo = SqlAlchemyDDoSIncidentRepository(self._session)
        event_repo = SqlAlchemyDDoSIncidentEventRepository(self._session)

        now = datetime.now(UTC)
        evidence = _detection_to_evidence(detection)
        severity_str = (
            detection.severity.value if detection.severity else IncidentSeverity.LOW.value
        )
        classification_str = (
            detection.classification.value
            if detection.classification
            else "UNCLASSIFIED_DDOS_SUSPECTED"
        )

        # Acquire a PostgreSQL advisory transaction lock scoped to this (org, resource) pair.
        # This serializes concurrent callers (across replicas, workers, and retries) into a
        # queue so the read-then-insert is safe. The lock is released automatically on
        # commit or rollback. The partial unique index on ddos_incidents (migration 0032)
        # is the database-level safety net if the lock is bypassed (e.g. direct SQL).
        lock_key = _advisory_lock_key(organization_id, resource_id)
        await self._session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key}
        )

        existing = await repo.get_open_for_resource(organization_id, resource_id)

        if existing is not None:
            # Update metrics — best-effort, no versioning needed
            bps = detection.metrics.bytes_per_second
            pps = detection.metrics.packets_per_second
            fps = detection.metrics.flows_per_second
            deviation = detection.primary_deviation

            metric_updates: dict[str, Any] = {"latest_evidence": evidence}
            escalated = False

            # Update peaks
            if bps is not None and (
                existing.peak_bytes_per_second is None or bps > existing.peak_bytes_per_second
            ):
                metric_updates["peak_bytes_per_second"] = bps
                metric_updates["peak_at"] = now
            if pps is not None and (
                existing.peak_packets_per_second is None or pps > existing.peak_packets_per_second
            ):
                metric_updates["peak_packets_per_second"] = pps
            if (
                existing.peak_flows_per_second is None
                or fps > (existing.peak_flows_per_second or 0)
            ):
                metric_updates["peak_flows_per_second"] = fps
            if (
                existing.peak_unique_src_ips is None
                or detection.metrics.unique_src_ips > (existing.peak_unique_src_ips or 0)
            ):
                metric_updates["peak_unique_src_ips"] = detection.metrics.unique_src_ips
            if (
                existing.peak_deviation_multiplier is None
                or deviation > (existing.peak_deviation_multiplier or 0)
            ):
                metric_updates["peak_deviation_multiplier"] = deviation

            await repo.update_metrics(organization_id, existing.id, metric_updates)
            await repo.reset_quiet_windows(organization_id, existing.id)

            # Severity escalation (never downgrade during an open incident)
            severity_order = [
                s.value for s in [
                    IncidentSeverity.LOW, IncidentSeverity.MEDIUM,
                    IncidentSeverity.HIGH, IncidentSeverity.CRITICAL,
                ]
            ]
            current_idx = (
                severity_order.index(existing.severity)
                if existing.severity in severity_order else 0
            )
            new_idx = severity_order.index(severity_str) if severity_str in severity_order else 0
            if new_idx > current_idx:
                escalated = True
                # Transition to ESCALATED status for severity bump
                await repo.update_status(
                    organization_id, existing.id, "ESCALATED", existing.version,
                    updates={"severity": severity_str, "classification": classification_str},
                )
                await event_repo.append(DDoSIncidentEventModel(
                    id=str(ULID()),
                    organization_id=organization_id,
                    incident_id=existing.id,
                    event_type="severity_escalated",
                    occurred_at=now,
                    description=f"Severity escalated from {existing.severity} to {severity_str}",
                    payload={
                        "old_severity": existing.severity,
                        "new_severity": severity_str,
                        "evidence": evidence,
                    },
                ))

            if not escalated and existing.status == "DETECTED":
                # Transition DETECTED → ACTIVE on first confirmation
                await repo.update_status(
                    organization_id, existing.id, "ACTIVE", existing.version,
                )
                await event_repo.append(DDoSIncidentEventModel(
                    id=str(ULID()),
                    organization_id=organization_id,
                    incident_id=existing.id,
                    event_type="detection_confirmed",
                    occurred_at=now,
                    description="Attack confirmed — transitioning DETECTED → ACTIVE",
                    payload={"evidence": evidence},
                ))

            refreshed = await repo.get_by_id(organization_id, existing.id)
            return self._to_dto(refreshed)
        # Open new incident
        incident_id = str(ULID())
        bps = detection.metrics.bytes_per_second
        pps = detection.metrics.packets_per_second

        model = DDoSIncidentModel(
            id=incident_id,
            organization_id=organization_id,
            resource_id=resource_id,
            resource_name=resource_name,
            status=IncidentStatus.DETECTED.value,
            severity=severity_str,
            classification=classification_str,
            first_detected_at=now,
            last_updated_at=now,
            peak_at=now,
            peak_bytes_per_second=bps,
            peak_packets_per_second=pps,
            peak_flows_per_second=detection.metrics.flows_per_second,
            peak_unique_src_ips=detection.metrics.unique_src_ips,
            peak_deviation_multiplier=detection.primary_deviation,
            opening_evidence=evidence,
            latest_evidence=evidence,
            consecutive_quiet_windows=0,
            version=1,
        )
        created = await repo.create(model)

        await event_repo.append(DDoSIncidentEventModel(
            id=str(ULID()),
            organization_id=organization_id,
            incident_id=created.id,
            event_type="detection_opened",
            occurred_at=now,
            description=f"DDoS incident opened — {classification_str} ({severity_str})",
            payload={"evidence": evidence},
        ))

        return self._to_dto(created)

    async def record_quiet_window(
        self,
        organization_id: str,
        incident_id: str,
        required_quiet_windows: int,
    ) -> bool:
        """Record a quiet window. Returns True if incident transitioned to RESOLVED."""
        from redforge.infrastructure.database.models.ddos import DDoSIncidentEventModel
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyDDoSIncidentEventRepository,
            SqlAlchemyDDoSIncidentRepository,
        )

        repo = SqlAlchemyDDoSIncidentRepository(self._session)
        event_repo = SqlAlchemyDDoSIncidentEventRepository(self._session)
        now = datetime.now(UTC)

        incident = await repo.get_by_id(organization_id, incident_id)
        if incident is None or incident.status in ("RESOLVED", "CLOSED"):
            return False

        # Transition to MONITORING if not already
        if incident.status not in ("MONITORING",):
            await repo.update_status(
                organization_id, incident_id, "MONITORING", incident.version,
            )
            await event_repo.append(DDoSIncidentEventModel(
                id=str(ULID()),
                organization_id=organization_id,
                incident_id=incident_id,
                event_type="monitoring_started",
                occurred_at=now,
                description="Traffic returning toward baseline — monitoring for recovery",
                payload={},
            ))

        new_count = await repo.increment_quiet_windows(organization_id, incident_id)
        if new_count >= required_quiet_windows:
            # Resolve the incident
            refreshed = await repo.get_by_id(organization_id, incident_id)
            if refreshed is None:
                return False
            await repo.update_status(
                organization_id, incident_id, "RESOLVED", refreshed.version,
                updates={"resolved_at": now},
            )
            await event_repo.append(DDoSIncidentEventModel(
                id=str(ULID()),
                organization_id=organization_id,
                incident_id=incident_id,
                event_type="incident_resolved",
                occurred_at=now,
                description=f"Incident resolved — {new_count} consecutive quiet windows observed",
                payload={"quiet_windows": new_count},
            ))
            return True

        return False

    async def close_incident(
        self,
        organization_id: str,
        incident_id: str,
        actor_id: str,
    ) -> IncidentDTO | None:
        from redforge.infrastructure.database.models.ddos import DDoSIncidentEventModel
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyDDoSIncidentEventRepository,
            SqlAlchemyDDoSIncidentRepository,
        )

        repo = SqlAlchemyDDoSIncidentRepository(self._session)
        event_repo = SqlAlchemyDDoSIncidentEventRepository(self._session)
        now = datetime.now(UTC)

        incident = await repo.get_by_id(organization_id, incident_id)
        if incident is None:
            return None
        if incident.status == "CLOSED":
            return self._to_dto(incident)

        await repo.update_status(
            organization_id, incident_id, "CLOSED", incident.version,
            updates={"resolved_at": incident.resolved_at or now},
        )
        await event_repo.append(DDoSIncidentEventModel(
            id=str(ULID()),
            organization_id=organization_id,
            incident_id=incident_id,
            event_type="incident_closed",
            occurred_at=now,
            description="Incident closed by operator",
            payload={"actor_id": actor_id},
            actor_id=actor_id,
        ))

        refreshed = await repo.get_by_id(organization_id, incident_id)
        return self._to_dto(refreshed)
    async def get_incident(
        self, organization_id: str, incident_id: str
    ) -> IncidentDTO | None:
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyDDoSIncidentRepository,
        )

        repo = SqlAlchemyDDoSIncidentRepository(self._session)
        inc = await repo.get_by_id(organization_id, incident_id)
        return self._to_dto(inc) if inc else None

    async def list_incidents(
        self,
        organization_id: str,
        status_filter: list[str] | None = None,
        resource_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IncidentDTO]:
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyDDoSIncidentRepository,
        )

        repo = SqlAlchemyDDoSIncidentRepository(self._session)
        incidents = await repo.list_for_org(
            organization_id, status_filter=status_filter,
            resource_id=resource_id, limit=limit, offset=offset,
        )
        return [self._to_dto(i) for i in incidents]

    async def list_active_incidents(
        self, organization_id: str
    ) -> list[IncidentDTO]:
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyDDoSIncidentRepository,
        )

        repo = SqlAlchemyDDoSIncidentRepository(self._session)
        incidents = await repo.list_active_for_org(organization_id)
        return [self._to_dto(i) for i in incidents]

    async def get_timeline(
        self, organization_id: str, incident_id: str
    ) -> list[IncidentTimelineEventDTO]:
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyDDoSIncidentEventRepository,
        )

        repo = SqlAlchemyDDoSIncidentEventRepository(self._session)
        events = await repo.list_for_incident(organization_id, incident_id)
        return [
            IncidentTimelineEventDTO(
                id=e.id,
                event_type=e.event_type,
                occurred_at=e.occurred_at.isoformat(),
                description=e.description,
                payload=e.payload,
                actor_id=e.actor_id,
            )
            for e in events
        ]

    async def create_recommendation(
        self,
        organization_id: str,
        incident_id: str,
        recommendation_type: str,
        description: str,
        detail: dict[str, Any],
    ) -> MitigationRecommendationDTO:
        from redforge.infrastructure.database.models.ddos import (
            DDoSMitigationRecommendationModel,
        )
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyMitigationRecommendationRepository,
        )

        now = datetime.now(UTC)
        model = DDoSMitigationRecommendationModel(
            id=str(ULID()),
            organization_id=organization_id,
            incident_id=incident_id,
            recommendation_type=recommendation_type,
            description=description,
            recommendation_detail=detail,
            approval_status="PENDING",
            execution_status="NOT_STARTED",
            provider_type=None,  # NOT CONFIGURED until a provider adapter is wired
            created_at=now,
            updated_at=now,
        )
        repo = SqlAlchemyMitigationRecommendationRepository(self._session)
        created = await repo.create(model)
        return self._rec_to_dto(created)

    async def approve_recommendation(
        self,
        organization_id: str,
        rec_id: str,
        actor_id: str,
    ) -> MitigationRecommendationDTO | None:
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyMitigationRecommendationRepository,
        )

        repo = SqlAlchemyMitigationRecommendationRepository(self._session)
        rec = await repo.approve(organization_id, rec_id, actor_id)
        return self._rec_to_dto(rec) if rec else None

    async def reject_recommendation(
        self,
        organization_id: str,
        rec_id: str,
        actor_id: str,
        reason: str,
    ) -> MitigationRecommendationDTO | None:
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyMitigationRecommendationRepository,
        )

        repo = SqlAlchemyMitigationRecommendationRepository(self._session)
        rec = await repo.reject(organization_id, rec_id, actor_id, reason)
        return self._rec_to_dto(rec) if rec else None

    async def list_recommendations(
        self, organization_id: str, incident_id: str
    ) -> list[MitigationRecommendationDTO]:
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyMitigationRecommendationRepository,
        )

        repo = SqlAlchemyMitigationRecommendationRepository(self._session)
        recs = await repo.list_for_incident(organization_id, incident_id)
        return [self._rec_to_dto(r) for r in recs]

    async def list_pending_recommendations(
        self, organization_id: str
    ) -> list[MitigationRecommendationDTO]:
        from redforge.infrastructure.database.repositories.ddos.incident_repository import (
            SqlAlchemyMitigationRecommendationRepository,
        )

        repo = SqlAlchemyMitigationRecommendationRepository(self._session)
        recs = await repo.list_pending_for_org(organization_id)
        return [self._rec_to_dto(r) for r in recs]

    @staticmethod
    def _to_dto(i: Any) -> IncidentDTO:
        return IncidentDTO(
            id=i.id,
            resource_id=i.resource_id,
            resource_name=i.resource_name,
            status=i.status,
            severity=i.severity,
            classification=i.classification,
            first_detected_at=i.first_detected_at.isoformat(),
            last_updated_at=i.last_updated_at.isoformat(),
            peak_at=i.peak_at.isoformat() if i.peak_at else None,
            resolved_at=i.resolved_at.isoformat() if i.resolved_at else None,
            peak_bytes_per_second=i.peak_bytes_per_second,
            peak_packets_per_second=i.peak_packets_per_second,
            peak_flows_per_second=i.peak_flows_per_second,
            peak_unique_src_ips=i.peak_unique_src_ips,
            peak_deviation_multiplier=i.peak_deviation_multiplier,
            consecutive_quiet_windows=i.consecutive_quiet_windows,
            opening_evidence=i.opening_evidence,
            latest_evidence=i.latest_evidence,
        )

    @staticmethod
    def _rec_to_dto(r: Any) -> MitigationRecommendationDTO:
        return MitigationRecommendationDTO(
            id=r.id,
            incident_id=r.incident_id,
            recommendation_type=r.recommendation_type,
            description=r.description,
            recommendation_detail=r.recommendation_detail,
            approval_status=r.approval_status,
            approved_by=r.approved_by,
            approved_at=r.approved_at.isoformat() if r.approved_at else None,
            rejected_by=r.rejected_by,
            rejection_reason=r.rejection_reason,
            execution_status=r.execution_status,
            executed_at=r.executed_at.isoformat() if r.executed_at else None,
            provider_type=r.provider_type,
            expires_at=r.expires_at.isoformat() if r.expires_at else None,
            created_at=r.created_at.isoformat(),
        )
