"""PostgreSQL repositories for the incident bounded context.

Each repository opens one session per call from an injected
async_sessionmaker rather than holding a single long-lived session. This
keeps the drop-in shape identical to the in-memory repositories they
replace — IncidentApplicationService is constructed once with concrete
repository instances (see infrastructure/container.py) rather than through
a per-request unit-of-work, and preserving that shape avoids touching the
application service's transaction assumptions.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import delete, select

from incident.domain.aggregates.containment_action import ContainmentAction
from incident.domain.aggregates.eradication_verification import EradicationVerification
from incident.domain.aggregates.incident import Incident, IncidentTag
from incident.domain.aggregates.recovery_milestone import RecoveryMilestone
from incident.domain.entities.communication_log_entry import IncidentCommunicationLogEntry
from incident.domain.entities.timeline_entry import IncidentTimelineEntry
from incident.domain.repositories.i_incident_repositories import (
    IContainmentActionRepository,
    IEradicationVerificationRepository,
    IIncidentCommunicationLogRepository,
    IIncidentRepository,
    IRecoveryMilestoneRepository,
)
from incident.domain.value_objects.enums import (
    CommunicationType,
    ContainmentActionStatus,
    ContainmentActionType,
    ContainmentAuthorizationLevel,
    EradicationVerificationStatus,
    IncidentPhase,
    IncidentSeverity,
    IncidentTriggerType,
    RecoveryMilestoneStatus,
    ResolutionType,
    SeverityClassificationMethod,
    TimelineEntryType,
)
from incident.domain.value_objects.identifiers import (
    CommunicationLogEntryId,
    ContainmentActionId,
    EradicationVerificationId,
    IncidentId,
    RecoveryMilestoneId,
    TenantId,
)
from incident.domain.value_objects.refs import (
    EradicationEvidenceRef,
    EscalatedFindingRef,
    ExposureScopeRef,
    InvestigationRef,
)
from incident.infrastructure.persistence.models import (
    ContainmentActionModel,
    EradicationVerificationModel,
    IncidentCommunicationLogEntryModel,
    IncidentModel,
    IncidentTagModel,
    IncidentTimelineEntryModel,
    RecoveryMilestoneModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_UNIX_EPOCH = datetime.fromtimestamp(0, tz=UTC)


# ── Incident ────────────────────────────────────────────────────────────────


def _finding_ref_to_dict(ref: EscalatedFindingRef | None) -> dict[str, object] | None:
    if ref is None:
        return None
    return {
        "finding_id": ref.finding_id,
        "severity": ref.severity,
        "asset_ref": ref.asset_ref,
        "rule_id": ref.rule_id,
        "detected_at": ref.detected_at.isoformat(),
        "escalated_by": ref.escalated_by,
    }


def _finding_ref_from_dict(data: dict[str, object] | None) -> EscalatedFindingRef | None:
    if data is None:
        return None
    from datetime import datetime as _dt

    return EscalatedFindingRef(
        finding_id=str(data["finding_id"]),
        severity=str(data["severity"]),
        asset_ref=str(data["asset_ref"]),
        rule_id=str(data["rule_id"]),
        detected_at=_dt.fromisoformat(str(data["detected_at"])),
        escalated_by=str(data["escalated_by"]),
    )


def _investigation_ref_to_dict(ref: InvestigationRef | None) -> dict[str, object] | None:
    if ref is None:
        return None
    return {
        "investigation_id": ref.investigation_id,
        "concluded_at": ref.concluded_at.isoformat() if ref.concluded_at else None,
        "conclusion": ref.conclusion,
    }


def _investigation_ref_from_dict(data: dict[str, object] | None) -> InvestigationRef | None:
    if data is None:
        return None
    from datetime import datetime as _dt

    concluded_at = data.get("concluded_at")
    return InvestigationRef(
        investigation_id=str(data["investigation_id"]),
        concluded_at=_dt.fromisoformat(str(concluded_at)) if concluded_at else None,
        conclusion=str(data["conclusion"]),
    )


def _exposure_refs_to_list(refs: list[ExposureScopeRef]) -> list[dict[str, object]]:
    return [
        {
            "asset_ref_id": r.asset_ref_id,
            "composite_score": r.composite_score,
            "assessed_at": r.assessed_at.isoformat(),
        }
        for r in refs
    ]


def _exposure_refs_from_list(data: list[dict[str, object]]) -> list[ExposureScopeRef]:
    from datetime import datetime as _dt

    return [
        ExposureScopeRef(
            asset_ref_id=str(item["asset_ref_id"]),
            composite_score=float(item["composite_score"]),  # type: ignore[arg-type]
            assessed_at=_dt.fromisoformat(str(item["assessed_at"])),
        )
        for item in data
    ]


def _incident_to_row(incident: Incident) -> IncidentModel:
    return IncidentModel(
        incident_id=incident.incident_id.value,
        tenant_id=incident.tenant_id.value,
        title=incident.title,
        description=incident.description,
        phase=incident.phase.value,
        severity=incident.severity.value,
        trigger_type=incident.trigger_type.value,
        classification_method=(
            incident.classification_method.value if incident.classification_method else None
        ),
        classified_at=incident.classified_at,
        contained_at=incident.contained_at,
        eradicated_at=incident.eradicated_at,
        recovered_at=incident.recovered_at,
        closed_at=incident.closed_at,
        resolution_type=incident.resolution_type.value if incident.resolution_type else None,
        version=incident.version,
        payload={
            "source_finding_ref": _finding_ref_to_dict(incident.source_finding_ref),
            "investigation_ref": _investigation_ref_to_dict(incident.investigation_ref),
            "exposure_scope_refs": _exposure_refs_to_list(incident.exposure_scope_refs),
            "force_close_justification": incident.force_close_justification,
        },
    )


def _row_to_incident(
    row: IncidentModel,
    timeline: list[IncidentTimelineEntry],
    tags: list[IncidentTag],
) -> Incident:
    payload = row.payload or {}
    return Incident(
        incident_id=IncidentId(row.incident_id),
        tenant_id=TenantId(row.tenant_id),
        title=row.title,
        description=row.description,
        phase=IncidentPhase(row.phase),
        severity=IncidentSeverity(row.severity),
        trigger_type=IncidentTriggerType(row.trigger_type),
        classification_method=(
            SeverityClassificationMethod(row.classification_method)
            if row.classification_method
            else None
        ),
        # Incident.__init__ takes created_at only to discard it immediately
        # (`del created_at` — see the aggregate); it isn't persisted as its
        # own column, so any timezone-aware value satisfies the signature.
        created_at=row.classified_at or row.contained_at or row.closed_at or _UNIX_EPOCH,
        source_finding_ref=_finding_ref_from_dict(payload.get("source_finding_ref")),
        investigation_ref=_investigation_ref_from_dict(payload.get("investigation_ref")),
        exposure_scope_refs=_exposure_refs_from_list(payload.get("exposure_scope_refs") or []),
        classified_at=row.classified_at,
        contained_at=row.contained_at,
        eradicated_at=row.eradicated_at,
        recovered_at=row.recovered_at,
        closed_at=row.closed_at,
        resolution_type=ResolutionType(row.resolution_type) if row.resolution_type else None,
        tags=tags,
        timeline=timeline,
        version=row.version,
        force_close_justification=payload.get("force_close_justification"),
    )


class PgIncidentRepository(IIncidentRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def _load_children(
        self, session: AsyncSession, tenant_id: TenantId, incident_id: IncidentId
    ) -> tuple[list[IncidentTimelineEntry], list[IncidentTag]]:
        timeline_rows = (
            await session.execute(
                select(IncidentTimelineEntryModel)
                .where(
                    IncidentTimelineEntryModel.tenant_id == tenant_id.value,
                    IncidentTimelineEntryModel.incident_id == incident_id.value,
                )
                .order_by(IncidentTimelineEntryModel.occurred_at)
            )
        ).scalars().all()
        timeline = [
            IncidentTimelineEntry(
                entry_id=t.entry_id,
                entry_type=TimelineEntryType(t.entry_type),
                summary=t.summary,
                actor=t.actor,
                occurred_at=t.occurred_at,
                details=dict(t.details or {}),
            )
            for t in timeline_rows
        ]
        tag_rows = (
            await session.execute(
                select(IncidentTagModel).where(
                    IncidentTagModel.tenant_id == tenant_id.value,
                    IncidentTagModel.incident_id == incident_id.value,
                )
            )
        ).scalars().all()
        tags = [IncidentTag(key=t.tag_key, value=t.tag_value) for t in tag_rows]
        return timeline, tags

    async def find_by_id(self, tenant_id: TenantId, incident_id: IncidentId) -> Incident | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(IncidentModel).where(
                        IncidentModel.tenant_id == tenant_id.value,
                        IncidentModel.incident_id == incident_id.value,
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            timeline, tags = await self._load_children(session, tenant_id, incident_id)
            return _row_to_incident(row, timeline, tags)

    async def find_active(
        self, tenant_id: TenantId, *, phase_filter: IncidentPhase | None = None
    ) -> list[Incident]:
        async with self._session_factory() as session:
            stmt = select(IncidentModel).where(
                IncidentModel.tenant_id == tenant_id.value,
                IncidentModel.phase != IncidentPhase.CLOSED.value,
            )
            if phase_filter is not None:
                stmt = stmt.where(IncidentModel.phase == phase_filter.value)
            rows = (await session.execute(stmt)).scalars().all()
            out: list[Incident] = []
            for row in rows:
                timeline, tags = await self._load_children(
                    session, tenant_id, IncidentId(row.incident_id)
                )
                out.append(_row_to_incident(row, timeline, tags))
            return out

    async def find_by_severity(
        self, tenant_id: TenantId, severity: IncidentSeverity
    ) -> list[Incident]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(IncidentModel).where(
                        IncidentModel.tenant_id == tenant_id.value,
                        IncidentModel.severity == severity.value,
                    )
                )
            ).scalars().all()
            out: list[Incident] = []
            for row in rows:
                timeline, tags = await self._load_children(
                    session, tenant_id, IncidentId(row.incident_id)
                )
                out.append(_row_to_incident(row, timeline, tags))
            return out

    async def find_classified_in_period(
        self, tenant_id: TenantId, start: datetime, end: datetime
    ) -> list[Incident]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(IncidentModel).where(
                        IncidentModel.tenant_id == tenant_id.value,
                        IncidentModel.classified_at.is_not(None),
                        IncidentModel.classified_at >= start,
                        IncidentModel.classified_at < end,
                    )
                )
            ).scalars().all()
            out: list[Incident] = []
            for row in rows:
                timeline, tags = await self._load_children(
                    session, tenant_id, IncidentId(row.incident_id)
                )
                out.append(_row_to_incident(row, timeline, tags))
            return out

    async def save(self, tenant_id: TenantId, incident: Incident) -> None:
        async with self._session_factory() as session:
            existing = (
                await session.execute(
                    select(IncidentModel.incident_id).where(
                        IncidentModel.tenant_id == tenant_id.value,
                        IncidentModel.incident_id == incident.incident_id.value,
                    )
                )
            ).scalar_one_or_none()

            row = _incident_to_row(incident)
            if existing is None:
                session.add(row)
            else:
                await session.merge(row)

            await session.execute(
                delete(IncidentTimelineEntryModel).where(
                    IncidentTimelineEntryModel.tenant_id == tenant_id.value,
                    IncidentTimelineEntryModel.incident_id == incident.incident_id.value,
                )
            )
            for entry in incident.timeline:
                session.add(
                    IncidentTimelineEntryModel(
                        entry_id=entry.entry_id,
                        tenant_id=tenant_id.value,
                        incident_id=incident.incident_id.value,
                        entry_type=entry.entry_type.value,
                        summary=entry.summary,
                        actor=entry.actor,
                        occurred_at=entry.occurred_at,
                        details=dict(entry.details),
                    )
                )

            await session.execute(
                delete(IncidentTagModel).where(
                    IncidentTagModel.tenant_id == tenant_id.value,
                    IncidentTagModel.incident_id == incident.incident_id.value,
                )
            )
            for tag in incident.tags:
                session.add(
                    IncidentTagModel(
                        incident_id=incident.incident_id.value,
                        tenant_id=tenant_id.value,
                        tag_key=tag.key,
                        tag_value=tag.value,
                    )
                )

            await session.commit()


# ── ContainmentAction ───────────────────────────────────────────────────────


def _containment_to_row(action: ContainmentAction) -> ContainmentActionModel:
    return ContainmentActionModel(
        action_id=action.action_id.value,
        tenant_id=action.tenant_id.value,
        incident_id=action.incident_id.value,
        action_type=action.action_type.value,
        description=action.description,
        authorization_level_required=action.authorization_level_required.value,
        authorized_by=action.authorized_by,
        authorized_at=action.authorized_at,
        executed_by=action.executed_by,
        started_at=action.started_at,
        completed_at=action.completed_at,
        evidence_ref=action.evidence_ref,
        status=action.status.value,
        failure_reason=action.failure_reason,
        rollback_ref=action.rollback_ref,
    )


def _row_to_containment(row: ContainmentActionModel) -> ContainmentAction:
    return ContainmentAction(
        action_id=ContainmentActionId(row.action_id),
        tenant_id=TenantId(row.tenant_id),
        incident_id=IncidentId(row.incident_id),
        action_type=ContainmentActionType(row.action_type),
        description=row.description,
        authorization_level_required=ContainmentAuthorizationLevel(
            row.authorization_level_required
        ),
        status=ContainmentActionStatus(row.status),
        authorized_by=row.authorized_by,
        authorized_at=row.authorized_at,
        executed_by=row.executed_by,
        started_at=row.started_at,
        completed_at=row.completed_at,
        evidence_ref=row.evidence_ref,
        failure_reason=row.failure_reason,
        rollback_ref=row.rollback_ref,
    )


class PgContainmentActionRepository(IContainmentActionRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def find_by_id(
        self, tenant_id: TenantId, action_id: ContainmentActionId
    ) -> ContainmentAction | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ContainmentActionModel).where(
                        ContainmentActionModel.tenant_id == tenant_id.value,
                        ContainmentActionModel.action_id == action_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_containment(row) if row is not None else None

    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: IncidentId
    ) -> list[ContainmentAction]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(ContainmentActionModel).where(
                        ContainmentActionModel.tenant_id == tenant_id.value,
                        ContainmentActionModel.incident_id == incident_id.value,
                    )
                )
            ).scalars().all()
            return [_row_to_containment(r) for r in rows]

    async def save(self, tenant_id: TenantId, action: ContainmentAction) -> None:
        async with self._session_factory() as session:
            await session.merge(_containment_to_row(action))
            await session.commit()


# ── EradicationVerification ─────────────────────────────────────────────────


def _eradication_to_row(v: EradicationVerification) -> EradicationVerificationModel:
    return EradicationVerificationModel(
        verification_id=v.verification_id.value,
        tenant_id=v.tenant_id.value,
        incident_id=v.incident_id.value,
        assertion=v.assertion,
        evidence_refs=[
            {"evidence_id": r.evidence_id, "description": r.description} for r in v.evidence_refs
        ],
        submitted_by=v.submitted_by,
        submitted_at=v.submitted_at,
        verified_by=v.verified_by,
        verified_at=v.verified_at,
        status=v.status.value,
        dispute_reason=v.dispute_reason,
    )


def _row_to_eradication(row: EradicationVerificationModel) -> EradicationVerification:
    return EradicationVerification(
        verification_id=EradicationVerificationId(row.verification_id),
        tenant_id=TenantId(row.tenant_id),
        incident_id=IncidentId(row.incident_id),
        assertion=row.assertion,
        evidence_refs=[
            EradicationEvidenceRef(
                evidence_id=str(item["evidence_id"]), description=str(item["description"])
            )
            for item in (row.evidence_refs or [])
        ],
        status=EradicationVerificationStatus(row.status),
        submitted_by=row.submitted_by,
        submitted_at=row.submitted_at,
        verified_by=row.verified_by,
        verified_at=row.verified_at,
        dispute_reason=row.dispute_reason,
    )


class PgEradicationVerificationRepository(IEradicationVerificationRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: IncidentId
    ) -> EradicationVerification | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(EradicationVerificationModel).where(
                        EradicationVerificationModel.tenant_id == tenant_id.value,
                        EradicationVerificationModel.incident_id == incident_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_eradication(row) if row is not None else None

    async def save(self, tenant_id: TenantId, verification: EradicationVerification) -> None:
        async with self._session_factory() as session:
            await session.merge(_eradication_to_row(verification))
            await session.commit()


# ── RecoveryMilestone ────────────────────────────────────────────────────────


def _milestone_to_row(m: RecoveryMilestone) -> RecoveryMilestoneModel:
    return RecoveryMilestoneModel(
        milestone_id=m.milestone_id.value,
        tenant_id=m.tenant_id.value,
        incident_id=m.incident_id.value,
        title=m.title,
        description=m.description,
        owner=m.owner,
        target_date=m.target_date,
        started_at=m.started_at,
        completed_at=m.completed_at,
        status=m.status.value,
        completion_notes=m.completion_notes,
        defer_reason=m.defer_reason,
    )


def _row_to_milestone(row: RecoveryMilestoneModel) -> RecoveryMilestone:
    return RecoveryMilestone(
        milestone_id=RecoveryMilestoneId(row.milestone_id),
        tenant_id=TenantId(row.tenant_id),
        incident_id=IncidentId(row.incident_id),
        title=row.title,
        description=row.description,
        owner=row.owner,
        target_date=row.target_date,
        status=RecoveryMilestoneStatus(row.status),
        started_at=row.started_at,
        completed_at=row.completed_at,
        completion_notes=row.completion_notes,
        defer_reason=row.defer_reason,
    )


class PgRecoveryMilestoneRepository(IRecoveryMilestoneRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: IncidentId
    ) -> list[RecoveryMilestone]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(RecoveryMilestoneModel).where(
                        RecoveryMilestoneModel.tenant_id == tenant_id.value,
                        RecoveryMilestoneModel.incident_id == incident_id.value,
                    )
                )
            ).scalars().all()
            return [_row_to_milestone(r) for r in rows]

    async def save(self, tenant_id: TenantId, milestone: RecoveryMilestone) -> None:
        async with self._session_factory() as session:
            await session.merge(_milestone_to_row(milestone))
            await session.commit()


# ── Communication log (append-only) ────────────────────────────────────────


class PgIncidentCommunicationLogRepository(IIncidentCommunicationLogRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def append(
        self,
        tenant_id: TenantId,
        incident_id: IncidentId,
        entry: IncidentCommunicationLogEntry,
    ) -> None:
        async with self._session_factory() as session:
            session.add(
                IncidentCommunicationLogEntryModel(
                    entry_id=entry.entry_id.value,
                    tenant_id=tenant_id.value,
                    incident_id=incident_id.value,
                    content=entry.content,
                    author=entry.author,
                    recipient_summary=entry.recipient_summary,
                    communication_type=entry.communication_type.value,
                    logged_at=entry.logged_at,
                    entry_sequence=entry.entry_sequence,
                    prev_hash=entry.prev_hash,
                    entry_hash=entry.entry_hash,
                )
            )
            await session.commit()

    async def find_by_incident(
        self,
        tenant_id: TenantId,
        incident_id: IncidentId,
        *,
        after: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IncidentCommunicationLogEntry]:
        async with self._session_factory() as session:
            stmt = (
                select(IncidentCommunicationLogEntryModel)
                .where(
                    IncidentCommunicationLogEntryModel.tenant_id == tenant_id.value,
                    IncidentCommunicationLogEntryModel.incident_id == incident_id.value,
                )
                .order_by(IncidentCommunicationLogEntryModel.entry_sequence)
                .limit(limit)
                .offset(offset)
            )
            if after is not None:
                stmt = stmt.where(IncidentCommunicationLogEntryModel.logged_at > after)
            rows = (await session.execute(stmt)).scalars().all()
            return [
                IncidentCommunicationLogEntry(
                    entry_id=CommunicationLogEntryId(r.entry_id),
                    tenant_id=TenantId(r.tenant_id),
                    incident_id=IncidentId(r.incident_id),
                    content=r.content,
                    author=r.author,
                    recipient_summary=r.recipient_summary,
                    communication_type=CommunicationType(r.communication_type),
                    logged_at=r.logged_at,
                    entry_sequence=r.entry_sequence,
                    prev_hash=r.prev_hash,
                    entry_hash=r.entry_hash,
                )
                for r in rows
            ]
