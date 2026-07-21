"""In-memory repositories with tenant isolation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from incident.domain.entities.communication_log_entry import IncidentCommunicationLogEntry
from incident.domain.repositories.i_incident_repositories import (
    IContainmentActionRepository,
    IEradicationVerificationRepository,
    IIncidentCommunicationLogRepository,
    IIncidentRepository,
    IRecoveryMilestoneRepository,
)
from incident.domain.value_objects.enums import IncidentPhase
from incident.domain.value_objects.identifiers import CommunicationLogEntryId

if TYPE_CHECKING:
    from incident.domain.aggregates.containment_action import ContainmentAction
    from incident.domain.aggregates.eradication_verification import EradicationVerification
    from incident.domain.aggregates.incident import Incident
    from incident.domain.aggregates.recovery_milestone import RecoveryMilestone
    from incident.domain.value_objects.enums import IncidentSeverity
    from incident.domain.value_objects.identifiers import (
        ContainmentActionId,
        IncidentId,
        TenantId,
    )


class InMemoryIncidentRepository(IIncidentRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, Incident]] = {}

    async def find_by_id(self, tenant_id: TenantId, incident_id: IncidentId) -> Incident | None:
        return self._items.get(str(tenant_id), {}).get(str(incident_id))

    async def find_active(
        self, tenant_id: TenantId, *, phase_filter: IncidentPhase | None = None
    ) -> list[Incident]:
        rows = [
            i
            for i in self._items.get(str(tenant_id), {}).values()
            if i.phase != IncidentPhase.CLOSED
        ]
        if phase_filter:
            rows = [i for i in rows if i.phase == phase_filter]
        return rows

    async def find_by_severity(
        self, tenant_id: TenantId, severity: IncidentSeverity
    ) -> list[Incident]:
        return [i for i in self._items.get(str(tenant_id), {}).values() if i.severity == severity]

    async def find_classified_in_period(
        self, tenant_id: TenantId, start: datetime, end: datetime
    ) -> list[Incident]:
        out: list[Incident] = []
        for i in self._items.get(str(tenant_id), {}).values():
            if i.classified_at and start <= i.classified_at < end:
                out.append(i)
        return out

    async def save(self, tenant_id: TenantId, incident: Incident) -> None:
        self._items.setdefault(str(tenant_id), {})[str(incident.incident_id)] = incident


class InMemoryContainmentActionRepository(IContainmentActionRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, ContainmentAction]] = {}

    async def find_by_id(
        self, tenant_id: TenantId, action_id: ContainmentActionId
    ) -> ContainmentAction | None:
        return self._items.get(str(tenant_id), {}).get(str(action_id))

    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: IncidentId
    ) -> list[ContainmentAction]:
        return [
            a
            for a in self._items.get(str(tenant_id), {}).values()
            if str(a.incident_id) == str(incident_id)
        ]

    async def save(self, tenant_id: TenantId, action: ContainmentAction) -> None:
        self._items.setdefault(str(tenant_id), {})[str(action.action_id)] = action


class InMemoryEradicationVerificationRepository(IEradicationVerificationRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, EradicationVerification]] = {}

    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: IncidentId
    ) -> EradicationVerification | None:
        return self._items.get(str(tenant_id), {}).get(str(incident_id))

    async def save(self, tenant_id: TenantId, verification: EradicationVerification) -> None:
        self._items.setdefault(str(tenant_id), {})[str(verification.incident_id)] = verification


class InMemoryRecoveryMilestoneRepository(IRecoveryMilestoneRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, RecoveryMilestone]] = {}

    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: IncidentId
    ) -> list[RecoveryMilestone]:
        return [
            m
            for m in self._items.get(str(tenant_id), {}).values()
            if str(m.incident_id) == str(incident_id)
        ]

    async def save(self, tenant_id: TenantId, milestone: RecoveryMilestone) -> None:
        self._items.setdefault(str(tenant_id), {})[str(milestone.milestone_id)] = milestone


class InMemoryCommunicationLogRepository(IIncidentCommunicationLogRepository):
    def __init__(self) -> None:
        self._items: dict[str, list[IncidentCommunicationLogEntry]] = {}

    def _key(self, tenant_id: TenantId, incident_id: IncidentId) -> str:
        return f"{tenant_id}:{incident_id}"

    async def append(
        self,
        tenant_id: TenantId,
        incident_id: IncidentId,
        entry: IncidentCommunicationLogEntry,
    ) -> None:
        # System sets sequence, logged_at, hash — ignore caller mutability
        key = self._key(tenant_id, incident_id)
        existing = self._items.setdefault(key, [])
        seq = len(existing) + 1
        prev = existing[-1].entry_hash if existing else "GENESIS"
        now = datetime.now(UTC)
        entry_id = (
            entry.entry_id
            if isinstance(entry.entry_id, CommunicationLogEntryId)
            else CommunicationLogEntryId.generate()
        )
        digest = IncidentCommunicationLogEntry.compute_hash(
            prev_hash=prev,
            content=entry.content,
            author=entry.author,
            logged_at=now,
            entry_sequence=seq,
        )
        sealed = IncidentCommunicationLogEntry(
            entry_id=entry_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            content=entry.content,
            author=entry.author,
            recipient_summary=entry.recipient_summary,
            communication_type=entry.communication_type,
            logged_at=now,
            entry_sequence=seq,
            prev_hash=prev,
            entry_hash=digest,
        )
        existing.append(sealed)

    async def find_by_incident(
        self,
        tenant_id: TenantId,
        incident_id: IncidentId,
        *,
        after: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IncidentCommunicationLogEntry]:
        rows = list(self._items.get(self._key(tenant_id, incident_id), []))
        if after is not None:
            rows = [r for r in rows if r.logged_at > after]
        return rows[offset : offset + limit]
