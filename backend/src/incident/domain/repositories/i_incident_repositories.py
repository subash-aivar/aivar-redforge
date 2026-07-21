"""Frozen repository interfaces — tenant_id first; communication log append-only."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from incident.domain.aggregates.containment_action import ContainmentAction
    from incident.domain.aggregates.eradication_verification import EradicationVerification
    from incident.domain.aggregates.incident import Incident
    from incident.domain.aggregates.recovery_milestone import RecoveryMilestone
    from incident.domain.entities.communication_log_entry import IncidentCommunicationLogEntry
    from incident.domain.value_objects.enums import IncidentPhase, IncidentSeverity
    from incident.domain.value_objects.identifiers import (
        ContainmentActionId,
        IncidentId,
        TenantId,
    )


class IIncidentRepository(ABC):
    @abstractmethod
    async def find_by_id(self, tenant_id: TenantId, incident_id: IncidentId) -> Incident | None: ...

    @abstractmethod
    async def find_active(
        self, tenant_id: TenantId, *, phase_filter: IncidentPhase | None = None
    ) -> list[Incident]: ...

    @abstractmethod
    async def find_by_severity(
        self, tenant_id: TenantId, severity: IncidentSeverity
    ) -> list[Incident]: ...

    @abstractmethod
    async def find_classified_in_period(
        self, tenant_id: TenantId, start: datetime, end: datetime
    ) -> list[Incident]: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, incident: Incident) -> None: ...


class IContainmentActionRepository(ABC):
    @abstractmethod
    async def find_by_id(
        self, tenant_id: TenantId, action_id: ContainmentActionId
    ) -> ContainmentAction | None: ...

    @abstractmethod
    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: IncidentId
    ) -> list[ContainmentAction]: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, action: ContainmentAction) -> None: ...


class IEradicationVerificationRepository(ABC):
    @abstractmethod
    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: IncidentId
    ) -> EradicationVerification | None: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, verification: EradicationVerification) -> None: ...


class IRecoveryMilestoneRepository(ABC):
    @abstractmethod
    async def find_by_incident(
        self, tenant_id: TenantId, incident_id: IncidentId
    ) -> list[RecoveryMilestone]: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, milestone: RecoveryMilestone) -> None: ...


class IIncidentCommunicationLogRepository(ABC):
    @abstractmethod
    async def append(
        self,
        tenant_id: TenantId,
        incident_id: IncidentId,
        entry: IncidentCommunicationLogEntry,
    ) -> None: ...

    @abstractmethod
    async def find_by_incident(
        self,
        tenant_id: TenantId,
        incident_id: IncidentId,
        *,
        after: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IncidentCommunicationLogEntry]: ...
