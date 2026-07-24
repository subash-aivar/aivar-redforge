"""CQRS application service for incident BC."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from incident.application._auth import require_at_least
from incident.application.commands.incident_commands import (
    AddRecoveryMilestoneCommand,
    AuthorizeContainmentCommand,
    ClassifyIncidentCommand,
    CloseIncidentCommand,
    CompleteContainmentCommand,
    CompleteRecoveryMilestoneCommand,
    DeclareIncidentCommand,
    FailContainmentCommand,
    LogCommunicationCommand,
    ReclassifyIncidentCommand,
    SubmitEradicationCommand,
    VerifyEradicationCommand,
)
from incident.application.dtos.incident_dtos import (
    CommunicationLogEntryDTO,
    ContainmentActionDTO,
    IncidentDTO,
)
from incident.application.exceptions import ApplicationNotFoundError
from incident.domain.aggregates.containment_action import ContainmentAction
from incident.domain.aggregates.eradication_verification import EradicationVerification
from incident.domain.aggregates.incident import Incident
from incident.domain.aggregates.recovery_milestone import RecoveryMilestone
from incident.domain.entities.communication_log_entry import IncidentCommunicationLogEntry
from incident.domain.services.communication_log_service import CommunicationLogService
from incident.domain.services.containment_authorization_service import (
    ContainmentAuthorizationService,
)
from incident.domain.services.incident_lifecycle_service import IncidentLifecycleService
from incident.domain.services.incident_timeline_service import IncidentTimelineService
from incident.domain.services.mttr_publishing_service import MTTRPublishingService
from incident.domain.services.recovery_service import RecoveryService
from incident.domain.services.severity_classification_service import (
    SeverityClassificationService,
)
from incident.domain.value_objects.enums import (
    CommunicationType,
    ContainmentActionType,
    EradicationVerificationStatus,
    IncidentPhase,
    IncidentRole,
    IncidentSeverity,
    IncidentTriggerType,
    ResolutionType,
    SeverityClassificationMethod,
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
    InvestigationRef,
)


class IncidentApplicationService:
    def __init__(
        self,
        incidents: Any,
        actions: Any,
        eradications: Any,
        milestones: Any,
        comm_log: Any,
        analytics_port: Any,
        graph_port: Any,
        comm_notify: Any,
        itsm: Any,
        event_sink: list[Any] | None = None,
    ) -> None:
        self._incidents = incidents
        self._actions = actions
        self._eradications = eradications
        self._milestones = milestones
        self._comm_log = comm_log
        self._mttr = MTTRPublishingService(analytics_port)
        self._graph = graph_port
        self._comm_notify = comm_notify
        self._itsm = itsm
        self._authz = ContainmentAuthorizationService()
        self._lifecycle = IncidentLifecycleService()
        self._timeline = IncidentTimelineService()
        self._severity = SeverityClassificationService()
        self._recovery = RecoveryService()
        self._hash = CommunicationLogService()
        self._events: list[Any] = event_sink if event_sink is not None else []
        self.audit: list[dict[str, Any]] = []

    def _tenant(self, value: UUID) -> TenantId:
        if isinstance(value, TenantId):
            return value
        return TenantId.from_string(str(value))

    def _to_dto(self, inc: Incident) -> IncidentDTO:
        return IncidentDTO(
            incident_id=str(inc.incident_id),
            tenant_id=str(inc.tenant_id),
            title=inc.title,
            description=inc.description,
            phase=inc.phase.value,
            severity=inc.severity.value,
            trigger_type=inc.trigger_type.value,
            classified_at=inc.classified_at.isoformat() if inc.classified_at else None,
            contained_at=inc.contained_at.isoformat() if inc.contained_at else None,
            eradicated_at=inc.eradicated_at.isoformat() if inc.eradicated_at else None,
            recovered_at=inc.recovered_at.isoformat() if inc.recovered_at else None,
            closed_at=inc.closed_at.isoformat() if inc.closed_at else None,
            resolution_type=inc.resolution_type.value if inc.resolution_type else None,
            timeline=[
                {
                    "entry_type": e.entry_type.value,
                    "summary": e.summary,
                    "actor": e.actor,
                    "occurred_at": e.occurred_at.isoformat(),
                    "details": e.details,
                }
                for e in self._timeline.ordered_entries(inc)
            ],
        )

    async def _persist_events(self, source: Any) -> None:
        events = source.pop_events()
        self._events.extend(events)
        await self._mttr.publish_from_events(events)
        for e in events:
            self.audit.append(
                {"type": type(e).__name__, "aggregate": getattr(e, "aggregate_id", "")}
            )

    async def declare(self, cmd: DeclareIncidentCommand) -> IncidentDTO:
        require_at_least(cmd.roles, IncidentRole.ANALYST)
        now = datetime.now(UTC)
        tenant = self._tenant(cmd.tenant_id)
        finding = None
        if cmd.source_finding_id:
            finding = EscalatedFindingRef(
                cmd.source_finding_id,
                cmd.severity,
                "",
                "",
                now,
                cmd.actor,
            )
        investigation = None
        if cmd.investigation_id:
            investigation = InvestigationRef(cmd.investigation_id, None, "")
        inc = Incident.declare(
            IncidentId.generate(),
            tenant,
            cmd.title,
            cmd.description,
            IncidentTriggerType(cmd.trigger_type),
            IncidentSeverity(cmd.severity),
            now,
            source_finding_ref=finding,
            investigation_ref=investigation,
            actor=cmd.actor,
        )
        await self._incidents.save(tenant, inc)
        await self._persist_events(inc)
        await self._graph.write_incident_node(
            str(tenant), {"incident_id": str(inc.incident_id), "phase": inc.phase.value}
        )
        await self._itsm.create_ticket(str(tenant), str(inc.incident_id), inc.title)
        return self._to_dto(inc)

    async def classify(self, cmd: ClassifyIncidentCommand) -> IncidentDTO:
        require_at_least(cmd.roles, IncidentRole.ANALYST)
        tenant = self._tenant(cmd.tenant_id)
        inc = await self._incidents.find_by_id(tenant, IncidentId(cmd.incident_id))
        if inc is None:
            raise ApplicationNotFoundError("incident")
        now = datetime.now(UTC)
        inc.classify(
            tenant,
            IncidentSeverity(cmd.severity),
            SeverityClassificationMethod(cmd.method),
            now,
            cmd.actor,
        )
        await self._incidents.save(tenant, inc)
        await self._persist_events(inc)
        await self._comm_notify.notify_phase_transition(
            str(tenant), str(inc.incident_id), inc.phase.value, "classified"
        )
        return self._to_dto(inc)

    async def reclassify(self, cmd: ReclassifyIncidentCommand) -> IncidentDTO:
        require_at_least(cmd.roles, IncidentRole.COMMANDER)
        tenant = self._tenant(cmd.tenant_id)
        inc = await self._incidents.find_by_id(tenant, IncidentId(cmd.incident_id))
        if inc is None:
            raise ApplicationNotFoundError("incident")
        inc.reclassify(
            tenant,
            IncidentSeverity(cmd.new_severity),
            cmd.justification,
            cmd.actor,
            datetime.now(UTC),
        )
        await self._incidents.save(tenant, inc)
        await self._persist_events(inc)
        return self._to_dto(inc)

    async def authorize_containment(self, cmd: AuthorizeContainmentCommand) -> ContainmentActionDTO:
        action_type = ContainmentActionType(cmd.action_type)
        self._authz.assert_authorized(action_type, cmd.roles)
        require_at_least(cmd.roles, IncidentRole.ANALYST)
        tenant = self._tenant(cmd.tenant_id)
        inc = await self._incidents.find_by_id(tenant, IncidentId(cmd.incident_id))
        if inc is None:
            raise ApplicationNotFoundError("incident")
        level = self._authz.required_authorization_level(action_type)
        action = ContainmentAction.request(
            ContainmentActionId.generate(),
            tenant,
            IncidentId(cmd.incident_id),
            action_type,
            cmd.description,
            level,
        )
        now = datetime.now(UTC)
        action.authorize(tenant, cmd.actor, now)
        await self._actions.save(tenant, action)
        await self._persist_events(action)
        await self._graph.write_containment_node(
            str(tenant),
            {"action_id": str(action.action_id), "action_type": action_type.value},
        )
        if inc.phase == IncidentPhase.CLASSIFIED:
            # Auto-advance when first containment authorized+will complete later
            pass
        return ContainmentActionDTO(
            str(action.action_id),
            str(action.incident_id),
            action.action_type.value,
            action.status.value,
            action.authorization_level_required.value,
            action.authorized_by,
        )

    async def complete_containment(self, cmd: CompleteContainmentCommand) -> ContainmentActionDTO:
        require_at_least(cmd.roles, IncidentRole.ANALYST)
        tenant = self._tenant(cmd.tenant_id)
        action = await self._actions.find_by_id(tenant, ContainmentActionId(cmd.action_id))
        if action is None:
            raise ApplicationNotFoundError("action")
        now = datetime.now(UTC)
        action.complete(tenant, cmd.actor, cmd.evidence_ref, now)
        await self._actions.save(tenant, action)
        await self._persist_events(action)
        inc = await self._incidents.find_by_id(tenant, action.incident_id)
        if inc and inc.phase == IncidentPhase.CLASSIFIED:
            inc.mark_contained(tenant, now, cmd.actor)
            await self._incidents.save(tenant, inc)
            await self._persist_events(inc)
        return ContainmentActionDTO(
            str(action.action_id),
            str(action.incident_id),
            action.action_type.value,
            action.status.value,
            action.authorization_level_required.value,
            action.authorized_by,
        )

    async def fail_containment(self, cmd: FailContainmentCommand) -> ContainmentActionDTO:
        require_at_least(cmd.roles, IncidentRole.ANALYST)
        tenant = self._tenant(cmd.tenant_id)
        action = await self._actions.find_by_id(tenant, ContainmentActionId(cmd.action_id))
        if action is None:
            raise ApplicationNotFoundError("action")
        action.fail(tenant, cmd.failure_reason, datetime.now(UTC))
        await self._actions.save(tenant, action)
        await self._persist_events(action)
        return ContainmentActionDTO(
            str(action.action_id),
            str(action.incident_id),
            action.action_type.value,
            action.status.value,
            action.authorization_level_required.value,
            action.authorized_by,
        )

    async def submit_eradication(self, cmd: SubmitEradicationCommand) -> dict[str, str]:
        require_at_least(cmd.roles, IncidentRole.ANALYST)
        tenant = self._tenant(cmd.tenant_id)
        refs = [EradicationEvidenceRef(eid, "evidence") for eid in cmd.evidence_ids]
        v = EradicationVerification.submit(
            EradicationVerificationId.generate(),
            tenant,
            IncidentId(cmd.incident_id),
            cmd.assertion,
            refs,
            cmd.actor,
            datetime.now(UTC),
        )
        await self._eradications.save(tenant, v)
        await self._persist_events(v)
        return {"verification_id": str(v.verification_id), "status": v.status.value}

    async def verify_eradication(self, cmd: VerifyEradicationCommand) -> dict[str, str]:
        require_at_least(cmd.roles, IncidentRole.COMMANDER)
        tenant = self._tenant(cmd.tenant_id)
        v = await self._eradications.find_by_incident(tenant, IncidentId(cmd.incident_id))
        if v is None:
            raise ApplicationNotFoundError("eradication")
        now = datetime.now(UTC)
        v.verify(tenant, cmd.actor, now)
        await self._eradications.save(tenant, v)
        await self._persist_events(v)
        inc = await self._incidents.find_by_id(tenant, IncidentId(cmd.incident_id))
        if inc and inc.phase == IncidentPhase.CONTAINED:
            inc.mark_eradicated(tenant, now, cmd.actor)
            await self._incidents.save(tenant, inc)
            await self._persist_events(inc)
        return {"status": v.status.value}

    async def close(self, cmd: CloseIncidentCommand) -> IncidentDTO:
        if cmd.force:
            require_at_least(cmd.roles, IncidentRole.CISO)
        else:
            require_at_least(cmd.roles, IncidentRole.COMMANDER)
        tenant = self._tenant(cmd.tenant_id)
        inc = await self._incidents.find_by_id(tenant, IncidentId(cmd.incident_id))
        if inc is None:
            raise ApplicationNotFoundError("incident")
        eradication = await self._eradications.find_by_incident(tenant, IncidentId(cmd.incident_id))
        verified = (
            eradication is not None and eradication.status == EradicationVerificationStatus.VERIFIED
        )
        # Allow close from RECOVERED or earlier with force/fp
        now = datetime.now(UTC)
        if inc.phase == IncidentPhase.ERADICATED and not cmd.force:
            # auto recover if no milestones or all done
            milestones = await self._milestones.find_by_incident(
                tenant, IncidentId(cmd.incident_id)
            )
            if not milestones or self._recovery.all_completed(milestones):
                inc.mark_recovered(tenant, now, cmd.actor)
        inc.close(
            tenant,
            ResolutionType(cmd.resolution_type),
            now,
            cmd.actor,
            eradication_verified=verified,
            force=cmd.force,
            force_justification=cmd.force_justification,
        )
        await self._incidents.save(tenant, inc)
        await self._persist_events(inc)
        return self._to_dto(inc)

    async def add_milestone(self, cmd: AddRecoveryMilestoneCommand) -> dict[str, str]:
        require_at_least(cmd.roles, IncidentRole.ANALYST)
        tenant = self._tenant(cmd.tenant_id)
        m = RecoveryMilestone.create(
            RecoveryMilestoneId.generate(),
            tenant,
            IncidentId(cmd.incident_id),
            cmd.title,
            cmd.description,
            cmd.owner,
            cmd.target_date,
        )
        await self._milestones.save(tenant, m)
        return {"milestone_id": str(m.milestone_id), "status": m.status.value}

    async def complete_milestone(self, cmd: CompleteRecoveryMilestoneCommand) -> dict[str, str]:
        require_at_least(cmd.roles, IncidentRole.ANALYST)
        tenant = self._tenant(cmd.tenant_id)
        rows = await self._milestones.find_by_incident(tenant, IncidentId(cmd.incident_id))
        milestone = next((m for m in rows if m.milestone_id.value == cmd.milestone_id), None)
        if milestone is None:
            raise ApplicationNotFoundError("milestone")
        now = datetime.now(UTC)
        milestone.complete(tenant, cmd.notes, now)
        await self._milestones.save(tenant, milestone)
        await self._persist_events(milestone)
        if cmd.mark_incident_recovered:
            inc = await self._incidents.find_by_id(tenant, IncidentId(cmd.incident_id))
            if inc and inc.phase == IncidentPhase.ERADICATED:
                inc.mark_recovered(tenant, now, cmd.actor)
                await self._incidents.save(tenant, inc)
                await self._persist_events(inc)
        return {"status": milestone.status.value}

    async def log_communication(self, cmd: LogCommunicationCommand) -> CommunicationLogEntryDTO:
        require_at_least(cmd.roles, IncidentRole.ANALYST)
        tenant = self._tenant(cmd.tenant_id)
        # logged_at/hash set by repository
        provisional = IncidentCommunicationLogEntry(
            entry_id=CommunicationLogEntryId.generate(),
            tenant_id=tenant,
            incident_id=IncidentId(cmd.incident_id),
            content=cmd.content,
            author=cmd.actor,
            recipient_summary=cmd.recipient_summary,
            communication_type=CommunicationType(cmd.communication_type),
            logged_at=datetime.now(UTC),
            entry_sequence=0,
            prev_hash="",
            entry_hash="",
        )
        await self._comm_log.append(tenant, IncidentId(cmd.incident_id), provisional)
        rows = await self._comm_log.find_by_incident(tenant, IncidentId(cmd.incident_id))
        self._hash.verify_chain(rows)
        last = rows[-1]
        return CommunicationLogEntryDTO(
            str(last.entry_id),
            last.content,
            last.author,
            last.logged_at.isoformat(),
            last.entry_sequence,
            last.entry_hash,
            last.prev_hash,
        )

    async def get_incident(
        self, tenant_id: TenantId, incident_id: UUID, roles: tuple[str, ...]
    ) -> IncidentDTO:
        require_at_least(roles, IncidentRole.VIEWER)
        tenant = self._tenant(tenant_id)
        inc = await self._incidents.find_by_id(tenant, IncidentId(incident_id))
        if inc is None:
            raise ApplicationNotFoundError("incident")
        return self._to_dto(inc)

    async def list_incidents(self, tenant_id: TenantId, roles: tuple[str, ...]) -> list[IncidentDTO]:
        require_at_least(roles, IncidentRole.VIEWER)
        tenant = self._tenant(tenant_id)
        rows = await self._incidents.find_active(tenant)
        return [self._to_dto(i) for i in rows]

    async def get_comm_log(
        self, tenant_id: TenantId, incident_id: UUID, roles: tuple[str, ...]
    ) -> list[CommunicationLogEntryDTO]:
        require_at_least(roles, IncidentRole.VIEWER)
        tenant = self._tenant(tenant_id)
        rows = await self._comm_log.find_by_incident(tenant, IncidentId(incident_id))
        self._hash.verify_chain(rows)
        return [
            CommunicationLogEntryDTO(
                str(r.entry_id),
                r.content,
                r.author,
                r.logged_at.isoformat(),
                r.entry_sequence,
                r.entry_hash,
                r.prev_hash,
            )
            for r in rows
        ]

    async def dashboard(self, tenant_id: TenantId, roles: tuple[str, ...]) -> dict[str, Any]:
        require_at_least(roles, IncidentRole.VIEWER)
        tenant = self._tenant(tenant_id)
        active = await self._incidents.find_active(tenant)
        p1 = [i for i in active if i.severity == IncidentSeverity.P1_CRITICAL]
        p2 = [i for i in active if i.severity == IncidentSeverity.P2_HIGH]
        return {
            "active_count": len(active),
            "p1_count": len(p1),
            "p2_count": len(p2),
            "incidents": [self._to_dto(i) for i in active[:100]],
        }
