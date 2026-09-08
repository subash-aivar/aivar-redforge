"""ThreatActorApplicationService — the single application-service class
for threat_actor_intel (M51.1 Phase 2), owning every approved use
case (mirrors `exposure.ExposureApplicationService`'s one-class,
multi-method shape, not one class per use case).

Every mutating method follows the platform-wide flow: authorize ->
validate -> load/mutate aggregate -> save -> commit -> publish popped
domain events (in that order, and only in that order — events are
never published before a successful commit)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from threat_actor_intel.application._auth import require_at_least
from threat_actor_intel.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from threat_actor_intel.application.services.mappers import (
    to_association_dto,
    to_detail_dto,
    to_summary_dto,
)
from threat_actor_intel.domain.factories.threat_actor_association_factory import (
    ThreatActorAssociationFactory,
)
from threat_actor_intel.domain.factories.threat_actor_factory import ThreatActorFactory
from threat_actor_intel.domain.policies.association_uniqueness_policy import (
    AssociationUniquenessPolicy,
)
from threat_actor_intel.domain.value_objects.enums import (
    ActivityStatus,
    MotivationType,
    SophisticationLevel,
    ThreatActorIntelRole,
    ThreatActorOrigin,
)
from threat_actor_intel.domain.value_objects.evidence import EvidenceCitation
from threat_actor_intel.domain.value_objects.identifiers import (
    ThreatActorAssociationId,
    ThreatActorId,
)
from threat_actor_intel.domain.value_objects.identity import Alias, ThreatActorName
from threat_actor_intel.domain.value_objects.references import (
    AttackTechniqueReference,
    FusedIndicatorReference,
    ReferencedEntityRef,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from threat_actor_intel.application.commands.threat_actor_commands import (
        AddAliasCommand,
        AssociateIndicatorCommand,
        AssociateTechniqueCommand,
        CreateThreatActorAssociationCommand,
        RegisterThreatActorCommand,
        RetractThreatActorAssociationCommand,
        TransitionActivityStatusCommand,
        UpdateMotivationsCommand,
        UpdateSophisticationCommand,
    )
    from threat_actor_intel.application.dtos.threat_actor_dtos import (
        ThreatActorAssociationDTO,
        ThreatActorDetailDTO,
        ThreatActorSummaryDTO,
    )
    from threat_actor_intel.application.ports.i_event_publisher import IEventPublisher
    from threat_actor_intel.application.ports.i_unit_of_work import IUnitOfWork
    from threat_actor_intel.application.queries.threat_actor_queries import (
        GetThreatActorAssociationQuery,
        GetThreatActorQuery,
        ListAssociationsForTenantQuery,
        ListThreatActorsQuery,
    )
    from threat_actor_intel.domain.aggregates.threat_actor import ThreatActor
    from threat_actor_intel.domain.ports.i_evidence_validation_port import (
        IEvidenceValidationPort,
    )

_TARGET_STATUS_HANDLERS = {
    ActivityStatus.DORMANT: "mark_dormant",
    ActivityStatus.ACTIVE: "reactivate",
    ActivityStatus.DISBANDED: "disband",
}


class ThreatActorApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        evidence_validator: IEvidenceValidationPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._events = event_publisher
        self._evidence = evidence_validator

    # ── Global ThreatActor operations (platform-admin-only mutation) ───────

    async def register_threat_actor(self, cmd: RegisterThreatActorCommand) -> ThreatActorDetailDTO:
        require_at_least(cmd.actor_roles, ThreatActorIntelRole.PLATFORM_ADMIN)
        now = datetime.now(UTC)
        motivations = frozenset(MotivationType(m) for m in cmd.motivations)
        async with self._uow_factory() as uow:
            actor = ThreatActorFactory.register(
                tenant_id=None,
                name=ThreatActorName(cmd.name),
                now=now,
                origin=ThreatActorOrigin(cmd.origin),
                motivations=motivations,
                sophistication=SophisticationLevel(cmd.sophistication),
            )
            await uow.threat_actors.save(actor)
            await uow.commit()
            await self._events.publish_batch(actor.pop_events())
            return to_detail_dto(actor)

    async def add_alias(self, cmd: AddAliasCommand) -> ThreatActorDetailDTO:
        require_at_least(cmd.actor_roles, ThreatActorIntelRole.PLATFORM_ADMIN)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            actor = await self._require_actor(uow, cmd.threat_actor_id)
            actor.add_alias(None, Alias(cmd.alias), now)
            await uow.threat_actors.save(actor)
            await uow.commit()
            await self._events.publish_batch(actor.pop_events())
            return to_detail_dto(actor)

    async def associate_technique(self, cmd: AssociateTechniqueCommand) -> ThreatActorDetailDTO:
        require_at_least(cmd.actor_roles, ThreatActorIntelRole.PLATFORM_ADMIN)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            actor = await self._require_actor(uow, cmd.threat_actor_id)
            actor.associate_technique(None, AttackTechniqueReference(cmd.technique_id), now)
            await uow.threat_actors.save(actor)
            await uow.commit()
            await self._events.publish_batch(actor.pop_events())
            return to_detail_dto(actor)

    async def associate_indicator(self, cmd: AssociateIndicatorCommand) -> ThreatActorDetailDTO:
        require_at_least(cmd.actor_roles, ThreatActorIntelRole.PLATFORM_ADMIN)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            actor = await self._require_actor(uow, cmd.threat_actor_id)
            actor.associate_indicator(None, FusedIndicatorReference(cmd.indicator_id), now)
            await uow.threat_actors.save(actor)
            await uow.commit()
            await self._events.publish_batch(actor.pop_events())
            return to_detail_dto(actor)

    async def update_motivations(self, cmd: UpdateMotivationsCommand) -> ThreatActorDetailDTO:
        require_at_least(cmd.actor_roles, ThreatActorIntelRole.PLATFORM_ADMIN)
        now = datetime.now(UTC)
        motivations = frozenset(MotivationType(m) for m in cmd.motivations)
        async with self._uow_factory() as uow:
            actor = await self._require_actor(uow, cmd.threat_actor_id)
            actor.update_motivations(None, motivations, now)
            await uow.threat_actors.save(actor)
            await uow.commit()
            await self._events.publish_batch(actor.pop_events())
            return to_detail_dto(actor)

    async def update_sophistication(self, cmd: UpdateSophisticationCommand) -> ThreatActorDetailDTO:
        require_at_least(cmd.actor_roles, ThreatActorIntelRole.PLATFORM_ADMIN)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            actor = await self._require_actor(uow, cmd.threat_actor_id)
            actor.update_sophistication(None, SophisticationLevel(cmd.sophistication), now)
            await uow.threat_actors.save(actor)
            await uow.commit()
            await self._events.publish_batch(actor.pop_events())
            return to_detail_dto(actor)

    async def transition_activity_status(
        self, cmd: TransitionActivityStatusCommand
    ) -> ThreatActorDetailDTO:
        require_at_least(cmd.actor_roles, ThreatActorIntelRole.PLATFORM_ADMIN)
        now = datetime.now(UTC)
        target = ActivityStatus(cmd.target_status)
        handler_name = _TARGET_STATUS_HANDLERS[target]
        async with self._uow_factory() as uow:
            actor = await self._require_actor(uow, cmd.threat_actor_id)
            getattr(actor, handler_name)(None, now)
            await uow.threat_actors.save(actor)
            await uow.commit()
            await self._events.publish_batch(actor.pop_events())
            return to_detail_dto(actor)

    async def get_threat_actor(self, query: GetThreatActorQuery) -> ThreatActorDetailDTO:
        require_at_least(query.actor_roles, ThreatActorIntelRole.VIEWER)
        async with self._uow_factory() as uow:
            actor = await self._require_actor(uow, query.threat_actor_id)
            return to_detail_dto(actor)

    async def list_threat_actors(self, query: ListThreatActorsQuery) -> list[ThreatActorSummaryDTO]:
        require_at_least(query.actor_roles, ThreatActorIntelRole.VIEWER)
        status = ActivityStatus(query.status) if query.status else None
        origin = ThreatActorOrigin(query.origin) if query.origin else None
        async with self._uow_factory() as uow:
            actors = await uow.threat_actors.list(status=status, origin=origin)
            return [to_summary_dto(a) for a in actors]

    # ── Tenant association operations ───────────────────────────────────────

    async def create_association(
        self, cmd: CreateThreatActorAssociationCommand
    ) -> ThreatActorAssociationDTO:
        require_at_least(cmd.actor_roles, ThreatActorIntelRole.ANALYST)
        now = datetime.now(UTC)
        referenced_entity = ReferencedEntityRef(
            entity_type=cmd.referenced_entity_type, entity_id=cmd.referenced_entity_id
        )
        evidence_citation = EvidenceCitation(cmd.evidence_citation)

        # Fail-closed (ADR-M51.1-08): a `False` result, or any exception
        # this port raises, both abort the association below — neither
        # is caught and treated as "proceed anyway".
        is_valid = await self._evidence.validate(
            tenant_id=cmd.tenant_id,
            referenced_entity_type=cmd.referenced_entity_type,
            referenced_entity_id=cmd.referenced_entity_id,
            evidence_citation=cmd.evidence_citation,
        )
        if not is_valid:
            raise ApplicationValidationError(
                f"Evidence citation failed validation for "
                f"{cmd.referenced_entity_type}:{cmd.referenced_entity_id}"
            )

        threat_actor_id = _parse_threat_actor_id(cmd.threat_actor_id)
        async with self._uow_factory() as uow:
            actor = await uow.threat_actors.get(threat_actor_id)
            if actor is None:
                raise ApplicationNotFoundError("ThreatActor", cmd.threat_actor_id)

            existing = await uow.associations.list_for_tenant(
                cmd.tenant_id, threat_actor_id=threat_actor_id
            )
            AssociationUniquenessPolicy.assert_no_active_duplicate(
                existing=existing,
                tenant_id=cmd.tenant_id,
                threat_actor_id=threat_actor_id,
                referenced_entity=referenced_entity,
            )

            association = ThreatActorAssociationFactory.create(
                tenant_id=cmd.tenant_id,
                threat_actor_id=threat_actor_id,
                referenced_entity=referenced_entity,
                evidence_citation=evidence_citation,
                now=now,
            )
            await uow.associations.save(cmd.tenant_id, association)
            await uow.commit()
            await self._events.publish_batch(association.pop_events())
            return to_association_dto(association)

    async def retract_association(
        self, cmd: RetractThreatActorAssociationCommand
    ) -> ThreatActorAssociationDTO:
        require_at_least(cmd.actor_roles, ThreatActorIntelRole.ANALYST)
        now = datetime.now(UTC)
        association_id = ThreatActorAssociationId(UUID(cmd.association_id))
        async with self._uow_factory() as uow:
            association = await uow.associations.get(cmd.tenant_id, association_id)
            if association is None:
                raise ApplicationNotFoundError("ThreatActorAssociation", cmd.association_id)
            association.retract(now)
            await uow.associations.save(cmd.tenant_id, association)
            await uow.commit()
            await self._events.publish_batch(association.pop_events())
            return to_association_dto(association)

    async def list_associations_for_tenant(
        self, query: ListAssociationsForTenantQuery
    ) -> list[ThreatActorAssociationDTO]:
        require_at_least(query.actor_roles, ThreatActorIntelRole.VIEWER)
        threat_actor_id = (
            _parse_threat_actor_id(query.threat_actor_id) if query.threat_actor_id else None
        )
        async with self._uow_factory() as uow:
            associations = await uow.associations.list_for_tenant(
                query.tenant_id, threat_actor_id=threat_actor_id
            )
            return [to_association_dto(a) for a in associations]

    async def get_association(
        self, query: GetThreatActorAssociationQuery
    ) -> ThreatActorAssociationDTO:
        require_at_least(query.actor_roles, ThreatActorIntelRole.VIEWER)
        association_id = ThreatActorAssociationId(UUID(query.association_id))
        async with self._uow_factory() as uow:
            association = await uow.associations.get(query.tenant_id, association_id)
            if association is None:
                raise ApplicationNotFoundError("ThreatActorAssociation", query.association_id)
            return to_association_dto(association)

    # ── Internal helpers ─────────────────────────────────────────────────────

    async def _require_actor(self, uow: IUnitOfWork, threat_actor_id: str) -> ThreatActor:
        actor = await uow.threat_actors.get(_parse_threat_actor_id(threat_actor_id))
        if actor is None:
            raise ApplicationNotFoundError("ThreatActor", threat_actor_id)
        return actor


def _parse_threat_actor_id(value: str) -> ThreatActorId:
    return ThreatActorId(UUID(value))
