"""IntelligenceRelationshipApplicationService — the single
application-service class for intelligence_relationships (M51.4 Phase
C1), mirroring `AttackPatternApplicationService`'s one-class,
multi-method shape.

Every mutating method follows the platform-wide flow: validate ->
load/deduplicate -> mutate -> save -> commit -> publish popped domain
events (in that order; events are never published before a successful
commit). Authorization (tenant vs. global, permission checks) happens
exclusively in the API layer — this service trusts the `tenant_id` it
is given.

Dedup is enforced two ways (mirroring `attack_pattern_intel`'s exact
discipline): the domain-level `RelationshipIdentityPolicy`, and a
repository existence check here before insert.

Endpoint existence is validated against the three owning bounded
contexts through the read-only ACL ports BEFORE the (pure, sync)
domain factory is ever called. Endpoints of the five entity types with
no owning module (malware, tool, campaign, infrastructure, threat
report) are structurally unverifiable and are accepted as opaque
strings by design.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import UUID

from intelligence_relationships.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from intelligence_relationships.application.services.mappers import to_detail_dto, to_summary_dto
from intelligence_relationships.domain.exceptions.domain_exceptions import (
    DuplicateRelationshipError,
    UnknownAttackPatternError,
    UnknownIocError,
    UnknownThreatActorError,
)
from intelligence_relationships.domain.factories.relationship_factory import (
    IntelligenceRelationshipFactory,
)
from intelligence_relationships.domain.policies.identity_policy import identity_key
from intelligence_relationships.domain.value_objects.entity_ref import EntityRef
from intelligence_relationships.domain.value_objects.enums import (
    EntityType,
    EpistemicState,
    RelationshipConfidence,
    RelationshipDirection,
    RelationshipLifecycleStatus,
    RelationshipType,
)
from intelligence_relationships.domain.value_objects.evidence import (
    EvidenceCitation,
    SourceAttribution,
)
from intelligence_relationships.domain.value_objects.identifiers import (
    IntelligenceRelationshipId,
)
from intelligence_relationships.domain.value_objects.validity import Validity

if TYPE_CHECKING:
    from collections.abc import Callable

    from intelligence_relationships.application.commands.relationship_commands import (
        AddEvidenceCitationCommand,
        AddSourceAttributionCommand,
        DeprecateRelationshipCommand,
        EntityRefInput,
        ObserveRelationshipCommand,
        ReactivateRelationshipCommand,
        RevokeRelationshipCommand,
        SourceAttributionInput,
        SupersedeRelationshipCommand,
        TransitionEpistemicStateCommand,
    )
    from intelligence_relationships.application.dtos.relationship_dtos import (
        RelationshipDetailDTO,
        RelationshipSummaryDTO,
    )
    from intelligence_relationships.application.ports.i_attack_pattern_identity_port import (
        IAttackPatternIdentityPort,
    )
    from intelligence_relationships.application.ports.i_event_publisher import IEventPublisher
    from intelligence_relationships.application.ports.i_ioc_identity_port import IIocIdentityPort
    from intelligence_relationships.application.ports.i_threat_actor_identity_port import (
        IThreatActorIdentityPort,
    )
    from intelligence_relationships.application.ports.i_unit_of_work import IUnitOfWork
    from intelligence_relationships.application.queries.relationship_queries import (
        GetRelationshipQuery,
        ListRelationshipsQuery,
    )
    from intelligence_relationships.domain.aggregates.intelligence_relationship import (
        IntelligenceRelationship,
    )
    from intelligence_relationships.domain.value_objects.identifiers import TenantId


def _parse_id(value: str) -> IntelligenceRelationshipId:
    return IntelligenceRelationshipId(UUID(value))


def _parse_enum[T: StrEnum](enum_cls: type[T], value: str, field: str) -> T:
    """Turn an unvalidated wire string into a closed-enum member, or
    raise a 422-shaped application error. The API layer never
    pre-validates these — the closed vocabulary is enforced here."""
    try:
        return enum_cls(value)
    except ValueError as exc:
        raise ApplicationValidationError(f"Invalid {field}: {value!r}") from exc


def _to_attribution(item: SourceAttributionInput) -> SourceAttribution:
    return SourceAttribution(
        source_system=item.source_system,
        reference=item.reference,
        observed_at=datetime.fromisoformat(item.observed_at),
        confidence=_parse_enum(RelationshipConfidence, item.confidence, "confidence"),
        notes=item.notes,
    )


def _to_entity_ref(item: EntityRefInput, field: str) -> EntityRef:
    return EntityRef(
        entity_type=_parse_enum(EntityType, item.entity_type, f"{field}.entity_type"),
        entity_id=item.entity_id,
    )


class IntelligenceRelationshipApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        ioc_identity_port: IIocIdentityPort,
        threat_actor_identity_port: IThreatActorIdentityPort,
        attack_pattern_identity_port: IAttackPatternIdentityPort,
        factory: IntelligenceRelationshipFactory | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._events = event_publisher
        self._iocs = ioc_identity_port
        self._threat_actors = threat_actor_identity_port
        self._attack_patterns = attack_pattern_identity_port
        self._factory = factory or IntelligenceRelationshipFactory()

    # ── Observation ──────────────────────────────────────────────────────

    async def observe(self, cmd: ObserveRelationshipCommand) -> RelationshipDetailDTO:
        relationship_type = _parse_enum(
            RelationshipType, cmd.relationship_type, "relationship_type"
        )
        direction = _parse_enum(RelationshipDirection, cmd.direction, "direction")
        confidence = _parse_enum(RelationshipConfidence, cmd.confidence, "confidence")
        epistemic_state = _parse_enum(EpistemicState, cmd.epistemic_state, "epistemic_state")

        source_entity = _to_entity_ref(cmd.source_entity, "source_entity")
        target_entity = _to_entity_ref(cmd.target_entity, "target_entity")

        await self._assert_endpoint_exists(source_entity)
        await self._assert_endpoint_exists(target_entity)

        now = datetime.now(UTC)
        validity = Validity(
            valid_from=datetime.fromisoformat(cmd.valid_from) if cmd.valid_from else now,
            valid_until=datetime.fromisoformat(cmd.valid_until) if cmd.valid_until else None,
        )
        citations = tuple(EvidenceCitation(value=value) for value in cmd.evidence_citations)
        attributions = tuple(_to_attribution(a) for a in cmd.source_attributions)

        async with self._uow_factory() as uow:
            existing = await uow.relationships.get_by_identity(
                cmd.tenant_id, relationship_type, source_entity, target_entity
            )
            if existing is not None:
                raise DuplicateRelationshipError(
                    identity_key(relationship_type, source_entity, target_entity)
                )

            relationship = self._factory.observe(
                tenant_id=cmd.tenant_id,
                relationship_type=relationship_type,
                source_entity=source_entity,
                target_entity=target_entity,
                direction=direction,
                confidence=confidence,
                validity=validity,
                now=now,
                epistemic_state=epistemic_state,
                evidence_citations=citations,
                source_attributions=attributions,
            )
            await uow.relationships.save(relationship)
            await uow.commit()
            await self._events.publish_batch(relationship.pop_events())
            return to_detail_dto(relationship)

    # ── Reads ────────────────────────────────────────────────────────────

    async def get_scope(self, relationship_id: str) -> TenantId | None:
        """Resolve a relationship's ownership scope (its `tenant_id`;
        `None` means global) without authorizing anything else — exists
        solely for the API layer's ownership-based authorization
        decision, mirroring
        `AttackPatternApplicationService.get_scope`."""
        async with self._uow_factory() as uow:
            relationship = await uow.relationships.get_any(_parse_id(relationship_id))
            if relationship is None:
                raise ApplicationNotFoundError("IntelligenceRelationship", relationship_id)
            return relationship.tenant_id

    async def get(self, query: GetRelationshipQuery) -> RelationshipDetailDTO:
        async with self._uow_factory() as uow:
            relationship = await uow.relationships.get(
                query.tenant_id, _parse_id(query.relationship_id)
            )
            if relationship is None:
                raise ApplicationNotFoundError("IntelligenceRelationship", query.relationship_id)
            return to_detail_dto(relationship)

    async def list(self, query: ListRelationshipsQuery) -> list[RelationshipSummaryDTO]:
        relationship_type = (
            _parse_enum(RelationshipType, query.relationship_type, "relationship_type")
            if query.relationship_type
            else None
        )
        lifecycle_status = (
            _parse_enum(RelationshipLifecycleStatus, query.lifecycle_status, "lifecycle_status")
            if query.lifecycle_status
            else None
        )
        epistemic_state = (
            _parse_enum(EpistemicState, query.epistemic_state, "epistemic_state")
            if query.epistemic_state
            else None
        )
        async with self._uow_factory() as uow:
            relationships = await uow.relationships.list(
                query.tenant_id,
                relationship_type=relationship_type,
                lifecycle_status=lifecycle_status,
                epistemic_state=epistemic_state,
                source_entity_id=query.source_entity_id,
                target_entity_id=query.target_entity_id,
                limit=query.limit,
                offset=query.offset,
            )
            return [to_summary_dto(r) for r in relationships]

    # ── Enrichment ───────────────────────────────────────────────────────

    async def add_evidence_citation(self, cmd: AddEvidenceCitationCommand) -> RelationshipDetailDTO:
        now = datetime.now(UTC)
        citation = EvidenceCitation(value=cmd.value)
        async with self._uow_factory() as uow:
            relationship = await self._require(uow, cmd.tenant_id, cmd.relationship_id)
            relationship.add_evidence_citation(cmd.tenant_id, citation, now)
            await uow.relationships.save(relationship)
            await uow.commit()
            await self._events.publish_batch(relationship.pop_events())
            return to_detail_dto(relationship)

    async def add_source_attribution(
        self, cmd: AddSourceAttributionCommand
    ) -> RelationshipDetailDTO:
        now = datetime.now(UTC)
        attribution = _to_attribution(cmd.attribution)
        async with self._uow_factory() as uow:
            relationship = await self._require(uow, cmd.tenant_id, cmd.relationship_id)
            relationship.add_source_attribution(cmd.tenant_id, attribution, now)
            await uow.relationships.save(relationship)
            await uow.commit()
            await self._events.publish_batch(relationship.pop_events())
            return to_detail_dto(relationship)

    # ── Epistemic axis ───────────────────────────────────────────────────

    async def transition_epistemic_state(
        self, cmd: TransitionEpistemicStateCommand
    ) -> RelationshipDetailDTO:
        target = _parse_enum(EpistemicState, cmd.target_state, "target_state")
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            relationship = await self._require(uow, cmd.tenant_id, cmd.relationship_id)
            relationship.transition_epistemic_state(cmd.tenant_id, target, evidence, now)
            await uow.relationships.save(relationship)
            await uow.commit()
            await self._events.publish_batch(relationship.pop_events())
            return to_detail_dto(relationship)

    # ── Lifecycle axis ───────────────────────────────────────────────────

    async def deprecate(self, cmd: DeprecateRelationshipCommand) -> RelationshipDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            relationship = await self._require(uow, cmd.tenant_id, cmd.relationship_id)
            relationship.deprecate(cmd.tenant_id, evidence, now)
            await uow.relationships.save(relationship)
            await uow.commit()
            await self._events.publish_batch(relationship.pop_events())
            return to_detail_dto(relationship)

    async def revoke(self, cmd: RevokeRelationshipCommand) -> RelationshipDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            relationship = await self._require(uow, cmd.tenant_id, cmd.relationship_id)
            relationship.revoke(cmd.tenant_id, evidence, now)
            await uow.relationships.save(relationship)
            await uow.commit()
            await self._events.publish_batch(relationship.pop_events())
            return to_detail_dto(relationship)

    async def supersede(self, cmd: SupersedeRelationshipCommand) -> RelationshipDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        by = _parse_id(cmd.superseded_by)
        async with self._uow_factory() as uow:
            relationship = await self._require(uow, cmd.tenant_id, cmd.relationship_id)
            relationship.supersede(cmd.tenant_id, by, evidence, now)
            await uow.relationships.save(relationship)
            await uow.commit()
            await self._events.publish_batch(relationship.pop_events())
            return to_detail_dto(relationship)

    async def reactivate(self, cmd: ReactivateRelationshipCommand) -> RelationshipDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            relationship = await self._require(uow, cmd.tenant_id, cmd.relationship_id)
            relationship.reactivate(cmd.tenant_id, evidence, now)
            await uow.relationships.save(relationship)
            await uow.commit()
            await self._events.publish_batch(relationship.pop_events())
            return to_detail_dto(relationship)

    # ── Internal helpers ─────────────────────────────────────────────────

    async def _assert_endpoint_exists(self, ref: EntityRef) -> None:
        """Only the three entity types with a RedForge-native owning
        bounded context can be verified. The other five are opaque by
        design — there is no module to ask, so no check is possible or
        pretended."""
        if ref.entity_type is EntityType.IOC and not await self._iocs.exists(ref.entity_id):
            raise UnknownIocError(ref.entity_id)
        if ref.entity_type is EntityType.THREAT_ACTOR and not await self._threat_actors.exists(
            ref.entity_id
        ):
            raise UnknownThreatActorError(ref.entity_id)
        if ref.entity_type is EntityType.ATTACK_PATTERN and not await self._attack_patterns.exists(
            ref.entity_id
        ):
            raise UnknownAttackPatternError(ref.entity_id)

    async def _require(
        self, uow: IUnitOfWork, tenant_id: TenantId | None, relationship_id: str
    ) -> IntelligenceRelationship:
        relationship = await uow.relationships.get(tenant_id, _parse_id(relationship_id))
        if relationship is None:
            raise ApplicationNotFoundError("IntelligenceRelationship", relationship_id)
        return relationship
