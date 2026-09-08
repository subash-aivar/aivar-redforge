"""AttackPatternApplicationService — the single application-service
class for attack_pattern_intel (M51.3 Phase B1), mirroring
`IOCApplicationService`'s one-class, multi-method shape.

Every mutating method follows the platform-wide flow: validate ->
load/deduplicate -> mutate -> save -> commit -> publish popped domain
events (in that order; events are never published before a successful
commit). Authorization (tenant vs. global, permission checks) happens
exclusively in the API layer — this service trusts the `tenant_id` it
is given.

Dedup is enforced two ways (mirrors `ioc_intelligence`'s exact
discipline): the domain-level `IdentityDedupPolicy`, and a repository
existence check here before insert.

`technique_id` existence is validated against the canonical
`threat_intel` catalog via `IMitreTechniqueIdentityPort` BEFORE the
(pure, sync) domain factory is ever called."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from attack_pattern_intel.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from attack_pattern_intel.application.services.mappers import to_detail_dto, to_summary_dto
from attack_pattern_intel.domain.exceptions.domain_exceptions import (
    DuplicateAttackPatternError,
    UnknownMitreTechniqueError,
)
from attack_pattern_intel.domain.factories.attack_pattern_factory import AttackPatternFactory
from attack_pattern_intel.domain.value_objects.detection_guidance import DetectionGuidance
from attack_pattern_intel.domain.value_objects.enums import TechniqueLifecycleStatus
from attack_pattern_intel.domain.value_objects.evidence import SourceAttribution
from attack_pattern_intel.domain.value_objects.identifiers import AttackPatternId
from attack_pattern_intel.domain.value_objects.mitigation_reference import MitigationReference
from attack_pattern_intel.domain.value_objects.mitre_technique_ref import MitreTechniqueRef
from attack_pattern_intel.domain.value_objects.procedure_example import ProcedureExample
from attack_pattern_intel.domain.value_objects.relationship_metadata import RelationshipMetadata
from attack_pattern_intel.domain.value_objects.tactic_mapping import TacticMapping

if TYPE_CHECKING:
    from collections.abc import Callable

    from attack_pattern_intel.application.commands.attack_pattern_commands import (
        AddDetectionGuidanceCommand,
        AddMitigationReferenceCommand,
        AddProcedureExampleCommand,
        AddRelationshipCommand,
        DeprecateAttackPatternCommand,
        ObserveAttackPatternCommand,
        ReactivateAttackPatternCommand,
        RevokeAttackPatternCommand,
        SourceAttributionInput,
        SupersedeAttackPatternCommand,
    )
    from attack_pattern_intel.application.dtos.attack_pattern_dtos import (
        AttackPatternDetailDTO,
        AttackPatternSummaryDTO,
    )
    from attack_pattern_intel.application.ports.i_event_publisher import IEventPublisher
    from attack_pattern_intel.application.ports.i_mitre_technique_identity_port import (
        IMitreTechniqueIdentityPort,
    )
    from attack_pattern_intel.application.ports.i_unit_of_work import IUnitOfWork
    from attack_pattern_intel.application.queries.attack_pattern_queries import (
        GetAttackPatternQuery,
        ListAttackPatternsQuery,
    )
    from attack_pattern_intel.domain.aggregates.attack_pattern import AttackPattern
    from attack_pattern_intel.domain.value_objects.identifiers import TenantId


def _parse_id(value: str) -> AttackPatternId:
    return AttackPatternId(UUID(value))


def _to_attribution(item: SourceAttributionInput) -> SourceAttribution:
    return SourceAttribution(
        source_system=item.source_system,
        reference=item.reference,
        observed_at=datetime.fromisoformat(item.observed_at),
        notes=item.notes,
    )


class AttackPatternApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        mitre_identity_port: IMitreTechniqueIdentityPort,
        factory: AttackPatternFactory | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._events = event_publisher
        self._mitre = mitre_identity_port
        self._factory = factory or AttackPatternFactory()

    # ── Observation ──────────────────────────────────────────────────────

    async def observe(self, cmd: ObserveAttackPatternCommand) -> AttackPatternDetailDTO:
        mitre_ref = MitreTechniqueRef(
            technique_id=cmd.technique_id, sub_technique_id=cmd.sub_technique_id
        )
        if not await self._mitre.exists(mitre_ref.effective_id):
            raise UnknownMitreTechniqueError(mitre_ref.effective_id)

        now = datetime.now(UTC)
        tactic_mappings = tuple(
            TacticMapping(
                tactic_id=t.tactic_id,
                tactic_shortname=t.tactic_shortname,
                priority=t.priority,
                notes=t.notes,
            )
            for t in cmd.tactic_mappings
        )

        async with self._uow_factory() as uow:
            existing = await uow.attack_patterns.get_by_technique_id(
                cmd.tenant_id, mitre_ref.effective_id
            )
            if existing is not None:
                raise DuplicateAttackPatternError(mitre_ref.effective_id)

            pattern = self._factory.observe(
                tenant_id=cmd.tenant_id,
                mitre_technique_ref=mitre_ref,
                now=now,
                tactic_mappings=tactic_mappings,
                platforms=cmd.platforms,
            )
            await uow.attack_patterns.save(pattern)
            await uow.commit()
            await self._events.publish_batch(pattern.pop_events())
            return to_detail_dto(pattern)

    # ── Reads ────────────────────────────────────────────────────────────

    async def get_scope(self, attack_pattern_id: str) -> TenantId | None:
        """Resolve an AttackPattern's ownership scope (its `tenant_id`;
        `None` means global) without authorizing anything else — exists
        solely for the API layer's ownership-based authorization
        decision, mirroring `IOCApplicationService.get_ioc_scope`."""
        async with self._uow_factory() as uow:
            pattern = await uow.attack_patterns.get_any(_parse_id(attack_pattern_id))
            if pattern is None:
                raise ApplicationNotFoundError("AttackPattern", attack_pattern_id)
            return pattern.tenant_id

    async def get(self, query: GetAttackPatternQuery) -> AttackPatternDetailDTO:
        async with self._uow_factory() as uow:
            pattern = await uow.attack_patterns.get(
                query.tenant_id, _parse_id(query.attack_pattern_id)
            )
            if pattern is None:
                raise ApplicationNotFoundError("AttackPattern", query.attack_pattern_id)
            return to_detail_dto(pattern)

    async def list(self, query: ListAttackPatternsQuery) -> list[AttackPatternSummaryDTO]:
        lifecycle_status = (
            TechniqueLifecycleStatus(query.lifecycle_status) if query.lifecycle_status else None
        )
        async with self._uow_factory() as uow:
            patterns = await uow.attack_patterns.list(
                query.tenant_id,
                lifecycle_status=lifecycle_status,
                tactic_id=query.tactic_id,
                platform=query.platform,
                limit=query.limit,
                offset=query.offset,
            )
            return [to_summary_dto(p) for p in patterns]

    # ── Enrichment ───────────────────────────────────────────────────────

    async def add_detection_guidance(
        self, cmd: AddDetectionGuidanceCommand
    ) -> AttackPatternDetailDTO:
        now = datetime.now(UTC)
        guidance = DetectionGuidance(
            content=cmd.content, attribution=_to_attribution(cmd.attribution)
        )
        async with self._uow_factory() as uow:
            pattern = await self._require(uow, cmd.tenant_id, cmd.attack_pattern_id)
            pattern.add_detection_guidance(cmd.tenant_id, guidance, now)
            await uow.attack_patterns.save(pattern)
            await uow.commit()
            await self._events.publish_batch(pattern.pop_events())
            return to_detail_dto(pattern)

    async def add_mitigation_reference(
        self, cmd: AddMitigationReferenceCommand
    ) -> AttackPatternDetailDTO:
        now = datetime.now(UTC)
        mitigation = MitigationReference(
            mitigation_id=cmd.mitigation_id,
            name=cmd.name,
            description=cmd.description,
            attribution=_to_attribution(cmd.attribution),
        )
        async with self._uow_factory() as uow:
            pattern = await self._require(uow, cmd.tenant_id, cmd.attack_pattern_id)
            pattern.add_mitigation_reference(cmd.tenant_id, mitigation, now)
            await uow.attack_patterns.save(pattern)
            await uow.commit()
            await self._events.publish_batch(pattern.pop_events())
            return to_detail_dto(pattern)

    async def add_procedure_example(
        self, cmd: AddProcedureExampleCommand
    ) -> AttackPatternDetailDTO:
        now = datetime.now(UTC)
        example = ProcedureExample(
            description=cmd.description,
            attribution=_to_attribution(cmd.attribution),
            actor_ref=cmd.actor_ref,
        )
        async with self._uow_factory() as uow:
            pattern = await self._require(uow, cmd.tenant_id, cmd.attack_pattern_id)
            pattern.add_procedure_example(cmd.tenant_id, example, now)
            await uow.attack_patterns.save(pattern)
            await uow.commit()
            await self._events.publish_batch(pattern.pop_events())
            return to_detail_dto(pattern)

    async def add_relationship(self, cmd: AddRelationshipCommand) -> AttackPatternDetailDTO:
        now = datetime.now(UTC)
        relationship = RelationshipMetadata(
            relationship_type=cmd.relationship_type,
            target_attack_pattern_id=_parse_id(cmd.target_attack_pattern_id),
            attribution=_to_attribution(cmd.attribution),
        )
        async with self._uow_factory() as uow:
            pattern = await self._require(uow, cmd.tenant_id, cmd.attack_pattern_id)
            pattern.add_relationship(cmd.tenant_id, relationship, now)
            await uow.attack_patterns.save(pattern)
            await uow.commit()
            await self._events.publish_batch(pattern.pop_events())
            return to_detail_dto(pattern)

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def deprecate(self, cmd: DeprecateAttackPatternCommand) -> AttackPatternDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            pattern = await self._require(uow, cmd.tenant_id, cmd.attack_pattern_id)
            pattern.deprecate(cmd.tenant_id, evidence, now)
            await uow.attack_patterns.save(pattern)
            await uow.commit()
            await self._events.publish_batch(pattern.pop_events())
            return to_detail_dto(pattern)

    async def revoke(self, cmd: RevokeAttackPatternCommand) -> AttackPatternDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            pattern = await self._require(uow, cmd.tenant_id, cmd.attack_pattern_id)
            pattern.revoke(cmd.tenant_id, evidence, now)
            await uow.attack_patterns.save(pattern)
            await uow.commit()
            await self._events.publish_batch(pattern.pop_events())
            return to_detail_dto(pattern)

    async def supersede(self, cmd: SupersedeAttackPatternCommand) -> AttackPatternDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        by = _parse_id(cmd.superseded_by)
        async with self._uow_factory() as uow:
            pattern = await self._require(uow, cmd.tenant_id, cmd.attack_pattern_id)
            pattern.supersede(cmd.tenant_id, by, evidence, now)
            await uow.attack_patterns.save(pattern)
            await uow.commit()
            await self._events.publish_batch(pattern.pop_events())
            return to_detail_dto(pattern)

    async def reactivate(self, cmd: ReactivateAttackPatternCommand) -> AttackPatternDetailDTO:
        now = datetime.now(UTC)
        evidence = _to_attribution(cmd.evidence)
        async with self._uow_factory() as uow:
            pattern = await self._require(uow, cmd.tenant_id, cmd.attack_pattern_id)
            pattern.reactivate(cmd.tenant_id, evidence, now)
            await uow.attack_patterns.save(pattern)
            await uow.commit()
            await self._events.publish_batch(pattern.pop_events())
            return to_detail_dto(pattern)

    # ── Internal helpers ─────────────────────────────────────────────────

    async def _require(
        self, uow: IUnitOfWork, tenant_id: TenantId | None, attack_pattern_id: str
    ) -> AttackPattern:
        pattern = await uow.attack_patterns.get(tenant_id, _parse_id(attack_pattern_id))
        if pattern is None:
            raise ApplicationNotFoundError("AttackPattern", attack_pattern_id)
        return pattern

    @staticmethod
    def _validate_lifecycle_or_raise(value: str) -> None:
        try:
            TechniqueLifecycleStatus(value)
        except ValueError as exc:
            raise ApplicationValidationError(f"Invalid lifecycle_status: {value!r}") from exc
