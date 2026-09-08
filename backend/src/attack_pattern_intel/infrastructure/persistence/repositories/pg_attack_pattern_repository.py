"""PgAttackPatternRepository — SQLAlchemy implementation of
`IAttackPatternRepository` (M51.3 Phase B1), mirroring
`ioc_intelligence.infrastructure.persistence.repositories.
pg_ioc_repository.PgIocRepository`'s translation shape (no business
logic, no authorization) plus its real optimistic-concurrency
compare-and-swap pattern.

Tenant scoping is query-enforced everywhere: every read filters by
`tenant_id == scope` (`scope=None` meaning "global rows only"), so a
row belonging to a different scope is indistinguishable from "does not
exist".

Child collections (guidance, mitigations, procedure examples,
relationships) are wholesale-replaced on every `save()` — the
aggregate itself is the sole authority on their contents. Version
history is append-only: only rows whose `version` is not already
persisted are inserted, matching the aggregate's own append-only
invariant."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from attack_pattern_intel.application.ports.i_attack_pattern_repository import (
    IAttackPatternRepository,
)
from attack_pattern_intel.domain.aggregates.attack_pattern import AttackPattern
from attack_pattern_intel.domain.value_objects.detection_guidance import DetectionGuidance
from attack_pattern_intel.domain.value_objects.enums import TechniqueLifecycleStatus
from attack_pattern_intel.domain.value_objects.evidence import SourceAttribution
from attack_pattern_intel.domain.value_objects.identifiers import AttackPatternId, TenantId
from attack_pattern_intel.domain.value_objects.mitigation_reference import MitigationReference
from attack_pattern_intel.domain.value_objects.mitre_technique_ref import MitreTechniqueRef
from attack_pattern_intel.domain.value_objects.procedure_example import ProcedureExample
from attack_pattern_intel.domain.value_objects.relationship_metadata import RelationshipMetadata
from attack_pattern_intel.domain.value_objects.tactic_mapping import TacticMapping
from attack_pattern_intel.domain.value_objects.version_record import VersionRecord
from attack_pattern_intel.infrastructure.persistence.exceptions import (
    AttackPatternIntelIntegrityError,
    OptimisticLockConflictError,
)
from attack_pattern_intel.infrastructure.persistence.models.attack_pattern_models import (
    AttackPatternDetectionGuidanceModel,
    AttackPatternMitigationReferenceModel,
    AttackPatternModel,
    AttackPatternProcedureExampleModel,
    AttackPatternRelationshipModel,
    AttackPatternVersionModel,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql.elements import ColumnElement


def _tenant_uuid(tenant_id: TenantId | None) -> UUID | None:
    return None if tenant_id is None else tenant_id.value.to_uuid()


def _tenant_filter(tenant_uuid: UUID | None) -> ColumnElement[bool]:
    if tenant_uuid is None:
        return AttackPatternModel.tenant_id.is_(None)
    return AttackPatternModel.tenant_id == tenant_uuid


def _row_to_pattern(row: AttackPatternModel) -> AttackPattern:
    ref = MitreTechniqueRef(technique_id=row.technique_id, sub_technique_id=row.sub_technique_id)
    pattern = AttackPattern(
        attack_pattern_id=AttackPatternId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id) if row.tenant_id is not None else None,
        mitre_technique_ref=ref,
        lifecycle_status=TechniqueLifecycleStatus(row.lifecycle_status),
        created_at=row.created_at,
        updated_at=row.updated_at,
        tactic_mappings=tuple(
            TacticMapping(
                tactic_id=str(t["tactic_id"]),
                tactic_shortname=str(t["tactic_shortname"]),
                priority=int(t.get("priority", 0)),  # type: ignore[call-overload]
                notes=str(t.get("notes", "")),
            )
            for t in row.tactic_mappings
        ),
        platforms=tuple(row.platforms),
        data_sources=(),
        data_components=(),
        detection_guidance=tuple(
            DetectionGuidance(
                content=g.content,
                attribution=SourceAttribution(
                    source_system=g.source_system,
                    reference=g.reference,
                    observed_at=g.observed_at,
                    notes=g.notes,
                ),
            )
            for g in row.detection_guidance
        ),
        mitigation_references=tuple(
            MitigationReference(
                mitigation_id=m.mitigation_id,
                name=m.name,
                description=m.description,
                attribution=SourceAttribution(
                    source_system=m.source_system,
                    reference=m.reference,
                    observed_at=m.observed_at,
                    notes=m.notes,
                ),
            )
            for m in row.mitigation_references
        ),
        procedure_examples=tuple(
            ProcedureExample(
                description=p.description,
                actor_ref=p.actor_ref,
                attribution=SourceAttribution(
                    source_system=p.source_system,
                    reference=p.reference,
                    observed_at=p.observed_at,
                    notes=p.notes,
                ),
            )
            for p in row.procedure_examples
        ),
        relationship_metadata=tuple(
            RelationshipMetadata(
                relationship_type=r.relationship_type,
                target_attack_pattern_id=AttackPatternId(r.target_attack_pattern_id),
                attribution=SourceAttribution(
                    source_system=r.source_system,
                    reference=r.reference,
                    observed_at=r.observed_at,
                    notes=r.notes,
                ),
            )
            for r in row.relationship_metadata
        ),
        version_history=tuple(
            VersionRecord(
                version=v.version,
                changed_at=v.changed_at,
                change_summary=v.change_summary,
                source=v.source,
            )
            for v in sorted(row.version_history, key=lambda v: v.version)
        ),
        superseded_by=AttackPatternId(row.superseded_by) if row.superseded_by else None,
        row_version=row.row_version,
    )
    return pattern


class PgAttackPatternRepository(IAttackPatternRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, pattern: AttackPattern) -> None:
        try:
            await self._save(pattern)
        except IntegrityError as exc:
            raise AttackPatternIntelIntegrityError("save AttackPattern", str(exc.orig)) from exc
        except SQLAlchemyError as exc:
            raise AttackPatternIntelIntegrityError("save AttackPattern", str(exc)) from exc

    async def _save(self, pattern: AttackPattern) -> None:
        pattern_uuid = pattern.attack_pattern_id.value
        tenant_uuid = _tenant_uuid(pattern.tenant_id)
        superseded_by_uuid = (
            pattern.superseded_by.value if pattern.superseded_by is not None else None
        )
        tactic_mappings_json = [
            {
                "tactic_id": t.tactic_id,
                "tactic_shortname": t.tactic_shortname,
                "priority": t.priority,
                "notes": t.notes,
            }
            for t in pattern.tactic_mappings
        ]

        row = await self._session.get(AttackPatternModel, pattern_uuid)
        if row is None:
            row = AttackPatternModel(
                id=pattern_uuid,
                tenant_id=tenant_uuid,
                technique_id=pattern.mitre_technique_ref.technique_id,
                sub_technique_id=pattern.mitre_technique_ref.sub_technique_id,
                lifecycle_status=pattern.lifecycle_status.value,
                superseded_by=superseded_by_uuid,
                tactic_mappings=tactic_mappings_json,
                platforms=list(pattern.platforms),
                created_at=pattern.created_at,
                updated_at=pattern.updated_at,
                row_version=1,
            )
            self._session.add(row)
            await self._replace_children(pattern, pattern_uuid)
            await self._session.flush()
            pattern.row_version = 1
            return

        expected = pattern.row_version
        result = await self._session.execute(
            update(AttackPatternModel)
            .where(
                AttackPatternModel.id == pattern_uuid,
                AttackPatternModel.row_version == expected,
            )
            .values(
                tenant_id=tenant_uuid,
                lifecycle_status=pattern.lifecycle_status.value,
                superseded_by=superseded_by_uuid,
                tactic_mappings=tactic_mappings_json,
                platforms=list(pattern.platforms),
                updated_at=pattern.updated_at,
                row_version=expected + 1,
            )
            .returning(AttackPatternModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            actual_row = await self._session.get(AttackPatternModel, pattern_uuid)
            actual = actual_row.row_version if actual_row is not None else -1
            raise OptimisticLockConflictError(str(pattern.attack_pattern_id), expected, actual)

        await self._replace_children(pattern, pattern_uuid)
        await self._session.flush()
        pattern.row_version = int(new_version)

    async def _replace_children(self, pattern: AttackPattern, pattern_uuid: UUID) -> None:
        await self._session.execute(
            delete(AttackPatternDetectionGuidanceModel).where(
                AttackPatternDetectionGuidanceModel.attack_pattern_id == pattern_uuid
            )
        )
        for guidance in pattern.detection_guidance:
            self._session.add(
                AttackPatternDetectionGuidanceModel(
                    id=uuid4(),
                    attack_pattern_id=pattern_uuid,
                    content=guidance.content,
                    source_system=guidance.attribution.source_system,
                    reference=guidance.attribution.reference,
                    observed_at=guidance.attribution.observed_at,
                    notes=guidance.attribution.notes,
                )
            )

        await self._session.execute(
            delete(AttackPatternMitigationReferenceModel).where(
                AttackPatternMitigationReferenceModel.attack_pattern_id == pattern_uuid
            )
        )
        for mitigation in pattern.mitigation_references:
            self._session.add(
                AttackPatternMitigationReferenceModel(
                    id=uuid4(),
                    attack_pattern_id=pattern_uuid,
                    mitigation_id=mitigation.mitigation_id,
                    name=mitigation.name,
                    description=mitigation.description,
                    source_system=mitigation.attribution.source_system,
                    reference=mitigation.attribution.reference,
                    observed_at=mitigation.attribution.observed_at,
                    notes=mitigation.attribution.notes,
                )
            )

        await self._session.execute(
            delete(AttackPatternProcedureExampleModel).where(
                AttackPatternProcedureExampleModel.attack_pattern_id == pattern_uuid
            )
        )
        for example in pattern.procedure_examples:
            self._session.add(
                AttackPatternProcedureExampleModel(
                    id=uuid4(),
                    attack_pattern_id=pattern_uuid,
                    description=example.description,
                    actor_ref=example.actor_ref,
                    source_system=example.attribution.source_system,
                    reference=example.attribution.reference,
                    observed_at=example.attribution.observed_at,
                    notes=example.attribution.notes,
                )
            )

        await self._session.execute(
            delete(AttackPatternRelationshipModel).where(
                AttackPatternRelationshipModel.attack_pattern_id == pattern_uuid
            )
        )
        for relationship in pattern.relationship_metadata:
            self._session.add(
                AttackPatternRelationshipModel(
                    id=uuid4(),
                    attack_pattern_id=pattern_uuid,
                    relationship_type=relationship.relationship_type,
                    target_attack_pattern_id=relationship.target_attack_pattern_id.value,
                    source_system=relationship.attribution.source_system,
                    reference=relationship.attribution.reference,
                    observed_at=relationship.attribution.observed_at,
                    notes=relationship.attribution.notes,
                )
            )

        # Version history is append-only: only insert versions not
        # already persisted (never delete/replace, matching the
        # aggregate's own append-only invariant).
        result = await self._session.execute(
            select(AttackPatternVersionModel.version).where(
                AttackPatternVersionModel.attack_pattern_id == pattern_uuid
            )
        )
        existing_versions = {row[0] for row in result.all()}
        for record in pattern.version_history:
            if record.version not in existing_versions:
                self._session.add(
                    AttackPatternVersionModel(
                        id=uuid4(),
                        attack_pattern_id=pattern_uuid,
                        version=record.version,
                        changed_at=record.changed_at,
                        change_summary=record.change_summary,
                        source=record.source,
                    )
                )

    async def get(
        self, tenant_id: TenantId | None, attack_pattern_id: AttackPatternId
    ) -> AttackPattern | None:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(AttackPatternModel).where(AttackPatternModel.id == attack_pattern_id.value)
        stmt = stmt.where(_tenant_filter(tenant_uuid))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_pattern(row)

    async def get_any(self, attack_pattern_id: AttackPatternId) -> AttackPattern | None:
        row = await self._session.get(AttackPatternModel, attack_pattern_id.value)
        if row is None:
            return None
        return _row_to_pattern(row)

    async def get_by_technique_id(
        self, tenant_id: TenantId | None, effective_technique_id: str
    ) -> AttackPattern | None:
        tenant_uuid = _tenant_uuid(tenant_id)
        if "." in effective_technique_id:
            base, _, _rest = effective_technique_id.partition(".")
            stmt = select(AttackPatternModel).where(
                AttackPatternModel.technique_id == base,
                AttackPatternModel.sub_technique_id == effective_technique_id,
            )
        else:
            stmt = select(AttackPatternModel).where(
                AttackPatternModel.technique_id == effective_technique_id,
                AttackPatternModel.sub_technique_id.is_(None),
            )
        stmt = stmt.where(_tenant_filter(tenant_uuid))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_pattern(row)

    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: TechniqueLifecycleStatus | None = None,
        tactic_id: str | None = None,
        platform: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AttackPattern]:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(AttackPatternModel).where(_tenant_filter(tenant_uuid))
        if lifecycle_status is not None:
            stmt = stmt.where(AttackPatternModel.lifecycle_status == lifecycle_status.value)
        if platform is not None:
            stmt = stmt.where(AttackPatternModel.platforms.contains([platform]))
        # Stable ordering (created_at, then id as a tiebreaker) is
        # required for pagination to be well-defined across pages.
        stmt = stmt.order_by(AttackPatternModel.created_at.desc(), AttackPatternModel.id.desc())
        stmt = stmt.limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        patterns = [_row_to_pattern(row) for row in rows]
        if tactic_id is not None:
            patterns = [
                p for p in patterns if any(t.tactic_id == tactic_id for t in p.tactic_mappings)
            ]
        return patterns
