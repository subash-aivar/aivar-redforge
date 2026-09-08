"""PgIntelligenceRelationshipRepository — SQLAlchemy implementation of
`IIntelligenceRelationshipRepository` (M51.4 Phase C1), mirroring
`attack_pattern_intel`'s `PgAttackPatternRepository` translation shape
(no business logic, no authorization) plus its real
optimistic-concurrency compare-and-swap pattern.

Tenant scoping is query-enforced everywhere: every read filters by
`tenant_id == scope` (`scope=None` meaning "global rows only"), so a
row belonging to a different scope is indistinguishable from "does not
exist".

Child collections (evidence citations, source attributions) are
wholesale-replaced on every `save()` — the aggregate itself is the
sole authority on their contents; `position` preserves their
append order. Version history is append-only: only rows whose
`version` is not already persisted are inserted, matching the
aggregate's own append-only invariant.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from intelligence_relationships.application.ports.i_relationship_repository import (
    IIntelligenceRelationshipRepository,
)
from intelligence_relationships.domain.aggregates.intelligence_relationship import (
    IntelligenceRelationship,
)
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
    TenantId,
)
from intelligence_relationships.domain.value_objects.validity import Validity
from intelligence_relationships.domain.value_objects.version_record import VersionRecord
from intelligence_relationships.infrastructure.persistence.exceptions import (
    IntelligenceRelationshipsIntegrityError,
    OptimisticLockConflictError,
)
from intelligence_relationships.infrastructure.persistence.models.relationship_models import (
    IntelligenceRelationshipEvidenceCitationModel,
    IntelligenceRelationshipModel,
    IntelligenceRelationshipSourceAttributionModel,
    IntelligenceRelationshipVersionModel,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql.elements import ColumnElement


def _tenant_uuid(tenant_id: TenantId | None) -> UUID | None:
    return None if tenant_id is None else tenant_id.value.to_uuid()


def _tenant_filter(tenant_uuid: UUID | None) -> ColumnElement[bool]:
    if tenant_uuid is None:
        return IntelligenceRelationshipModel.tenant_id.is_(None)
    return IntelligenceRelationshipModel.tenant_id == tenant_uuid


def _row_to_relationship(row: IntelligenceRelationshipModel) -> IntelligenceRelationship:
    return IntelligenceRelationship(
        relationship_id=IntelligenceRelationshipId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id) if row.tenant_id is not None else None,
        relationship_type=RelationshipType(row.relationship_type),
        source_entity=EntityRef(
            entity_type=EntityType(row.source_entity_type), entity_id=row.source_entity_id
        ),
        target_entity=EntityRef(
            entity_type=EntityType(row.target_entity_type), entity_id=row.target_entity_id
        ),
        direction=RelationshipDirection(row.direction),
        confidence=RelationshipConfidence(row.confidence),
        epistemic_state=EpistemicState(row.epistemic_state),
        lifecycle_status=RelationshipLifecycleStatus(row.lifecycle_status),
        validity=Validity(valid_from=row.valid_from, valid_until=row.valid_until),
        created_at=row.created_at,
        updated_at=row.updated_at,
        evidence_citations=tuple(
            EvidenceCitation(value=c.value)
            for c in sorted(row.evidence_citations, key=lambda c: c.position)
        ),
        source_attributions=tuple(
            SourceAttribution(
                source_system=a.source_system,
                reference=a.reference,
                observed_at=a.observed_at,
                confidence=RelationshipConfidence(a.confidence),
                notes=a.notes,
            )
            for a in sorted(row.source_attributions, key=lambda a: a.position)
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
        superseded_by=(
            IntelligenceRelationshipId(row.superseded_by) if row.superseded_by else None
        ),
        row_version=row.row_version,
    )


class PgIntelligenceRelationshipRepository(IIntelligenceRelationshipRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, relationship: IntelligenceRelationship) -> None:
        try:
            await self._save(relationship)
        except IntegrityError as exc:
            raise IntelligenceRelationshipsIntegrityError(
                "save IntelligenceRelationship", str(exc.orig)
            ) from exc
        except SQLAlchemyError as exc:
            raise IntelligenceRelationshipsIntegrityError(
                "save IntelligenceRelationship", str(exc)
            ) from exc

    async def _save(self, relationship: IntelligenceRelationship) -> None:
        relationship_uuid = relationship.relationship_id.value
        tenant_uuid = _tenant_uuid(relationship.tenant_id)
        superseded_by_uuid = (
            relationship.superseded_by.value if relationship.superseded_by is not None else None
        )

        row = await self._session.get(IntelligenceRelationshipModel, relationship_uuid)
        if row is None:
            row = IntelligenceRelationshipModel(
                id=relationship_uuid,
                tenant_id=tenant_uuid,
                relationship_type=relationship.relationship_type.value,
                source_entity_type=relationship.source_entity.entity_type.value,
                source_entity_id=relationship.source_entity.entity_id,
                target_entity_type=relationship.target_entity.entity_type.value,
                target_entity_id=relationship.target_entity.entity_id,
                direction=relationship.direction.value,
                confidence=relationship.confidence.value,
                epistemic_state=relationship.epistemic_state.value,
                lifecycle_status=relationship.lifecycle_status.value,
                superseded_by=superseded_by_uuid,
                valid_from=relationship.validity.valid_from,
                valid_until=relationship.validity.valid_until,
                created_at=relationship.created_at,
                updated_at=relationship.updated_at,
                row_version=1,
            )
            self._session.add(row)
            await self._replace_children(relationship, relationship_uuid)
            await self._session.flush()
            relationship.row_version = 1
            return

        expected = relationship.row_version
        result = await self._session.execute(
            update(IntelligenceRelationshipModel)
            .where(
                IntelligenceRelationshipModel.id == relationship_uuid,
                IntelligenceRelationshipModel.row_version == expected,
            )
            .values(
                tenant_id=tenant_uuid,
                direction=relationship.direction.value,
                confidence=relationship.confidence.value,
                epistemic_state=relationship.epistemic_state.value,
                lifecycle_status=relationship.lifecycle_status.value,
                superseded_by=superseded_by_uuid,
                valid_from=relationship.validity.valid_from,
                valid_until=relationship.validity.valid_until,
                updated_at=relationship.updated_at,
                row_version=expected + 1,
            )
            .returning(IntelligenceRelationshipModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            actual_row = await self._session.get(IntelligenceRelationshipModel, relationship_uuid)
            actual = actual_row.row_version if actual_row is not None else -1
            raise OptimisticLockConflictError(str(relationship.relationship_id), expected, actual)

        await self._replace_children(relationship, relationship_uuid)
        await self._session.flush()
        relationship.row_version = int(new_version)

    async def _replace_children(
        self, relationship: IntelligenceRelationship, relationship_uuid: UUID
    ) -> None:
        await self._session.execute(
            delete(IntelligenceRelationshipEvidenceCitationModel).where(
                IntelligenceRelationshipEvidenceCitationModel.relationship_id == relationship_uuid
            )
        )
        for position, citation in enumerate(relationship.evidence_citations):
            self._session.add(
                IntelligenceRelationshipEvidenceCitationModel(
                    id=uuid4(),
                    relationship_id=relationship_uuid,
                    value=citation.value,
                    position=position,
                )
            )

        await self._session.execute(
            delete(IntelligenceRelationshipSourceAttributionModel).where(
                IntelligenceRelationshipSourceAttributionModel.relationship_id == relationship_uuid
            )
        )
        for position, attribution in enumerate(relationship.source_attributions):
            self._session.add(
                IntelligenceRelationshipSourceAttributionModel(
                    id=uuid4(),
                    relationship_id=relationship_uuid,
                    source_system=attribution.source_system,
                    reference=attribution.reference,
                    observed_at=attribution.observed_at,
                    confidence=attribution.confidence.value,
                    notes=attribution.notes,
                    position=position,
                )
            )

        # Version history is append-only: only insert versions not
        # already persisted (never delete/replace, matching the
        # aggregate's own append-only invariant).
        result = await self._session.execute(
            select(IntelligenceRelationshipVersionModel.version).where(
                IntelligenceRelationshipVersionModel.relationship_id == relationship_uuid
            )
        )
        existing_versions = {row[0] for row in result.all()}
        for record in relationship.version_history:
            if record.version not in existing_versions:
                self._session.add(
                    IntelligenceRelationshipVersionModel(
                        id=uuid4(),
                        relationship_id=relationship_uuid,
                        version=record.version,
                        changed_at=record.changed_at,
                        change_summary=record.change_summary,
                        source=record.source,
                    )
                )

    async def get(
        self, tenant_id: TenantId | None, relationship_id: IntelligenceRelationshipId
    ) -> IntelligenceRelationship | None:
        stmt = (
            select(IntelligenceRelationshipModel)
            .where(IntelligenceRelationshipModel.id == relationship_id.value)
            .where(_tenant_filter(_tenant_uuid(tenant_id)))
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_relationship(row)

    async def get_any(
        self, relationship_id: IntelligenceRelationshipId
    ) -> IntelligenceRelationship | None:
        row = await self._session.get(IntelligenceRelationshipModel, relationship_id.value)
        if row is None:
            return None
        return _row_to_relationship(row)

    async def get_by_identity(
        self,
        tenant_id: TenantId | None,
        relationship_type: RelationshipType,
        source_entity: EntityRef,
        target_entity: EntityRef,
    ) -> IntelligenceRelationship | None:
        stmt = (
            select(IntelligenceRelationshipModel)
            .where(
                IntelligenceRelationshipModel.relationship_type == relationship_type.value,
                IntelligenceRelationshipModel.source_entity_type == source_entity.entity_type.value,
                IntelligenceRelationshipModel.source_entity_id == source_entity.entity_id,
                IntelligenceRelationshipModel.target_entity_type == target_entity.entity_type.value,
                IntelligenceRelationshipModel.target_entity_id == target_entity.entity_id,
            )
            .where(_tenant_filter(_tenant_uuid(tenant_id)))
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_relationship(row)

    async def list(
        self,
        tenant_id: TenantId | None,
        relationship_type: RelationshipType | None = None,
        lifecycle_status: RelationshipLifecycleStatus | None = None,
        epistemic_state: EpistemicState | None = None,
        source_entity_id: str | None = None,
        target_entity_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[IntelligenceRelationship]:
        stmt = select(IntelligenceRelationshipModel).where(_tenant_filter(_tenant_uuid(tenant_id)))
        if relationship_type is not None:
            stmt = stmt.where(
                IntelligenceRelationshipModel.relationship_type == relationship_type.value
            )
        if lifecycle_status is not None:
            stmt = stmt.where(
                IntelligenceRelationshipModel.lifecycle_status == lifecycle_status.value
            )
        if epistemic_state is not None:
            stmt = stmt.where(
                IntelligenceRelationshipModel.epistemic_state == epistemic_state.value
            )
        if source_entity_id is not None:
            stmt = stmt.where(IntelligenceRelationshipModel.source_entity_id == source_entity_id)
        if target_entity_id is not None:
            stmt = stmt.where(IntelligenceRelationshipModel.target_entity_id == target_entity_id)
        # Stable ordering (created_at, then id as a tiebreaker) is
        # required for pagination to be well-defined across pages.
        stmt = stmt.order_by(
            IntelligenceRelationshipModel.created_at.desc(),
            IntelligenceRelationshipModel.id.desc(),
        )
        stmt = stmt.limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return [_row_to_relationship(row) for row in result.scalars().all()]
