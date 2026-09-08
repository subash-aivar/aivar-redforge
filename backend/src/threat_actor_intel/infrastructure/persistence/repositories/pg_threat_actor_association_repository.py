"""PgThreatActorAssociationRepository — SQLAlchemy implementation of
`IThreatActorAssociationRepository` (M51.1 Phase 3). Every method
requires `tenant_id` first (ADR-M51.1-03); `get()` treats a row
belonging to a different tenant as not-found, never as a visible-but-
forbidden row — the same tenant-isolation discipline
`PgEnterpriseRiskProfileRepository.get()` established."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from threat_actor_intel.domain.aggregates.threat_actor_association import ThreatActorAssociation
from threat_actor_intel.domain.repositories.i_threat_actor_association_repository import (
    IThreatActorAssociationRepository,
)
from threat_actor_intel.domain.value_objects.enums import AssociationState
from threat_actor_intel.domain.value_objects.evidence import EvidenceCitation
from threat_actor_intel.domain.value_objects.identifiers import (
    TenantId,
    ThreatActorAssociationId,
    ThreatActorId,
)
from threat_actor_intel.domain.value_objects.references import ReferencedEntityRef
from threat_actor_intel.infrastructure.persistence.exceptions import (
    ThreatActorIntelIntegrityError,
)
from threat_actor_intel.infrastructure.persistence.models.threat_actor_models import (
    ThreatActorAssociationModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _row_to_association(row: ThreatActorAssociationModel) -> ThreatActorAssociation:
    return ThreatActorAssociation(
        association_id=ThreatActorAssociationId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        threat_actor_id=ThreatActorId(row.threat_actor_id),
        referenced_entity=ReferencedEntityRef(
            entity_type=row.referenced_entity_type, entity_id=row.referenced_entity_id
        ),
        evidence_citation=EvidenceCitation(row.evidence_citation),
        state=AssociationState(row.state),
        created_at=row.created_at,
        updated_at=row.updated_at,
        retracted_at=row.retracted_at,
    )


class PgThreatActorAssociationRepository(IThreatActorAssociationRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, tenant_id: TenantId, association: ThreatActorAssociation) -> None:
        try:
            await self._save(tenant_id, association)
        except IntegrityError as exc:
            await self._session.rollback()
            raise ThreatActorIntelIntegrityError(
                "save ThreatActorAssociation", str(exc.orig)
            ) from exc
        except SQLAlchemyError as exc:
            await self._session.rollback()
            raise ThreatActorIntelIntegrityError("save ThreatActorAssociation", str(exc)) from exc

    async def _save(self, tenant_id: TenantId, association: ThreatActorAssociation) -> None:
        association_uuid = association.association_id.value
        row = await self._session.get(ThreatActorAssociationModel, association_uuid)
        if row is None:
            row = ThreatActorAssociationModel(
                id=association_uuid,
                tenant_id=tenant_id.value.to_uuid(),
                threat_actor_id=association.threat_actor_id.value,
                referenced_entity_type=association.referenced_entity.entity_type,
                referenced_entity_id=association.referenced_entity.entity_id,
                evidence_citation=str(association.evidence_citation),
                state=association.state.value,
                created_at=association.created_at,
                updated_at=association.updated_at,
                retracted_at=association.retracted_at,
            )
            self._session.add(row)
        else:
            row.state = association.state.value
            row.updated_at = association.updated_at
            row.retracted_at = association.retracted_at

        await self._session.flush()

    async def get(
        self, tenant_id: TenantId, association_id: ThreatActorAssociationId
    ) -> ThreatActorAssociation | None:
        row = await self._session.get(ThreatActorAssociationModel, association_id.value)
        if row is None:
            return None
        if row.tenant_id != tenant_id.value.to_uuid():
            # Tenant isolation: an association belonging to a different
            # tenant must never be distinguishable from "doesn't exist".
            return None
        return _row_to_association(row)

    async def list_for_tenant(
        self, tenant_id: TenantId, threat_actor_id: ThreatActorId | None = None
    ) -> list[ThreatActorAssociation]:
        stmt = select(ThreatActorAssociationModel).where(
            ThreatActorAssociationModel.tenant_id == tenant_id.value.to_uuid()
        )
        if threat_actor_id is not None:
            stmt = stmt.where(ThreatActorAssociationModel.threat_actor_id == threat_actor_id.value)
        stmt = stmt.order_by(ThreatActorAssociationModel.created_at.desc())
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_association(row) for row in rows]
