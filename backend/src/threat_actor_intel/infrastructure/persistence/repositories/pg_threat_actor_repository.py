"""PgThreatActorRepository — SQLAlchemy implementation of
`IThreatActorRepository` (M51.1 Phase 3), mirroring
`risk_engine.infrastructure.persistence.repositories.
pg_risk_profile_repository.PgEnterpriseRiskProfileRepository`'s shape
exactly: async over `AsyncSession`, full child-row replace on save
(aliases/techniques/indicators are identity-less, wholesale-replaced
sets on the aggregate, exactly like `RiskContribution`).

No `tenant_id` parameter anywhere — `ThreatActor` is the platform's
single canonical, global reference model (ADR-M51.1-01/02); this
repository translates between the domain and persistence only, no
business logic, no authorization."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from threat_actor_intel.domain.aggregates.threat_actor import ThreatActor
from threat_actor_intel.domain.repositories.i_threat_actor_repository import (
    IThreatActorRepository,
)
from threat_actor_intel.domain.value_objects.enums import (
    ActivityStatus,
    AttributionConfidence,
    MotivationType,
    SophisticationLevel,
    ThreatActorOrigin,
)
from threat_actor_intel.domain.value_objects.identifiers import TenantId, ThreatActorId
from threat_actor_intel.domain.value_objects.identity import Alias, ThreatActorName
from threat_actor_intel.domain.value_objects.references import (
    AttackTechniqueReference,
    FusedIndicatorReference,
)
from threat_actor_intel.infrastructure.persistence.exceptions import (
    ThreatActorIntelIntegrityError,
)
from threat_actor_intel.infrastructure.persistence.models.threat_actor_models import (
    ThreatActorAliasModel,
    ThreatActorIndicatorModel,
    ThreatActorModel,
    ThreatActorTechniqueModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _row_to_actor(row: ThreatActorModel) -> ThreatActor:
    return ThreatActor(
        threat_actor_id=ThreatActorId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id) if row.tenant_id is not None else None,
        name=ThreatActorName(row.name),
        origin=ThreatActorOrigin(row.origin),
        motivations=frozenset(MotivationType(m) for m in row.motivations),
        sophistication=SophisticationLevel(row.sophistication),
        status=ActivityStatus(row.status),
        created_at=row.created_at,
        updated_at=row.updated_at,
        aliases=tuple(Alias(a.alias) for a in row.aliases),
        technique_refs=tuple(AttackTechniqueReference(t.technique_id) for t in row.techniques),
        indicator_refs=tuple(FusedIndicatorReference(i.indicator_id) for i in row.indicators),
        attribution_confidence=AttributionConfidence(row.attribution_confidence),
    )


class PgThreatActorRepository(IThreatActorRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, actor: ThreatActor) -> None:
        try:
            await self._save(actor)
        except IntegrityError as exc:
            await self._session.rollback()
            raise ThreatActorIntelIntegrityError("save ThreatActor", str(exc.orig)) from exc
        except SQLAlchemyError as exc:
            await self._session.rollback()
            raise ThreatActorIntelIntegrityError("save ThreatActor", str(exc)) from exc

    async def _save(self, actor: ThreatActor) -> None:
        actor_uuid = actor.threat_actor_id.value
        tenant_uuid = actor.tenant_id.value.to_uuid() if actor.tenant_id is not None else None

        row = await self._session.get(ThreatActorModel, actor_uuid)
        if row is None:
            row = ThreatActorModel(
                id=actor_uuid,
                tenant_id=tenant_uuid,
                name=str(actor.name),
                origin=actor.origin.value,
                sophistication=actor.sophistication.value,
                status=actor.status.value,
                attribution_confidence=actor.attribution_confidence.value,
                motivations=sorted(m.value for m in actor.motivations),
                created_at=actor.created_at,
                updated_at=actor.updated_at,
                row_version=1,
            )
            self._session.add(row)
        else:
            row.tenant_id = tenant_uuid
            row.name = str(actor.name)
            row.origin = actor.origin.value
            row.sophistication = actor.sophistication.value
            row.status = actor.status.value
            row.attribution_confidence = actor.attribution_confidence.value
            row.motivations = sorted(m.value for m in actor.motivations)
            row.updated_at = actor.updated_at
            row.row_version = row.row_version + 1

        # Full replace of aliases/techniques/indicators — identity-less,
        # wholesale-replaced sets on the aggregate (mirrors
        # `PgEnterpriseRiskProfileRepository`'s contributions handling).
        await self._session.execute(
            delete(ThreatActorAliasModel).where(ThreatActorAliasModel.threat_actor_id == actor_uuid)
        )
        for alias in actor.aliases:
            self._session.add(
                ThreatActorAliasModel(id=uuid4(), threat_actor_id=actor_uuid, alias=str(alias))
            )

        await self._session.execute(
            delete(ThreatActorTechniqueModel).where(
                ThreatActorTechniqueModel.threat_actor_id == actor_uuid
            )
        )
        for technique_ref in actor.technique_refs:
            self._session.add(
                ThreatActorTechniqueModel(
                    id=uuid4(), threat_actor_id=actor_uuid, technique_id=technique_ref.technique_id
                )
            )

        await self._session.execute(
            delete(ThreatActorIndicatorModel).where(
                ThreatActorIndicatorModel.threat_actor_id == actor_uuid
            )
        )
        for indicator_ref in actor.indicator_refs:
            self._session.add(
                ThreatActorIndicatorModel(
                    id=uuid4(),
                    threat_actor_id=actor_uuid,
                    indicator_id=indicator_ref.indicator_id,
                )
            )

        await self._session.flush()

    async def get(self, threat_actor_id: ThreatActorId) -> ThreatActor | None:
        row = await self._session.get(ThreatActorModel, threat_actor_id.value)
        if row is None:
            return None
        return _row_to_actor(row)

    async def list(
        self,
        status: ActivityStatus | None = None,
        origin: ThreatActorOrigin | None = None,
    ) -> list[ThreatActor]:
        stmt = select(ThreatActorModel)
        if status is not None:
            stmt = stmt.where(ThreatActorModel.status == status.value)
        if origin is not None:
            stmt = stmt.where(ThreatActorModel.origin == origin.value)
        stmt = stmt.order_by(ThreatActorModel.created_at.desc())
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_actor(row) for row in rows]
