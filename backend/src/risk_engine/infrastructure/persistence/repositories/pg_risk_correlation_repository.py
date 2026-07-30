"""PgRiskCorrelationRepository — SQLAlchemy implementation of the
`RiskCorrelationRepository` async ABC port (M48C, converted from a
sync `Protocol` in the M48C contract correction — see
`docs/architecture/m48/M48E_ADR.md`). Genuinely async over
`AsyncSession`/`asyncpg`, matching
`operation.infrastructure.persistence.repositories.
pg_operation_repository.PgOperationRepository`'s pattern exactly.

`RiskCorrelationSet` is immutable once formed (no lifecycle
transitions exist on it — it is created once by
`RiskCorrelationApplicationService.form_correlation_sets` and never
mutated again), so `save()` here only ever handles the insert path;
there is no update branch to write."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from risk_engine.application.ports.i_risk_correlation_repository import RiskCorrelationRepository
from risk_engine.domain.aggregates.risk_correlation_set import RiskCorrelationSet
from risk_engine.domain.value_objects.identifiers import CorrelationSetId, TenantId
from risk_engine.infrastructure.persistence.exceptions import RiskEngineIntegrityError
from risk_engine.infrastructure.persistence.mappers import (
    new_uuid,
    row_to_signal_reference,
    signal_reference_to_columns,
)
from risk_engine.infrastructure.persistence.models.risk_correlation_model import (
    RiskCorrelationSetModel,
    RiskCorrelationSignalRefModel,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.ext.asyncio import AsyncSession

_logger = structlog.get_logger("risk_engine.infrastructure.persistence")


def _row_to_correlation_set(row: RiskCorrelationSetModel) -> RiskCorrelationSet:
    signal_references = tuple(
        row_to_signal_reference(ref)
        for ref in sorted(row.signal_references, key=lambda r: r.ordinal)
    )
    return RiskCorrelationSet(
        correlation_set_id=CorrelationSetId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        signal_references=signal_references,
        formed_at=row.formed_at,
    )


class PgRiskCorrelationRepository(RiskCorrelationRepository):
    """Tenant-scoped, transaction-bound async SQLAlchemy repository
    for `RiskCorrelationSet`."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, correlation_set: RiskCorrelationSet) -> None:
        try:
            await self._save(correlation_set)
        except IntegrityError as exc:
            await self._session.rollback()
            raise RiskEngineIntegrityError("save RiskCorrelationSet", str(exc.orig)) from exc
        except SQLAlchemyError as exc:
            await self._session.rollback()
            raise RiskEngineIntegrityError("save RiskCorrelationSet", str(exc)) from exc

    async def _save(self, correlation_set: RiskCorrelationSet) -> None:
        set_uuid = correlation_set.correlation_set_id.value
        tenant_uuid = correlation_set.tenant_id.value.to_uuid()

        row = await self._session.get(RiskCorrelationSetModel, set_uuid)
        if row is None:
            row = RiskCorrelationSetModel(
                id=set_uuid,
                tenant_id=tenant_uuid,
                formed_at=correlation_set.formed_at,
                row_version=1,
            )
            self._session.add(row)
            await self._session.flush()
            for ordinal, signal in enumerate(correlation_set.signal_references):
                self._session.add(
                    RiskCorrelationSignalRefModel(
                        id=new_uuid(),
                        correlation_set_id=set_uuid,
                        ordinal=ordinal,
                        **signal_reference_to_columns(signal),
                    )
                )
        # else: RiskCorrelationSet is immutable once formed; a repeat
        # save() of the same id is treated as a no-op rather than
        # re-writing signal references that can never change.

        await self._session.flush()
        _logger.info(
            "risk_correlation_set_saved",
            correlation_set_id=str(correlation_set.correlation_set_id),
            tenant_id=str(correlation_set.tenant_id),
            signal_count=len(correlation_set.signal_references),
        )

    async def get(
        self, tenant_id: TenantId, correlation_set_id: CorrelationSetId
    ) -> RiskCorrelationSet | None:
        row = await self._session.get(RiskCorrelationSetModel, correlation_set_id.value)
        if row is None:
            return None
        if row.tenant_id != tenant_id.value.to_uuid():
            return None
        return _row_to_correlation_set(row)

    async def list(self, tenant_id: TenantId) -> Sequence[RiskCorrelationSet]:
        stmt = (
            select(RiskCorrelationSetModel)
            .where(RiskCorrelationSetModel.tenant_id == tenant_id.value.to_uuid())
            .order_by(RiskCorrelationSetModel.formed_at.desc())
        )
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_correlation_set(row) for row in rows]
