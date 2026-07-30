"""PgEnterpriseRiskProfileRepository — SQLAlchemy implementation of the
`EnterpriseRiskProfileRepository` async ABC port (M48C, converted from
a sync `Protocol` in the M48C contract correction — see
`docs/architecture/m48/M48E_ADR.md`).

Now genuinely async over `AsyncSession`/`asyncpg`, matching
`operation.infrastructure.persistence.repositories.
pg_operation_repository.PgOperationRepository` exactly: every DB call
is `await`ed, no synchronous `Session`/`psycopg` involved anywhere.

No optimistic-locking version check is performed on `save()`: unlike
`credential_vault.Credential`, the frozen `EnterpriseRiskProfile`
aggregate carries no `version`/`row_version` field a caller could have
loaded and compared against — inventing one would mean reopening the
frozen M48B aggregate. `row_version` is still persisted and bumped on
every write (useful for auditing/debugging and as a foundation for a
future milestone that *does* thread a version through the aggregate),
but `save()` here is last-writer-wins at the row level, exactly like
every risk_engine command already is at the aggregate level (the
frozen application services always `get()` then mutate then `save()`
within a single unit of work, so there is no multi-step client-side
window for a lost update within one request).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from risk_engine.application.ports.i_risk_profile_repository import (
    EnterpriseRiskProfileRepository,
)
from risk_engine.domain.aggregates.enterprise_risk_profile import EnterpriseRiskProfile
from risk_engine.domain.entities.risk_contribution import RiskContribution
from risk_engine.domain.value_objects.composite_score import CompositeRiskScore
from risk_engine.domain.value_objects.enums import RiskDimension, RiskProfileStatus
from risk_engine.domain.value_objects.identifiers import RiskProfileId, TenantId
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
from risk_engine.infrastructure.persistence.exceptions import RiskEngineIntegrityError
from risk_engine.infrastructure.persistence.mappers import (
    new_uuid,
    row_to_signal_reference,
    signal_reference_to_columns,
)
from risk_engine.infrastructure.persistence.models.risk_profile_model import (
    RiskProfileContributionModel,
    RiskProfileModel,
    RiskProfileScoreHistoryModel,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.ext.asyncio import AsyncSession

_logger = structlog.get_logger("risk_engine.infrastructure.persistence")


def _row_to_profile(row: RiskProfileModel) -> EnterpriseRiskProfile:
    contributions = tuple(
        RiskContribution(
            dimension=RiskDimension(c.dimension),
            normalized_score=NormalizedRiskScore(c.normalized_score),
            source_signal=row_to_signal_reference(c),
            computed_at=c.computed_at,
        )
        for c in sorted(row.contributions, key=lambda c: c.ordinal)
    )
    composite_score = None
    if row.composite_score_value is not None and row.composite_computed_at is not None:
        composite_score = CompositeRiskScore(
            value=NormalizedRiskScore(row.composite_score_value),
            weight_profile_id=row.composite_weight_profile_id or "",
            computed_at=row.composite_computed_at,
        )
    return EnterpriseRiskProfile(
        profile_id=RiskProfileId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        subject_reference=row.subject_reference,
        created_at=row.created_at,
        contributions=contributions,
        composite_score=composite_score,
        status=RiskProfileStatus(row.status),
        updated_at=row.updated_at,
        accepted_expires_at=row.accepted_expires_at,
    )


class PgEnterpriseRiskProfileRepository(EnterpriseRiskProfileRepository):
    """Tenant-scoped, transaction-bound async SQLAlchemy repository
    for `EnterpriseRiskProfile`."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, profile: EnterpriseRiskProfile) -> None:
        try:
            await self._save(profile)
        except IntegrityError as exc:
            await self._session.rollback()
            raise RiskEngineIntegrityError("save EnterpriseRiskProfile", str(exc.orig)) from exc
        except SQLAlchemyError as exc:
            await self._session.rollback()
            raise RiskEngineIntegrityError("save EnterpriseRiskProfile", str(exc)) from exc

    async def _save(self, profile: EnterpriseRiskProfile) -> None:
        profile_uuid = profile.profile_id.value
        tenant_uuid = profile.tenant_id.value.to_uuid()

        row = await self._session.get(RiskProfileModel, profile_uuid)
        composite = profile.composite_score
        if row is None:
            row = RiskProfileModel(
                id=profile_uuid,
                tenant_id=tenant_uuid,
                subject_reference=profile.subject_reference,
                status=profile.status.value,
                created_at=profile.created_at,
                updated_at=profile.updated_at,
                accepted_expires_at=profile.accepted_expires_at,
                composite_score_value=composite.value.value if composite is not None else None,
                composite_weight_profile_id=(
                    composite.weight_profile_id if composite is not None else None
                ),
                composite_computed_at=composite.computed_at if composite is not None else None,
                row_version=1,
            )
            self._session.add(row)
        else:
            row.subject_reference = profile.subject_reference
            row.status = profile.status.value
            row.updated_at = profile.updated_at
            row.accepted_expires_at = profile.accepted_expires_at
            row.composite_score_value = composite.value.value if composite is not None else None
            row.composite_weight_profile_id = (
                composite.weight_profile_id if composite is not None else None
            )
            row.composite_computed_at = composite.computed_at if composite is not None else None
            row.row_version = row.row_version + 1

        # Full replace of contributions — RiskContribution is
        # identity-less and wholesale-replaced by recompute_score.
        await self._session.execute(
            delete(RiskProfileContributionModel).where(
                RiskProfileContributionModel.profile_id == profile_uuid
            )
        )
        for ordinal, contribution in enumerate(profile.contributions):
            self._session.add(
                RiskProfileContributionModel(
                    id=new_uuid(),
                    profile_id=profile_uuid,
                    ordinal=ordinal,
                    dimension=contribution.dimension.value,
                    normalized_score=contribution.normalized_score.value,
                    computed_at=contribution.computed_at,
                    **signal_reference_to_columns(contribution.source_signal),
                )
            )

        # Append-only score-history snapshot — one row per distinct
        # (profile_id, computed_at); idempotent under retries/replays.
        if composite is not None:
            result = await self._session.execute(
                select(RiskProfileScoreHistoryModel.id).where(
                    RiskProfileScoreHistoryModel.profile_id == profile_uuid,
                    RiskProfileScoreHistoryModel.computed_at == composite.computed_at,
                )
            )
            existing = result.scalar_one_or_none()
            if existing is None:
                self._session.add(
                    RiskProfileScoreHistoryModel(
                        id=new_uuid(),
                        profile_id=profile_uuid,
                        tenant_id=tenant_uuid,
                        value=composite.value.value,
                        weight_profile_id=composite.weight_profile_id,
                        computed_at=composite.computed_at,
                    )
                )

        await self._session.flush()
        _logger.info(
            "risk_profile_saved",
            profile_id=str(profile.profile_id),
            tenant_id=str(profile.tenant_id),
            status=profile.status.value,
            contribution_count=len(profile.contributions),
        )

    async def get(
        self, tenant_id: TenantId, profile_id: RiskProfileId
    ) -> EnterpriseRiskProfile | None:
        row = await self._session.get(RiskProfileModel, profile_id.value)
        if row is None:
            return None
        if row.tenant_id != tenant_id.value.to_uuid():
            # Tenant-isolation: a profile that exists under a different
            # tenant must never be distinguishable from "doesn't exist".
            return None
        return _row_to_profile(row)

    async def list(self, tenant_id: TenantId, **filters: object) -> Sequence[EnterpriseRiskProfile]:
        stmt = select(RiskProfileModel).where(
            RiskProfileModel.tenant_id == tenant_id.value.to_uuid()
        )
        status = filters.get("status")
        if status is not None:
            status_value = status.value if isinstance(status, RiskProfileStatus) else status
            stmt = stmt.where(RiskProfileModel.status == status_value)
        subject_reference = filters.get("subject_reference")
        if subject_reference is not None:
            stmt = stmt.where(RiskProfileModel.subject_reference == subject_reference)

        limit = filters.get("limit")
        offset = filters.get("offset")
        stmt = stmt.order_by(RiskProfileModel.created_at.desc())
        if isinstance(offset, int):
            stmt = stmt.offset(offset)
        if isinstance(limit, int):
            stmt = stmt.limit(limit)

        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_profile(row) for row in rows]

    async def score_history(
        self, tenant_id: TenantId, profile_id: RiskProfileId
    ) -> Sequence[CompositeRiskScore]:
        stmt = (
            select(RiskProfileScoreHistoryModel)
            .where(
                RiskProfileScoreHistoryModel.profile_id == profile_id.value,
                RiskProfileScoreHistoryModel.tenant_id == tenant_id.value.to_uuid(),
            )
            .order_by(RiskProfileScoreHistoryModel.computed_at.asc())
        )
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [
            CompositeRiskScore(
                value=NormalizedRiskScore(row.value),
                weight_profile_id=row.weight_profile_id,
                computed_at=row.computed_at,
            )
            for row in rows
        ]
