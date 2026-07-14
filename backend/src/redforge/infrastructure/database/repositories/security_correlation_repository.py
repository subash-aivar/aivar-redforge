"""SecurityCorrelationRepository — M9.

Idempotent upsert semantics mirroring the M8 SecurityCondition pattern:
canonical identity is a tenant-scoped unique constraint (`identity_key`),
not the row's own primary key. Concurrent evaluation of the same
correlation converges on one row via
select-then-insert-with-IntegrityError-fallback-to-refetch. Resolution
is a separate, explicit operation — never folded into upsert — so the
evaluation service's "resolve only after a successful complete cycle"
safety contract has one obvious call site.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from redforge.infrastructure.database.models.security_correlation import (
    SecurityCorrelationConditionModel,
    SecurityCorrelationEntityModel,
    SecurityCorrelationModel,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SecurityCorrelationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(
        self,
        correlation_id: str,
        organization_id: str,
        stable_rule_id: str,
        rule_version: int,
        identity_key: str,
        evidence_state: str,
        title: str,
        summary: str,
        operator_action: str,
        condition_ids: list[str],
        entity_ids: list[str],
    ) -> SecurityCorrelationModel:
        existing = await self._get_by_identity_key(organization_id, identity_key)
        now = datetime.now(UTC)
        if existing is not None:
            existing.evidence_state = evidence_state
            existing.title = title
            existing.summary = summary
            existing.operator_action = operator_action
            existing.lifecycle = "active"
            existing.resolved_at = None
            existing.last_observed_at = now
            existing.version += 1
            await self._session.flush()
            await self._sync_associations(existing.id, organization_id, condition_ids, entity_ids)
            return existing

        model = SecurityCorrelationModel(
            id=correlation_id,
            organization_id=organization_id,
            stable_rule_id=stable_rule_id,
            rule_version=rule_version,
            identity_key=identity_key,
            evidence_state=evidence_state,
            lifecycle="active",
            title=title,
            summary=summary,
            operator_action=operator_action,
            first_observed_at=now,
            last_observed_at=now,
            resolved_at=None,
            version=1,
        )
        self._session.add(model)
        try:
            await self._session.flush()
        except IntegrityError:
            await self._session.rollback()
            winner = await self._get_by_identity_key(organization_id, identity_key)
            if winner is None:  # pragma: no cover - should be unreachable
                raise
            winner.evidence_state = evidence_state
            winner.title = title
            winner.summary = summary
            winner.operator_action = operator_action
            winner.lifecycle = "active"
            winner.resolved_at = None
            winner.last_observed_at = now
            winner.version += 1
            await self._session.flush()
            await self._sync_associations(winner.id, organization_id, condition_ids, entity_ids)
            return winner

        await self._sync_associations(model.id, organization_id, condition_ids, entity_ids)
        return model

    async def _sync_associations(
        self, correlation_id: str, organization_id: str, condition_ids: list[str],
        entity_ids: list[str],
    ) -> None:
        existing_conditions = await self._session.execute(
            select(SecurityCorrelationConditionModel.security_condition_id).where(
                SecurityCorrelationConditionModel.correlation_id == correlation_id
            )
        )
        have_conditions = {row[0] for row in existing_conditions.all()}
        for condition_id in condition_ids:
            if condition_id in have_conditions:
                continue
            self._session.add(
                SecurityCorrelationConditionModel(
                    id=str(EntityId.generate()), correlation_id=correlation_id,
                    organization_id=organization_id, security_condition_id=condition_id,
                )
            )

        existing_entities = await self._session.execute(
            select(SecurityCorrelationEntityModel.asset_id).where(
                SecurityCorrelationEntityModel.correlation_id == correlation_id
            )
        )
        have_entities = {row[0] for row in existing_entities.all()}
        for asset_id in entity_ids:
            if asset_id in have_entities:
                continue
            self._session.add(
                SecurityCorrelationEntityModel(
                    id=str(EntityId.generate()), correlation_id=correlation_id,
                    organization_id=organization_id, asset_id=asset_id,
                )
            )
        await self._session.flush()

    async def get_by_identity_key(
        self, organization_id: str, identity_key: str
    ) -> SecurityCorrelationModel | None:
        return await self._get_by_identity_key(organization_id, identity_key)

    async def _get_by_identity_key(
        self, organization_id: str, identity_key: str
    ) -> SecurityCorrelationModel | None:
        stmt = select(SecurityCorrelationModel).where(
            SecurityCorrelationModel.organization_id == organization_id,
            SecurityCorrelationModel.identity_key == identity_key,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_id_for_org(
        self, correlation_id: str, organization_id: str
    ) -> SecurityCorrelationModel | None:
        stmt = select(SecurityCorrelationModel).where(
            SecurityCorrelationModel.id == correlation_id,
            SecurityCorrelationModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_org(
        self,
        organization_id: str,
        lifecycle: str | None = None,
        stable_rule_id: str | None = None,
        evidence_state: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[SecurityCorrelationModel]:
        stmt = select(SecurityCorrelationModel).where(
            SecurityCorrelationModel.organization_id == organization_id
        )
        if lifecycle is not None:
            stmt = stmt.where(SecurityCorrelationModel.lifecycle == lifecycle)
        if stable_rule_id is not None:
            stmt = stmt.where(SecurityCorrelationModel.stable_rule_id == stable_rule_id)
        if evidence_state is not None:
            stmt = stmt.where(SecurityCorrelationModel.evidence_state == evidence_state)
        stmt = stmt.order_by(SecurityCorrelationModel.id).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count_active(self, organization_id: str) -> int:
        """Count of currently-ACTIVE correlations — a real
        `COUNT(*) WHERE lifecycle='active'` query, the deterministic
        correlation input to the M18 posture score."""
        stmt = select(func.count(SecurityCorrelationModel.id)).where(
            SecurityCorrelationModel.organization_id == organization_id,
            SecurityCorrelationModel.lifecycle == "active",
        )
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def get_condition_ids(
        self, correlation_id: str, organization_id: str
    ) -> list[str]:
        stmt = select(SecurityCorrelationConditionModel.security_condition_id).where(
            SecurityCorrelationConditionModel.correlation_id == correlation_id,
            SecurityCorrelationConditionModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return [row[0] for row in result.all()]

    async def get_entity_ids(
        self, correlation_id: str, organization_id: str
    ) -> list[str]:
        stmt = select(SecurityCorrelationEntityModel.asset_id).where(
            SecurityCorrelationEntityModel.correlation_id == correlation_id,
            SecurityCorrelationEntityModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return [row[0] for row in result.all()]

    async def resolve_stale_for_rule(
        self, organization_id: str, stable_rule_id: str, active_identity_keys: set[str]
    ) -> int:
        """Resolves every ACTIVE correlation for this rule whose
        identity_key is absent from `active_identity_keys` — the set of
        identity keys the CURRENT successful evaluation cycle found.
        Callers MUST only invoke this after a fully successful fact load
        and rule evaluation (see the evaluation service's safety
        contract) — never on a partial/failed cycle. Returns the count
        resolved."""
        stmt = select(SecurityCorrelationModel).where(
            SecurityCorrelationModel.organization_id == organization_id,
            SecurityCorrelationModel.stable_rule_id == stable_rule_id,
            SecurityCorrelationModel.lifecycle == "active",
        )
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        now = datetime.now(UTC)
        resolved_count = 0
        for row in rows:
            if row.identity_key in active_identity_keys:
                continue
            row.lifecycle = "resolved"
            row.resolved_at = now
            row.version += 1
            resolved_count += 1
        if resolved_count:
            await self._session.flush()
        return resolved_count
