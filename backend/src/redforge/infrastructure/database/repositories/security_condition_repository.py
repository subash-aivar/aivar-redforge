"""SecurityConditionRepository — M8.

Idempotent upsert semantics mirroring the M3/M6/M7 asset-resolution
pattern: canonical identity is a tenant-scoped unique constraint
(`identity_key`), not the row's own primary key. Concurrent ingestion
of the same condition converges on one row via
select-then-insert-with-IntegrityError-fallback-to-refetch.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from redforge.infrastructure.database.models.security_conditions import SecurityConditionModel

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SecurityConditionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(
        self,
        condition_id: str,
        organization_id: str,
        affected_asset_id: str,
        source_category: str,
        stable_rule_id: str,
        qualifier: str,
        identity_key: str,
        evidence_state: str,
        severity: str,
        title: str,
        summary: str,
        remediation: str,
        canonical_references: list[str],
        evidence: list[dict[str, Any]],
    ) -> SecurityConditionModel:
        existing = await self._get_by_identity_key(organization_id, identity_key)
        now = datetime.now(UTC)
        if existing is not None:
            existing.evidence_state = evidence_state
            existing.severity = severity
            existing.title = title
            existing.summary = summary
            existing.remediation = remediation
            existing.canonical_references = canonical_references
            existing.evidence = evidence
            existing.lifecycle = "active"
            existing.last_observed_at = now
            existing.version += 1
            await self._session.flush()
            return existing

        model = SecurityConditionModel(
            id=condition_id,
            organization_id=organization_id,
            affected_asset_id=affected_asset_id,
            source_category=source_category,
            stable_rule_id=stable_rule_id,
            qualifier=qualifier,
            identity_key=identity_key,
            evidence_state=evidence_state,
            severity=severity,
            title=title,
            summary=summary,
            remediation=remediation,
            canonical_references=canonical_references,
            evidence=evidence,
            lifecycle="active",
            first_observed_at=now,
            last_observed_at=now,
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
            winner.severity = severity
            winner.title = title
            winner.summary = summary
            winner.remediation = remediation
            winner.canonical_references = canonical_references
            winner.evidence = evidence
            winner.lifecycle = "active"
            winner.last_observed_at = now
            winner.version += 1
            await self._session.flush()
            return winner
        return model

    async def _get_by_identity_key(
        self, organization_id: str, identity_key: str
    ) -> SecurityConditionModel | None:
        stmt = select(SecurityConditionModel).where(
            SecurityConditionModel.organization_id == organization_id,
            SecurityConditionModel.identity_key == identity_key,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_id_for_org(
        self, condition_id: str, organization_id: str
    ) -> SecurityConditionModel | None:
        stmt = select(SecurityConditionModel).where(
            SecurityConditionModel.id == condition_id,
            SecurityConditionModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_org(
        self,
        organization_id: str,
        evidence_state: str | None = None,
        severity: str | None = None,
        source_category: str | None = None,
        asset_kind: str | None = None,
        lifecycle: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[SecurityConditionModel]:
        stmt = select(SecurityConditionModel).where(
            SecurityConditionModel.organization_id == organization_id
        )
        if evidence_state is not None:
            stmt = stmt.where(SecurityConditionModel.evidence_state == evidence_state)
        if severity is not None:
            stmt = stmt.where(SecurityConditionModel.severity == severity)
        if source_category is not None:
            stmt = stmt.where(SecurityConditionModel.source_category == source_category)
        if lifecycle is not None:
            stmt = stmt.where(SecurityConditionModel.lifecycle == lifecycle)
        if asset_kind is not None:
            from redforge.infrastructure.database.models.asset_connector import AIAssetModel

            stmt = stmt.join(
                AIAssetModel, AIAssetModel.id == SecurityConditionModel.affected_asset_id,
            ).where(AIAssetModel.asset_type == asset_kind)
        stmt = stmt.order_by(SecurityConditionModel.id).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_active_for_asset(
        self, organization_id: str, affected_asset_id: str
    ) -> list[SecurityConditionModel]:
        stmt = select(SecurityConditionModel).where(
            SecurityConditionModel.organization_id == organization_id,
            SecurityConditionModel.affected_asset_id == affected_asset_id,
            SecurityConditionModel.lifecycle == "active",
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_asset_ids_with_multiple_active_conditions(
        self, organization_id: str, minimum_count: int = 2
    ) -> list[str]:
        """A real `GROUP BY ... HAVING COUNT(*) >= N` query — used by
        the M9 MULTIPLE_SECURITY_CONDITIONS_ON_ASSET rule. Never a
        Python-side tally over a fetch-everything query."""
        stmt = (
            select(SecurityConditionModel.affected_asset_id)
            .where(
                SecurityConditionModel.organization_id == organization_id,
                SecurityConditionModel.lifecycle == "active",
            )
            .group_by(SecurityConditionModel.affected_asset_id)
            .having(func.count(SecurityConditionModel.id) >= minimum_count)
        )
        result = await self._session.execute(stmt)
        return [row[0] for row in result.all()]

    async def resolve(
        self, condition_id: str, organization_id: str
    ) -> SecurityConditionModel | None:
        model = await self.get_by_id_for_org(condition_id, organization_id)
        if model is None:
            return None
        model.lifecycle = "resolved"
        model.version += 1
        await self._session.flush()
        return model

    async def resolve_stale_for_rule_and_asset(
        self,
        organization_id: str,
        stable_rule_id: str,
        affected_asset_id: str,
        still_active_identity_keys: set[str],
    ) -> int:
        """M14 — absence-based condition resolution. Mirrors
        SecurityCorrelationRepository.resolve_stale_for_rule() exactly:
        every currently-ACTIVE condition for this exact (rule, asset)
        pair that is NOT in `still_active_identity_keys` (i.e. was not
        freshly re-ingested this run) is resolved. The caller
        (application/continuous_validation) is responsible for only
        calling this when the covering step(s) for `stable_rule_id`
        genuinely completed successfully this run — see
        condition_reconciliation.py's rule-ownership coverage map. This
        method itself has no opinion on coverage; it only ever resolves
        what its caller tells it is stale."""
        stmt = select(SecurityConditionModel).where(
            SecurityConditionModel.organization_id == organization_id,
            SecurityConditionModel.stable_rule_id == stable_rule_id,
            SecurityConditionModel.affected_asset_id == affected_asset_id,
            SecurityConditionModel.lifecycle == "active",
        )
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        resolved_count = 0
        for row in rows:
            if row.identity_key in still_active_identity_keys:
                continue
            row.lifecycle = "resolved"
            row.version += 1
            resolved_count += 1
        if resolved_count:
            await self._session.flush()
        return resolved_count

    async def count_active_by_severity(self, organization_id: str) -> dict[str, int]:
        """Counts of currently-ACTIVE conditions grouped by severity — a
        real `GROUP BY COUNT(*) WHERE lifecycle='active'` query, the
        deterministic input to the M18 posture score. Never a
        client-side tally, never includes resolved conditions."""
        stmt = (
            select(SecurityConditionModel.severity, func.count(SecurityConditionModel.id))
            .where(
                SecurityConditionModel.organization_id == organization_id,
                SecurityConditionModel.lifecycle == "active",
            )
            .group_by(SecurityConditionModel.severity)
        )
        result = await self._session.execute(stmt)
        return {severity: count for severity, count in result.all()}

    async def count_by_dimension(
        self, organization_id: str, column_name: str
    ) -> dict[str, int]:
        """Backend-computed aggregate counts grouped by one column
        (`evidence_state`/`severity`/`source_category`/`lifecycle`) —
        a real `GROUP BY COUNT(*)` query, never a client-side tally
        over one paginated page of rows."""
        column = getattr(SecurityConditionModel, column_name)
        stmt = (
            select(column, func.count(SecurityConditionModel.id))
            .where(SecurityConditionModel.organization_id == organization_id)
            .group_by(column)
        )
        result = await self._session.execute(stmt)
        return {value: count for value, count in result.all()}
