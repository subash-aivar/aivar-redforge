"""TenantSecurityConditionService — M8.

Flow: SECURITY SOURCE -> SecurityConditionInput -> tenant/asset
validation -> normalization -> deduplication (race-safe upsert keyed
on `build_condition_identity_key`) -> evidence sanitization ->
persistence -> best-effort Security Graph projection.

Frontend never reaches `ingest()` directly — no API endpoint accepts a
`SecurityConditionInput`-shaped body; only M6/M7 analyzers and this
service's own internal callers construct one.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.application.security_conditions.ingestion import (
    SecurityConditionInput,
    sanitize_evidence,
)
from redforge.core.exceptions import NotFoundError, ValidationError
from redforge.domain.security_conditions.value_objects import (
    EvidenceState,
    SourceCategory,
    build_condition_identity_key,
)
from redforge.infrastructure.database.repositories.asset_repository import (
    SqlAlchemyAssetRepository,
)
from redforge.infrastructure.database.repositories.security_condition_repository import (
    SecurityConditionRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.infrastructure.database.models.security_conditions import (
        SecurityConditionModel,
    )


@dataclass(frozen=True, slots=True)
class SecurityConditionSummaryDTO:
    by_evidence_state: dict[str, int]
    by_severity: dict[str, int]
    by_source_category: dict[str, int]
    by_lifecycle: dict[str, int]


@dataclass(frozen=True, slots=True)
class SecurityConditionDTO:
    id: str
    organization_id: str
    affected_asset_id: str
    source_category: str
    stable_rule_id: str
    evidence_state: str
    severity: str
    title: str
    summary: str
    remediation: str
    canonical_references: list[str]
    evidence: list[dict[str, str]]
    lifecycle: str
    first_observed_at: str
    last_observed_at: str
    identity_key: str = ""
    # Real, already-persisted qualifier column (e.g. the port for a
    # network-sourced condition, set at ingestion — see
    # application/network_security/orchestrator.py's
    # _ingest_condition_best_effort()) that was previously written to the
    # model but never mapped back out to callers. Empty string, never
    # fabricated, when the ingesting rule didn't set one.
    qualifier: str = ""


def _to_dto(m: SecurityConditionModel) -> SecurityConditionDTO:
    return SecurityConditionDTO(
        id=m.id, organization_id=m.organization_id, affected_asset_id=m.affected_asset_id,
        source_category=m.source_category, stable_rule_id=m.stable_rule_id,
        evidence_state=m.evidence_state, severity=m.severity, title=m.title,
        summary=m.summary, remediation=m.remediation,
        canonical_references=list(m.canonical_references), evidence=list(m.evidence),
        lifecycle=m.lifecycle,
        first_observed_at=m.first_observed_at.isoformat(),
        last_observed_at=m.last_observed_at.isoformat(),
        identity_key=m.identity_key,
        qualifier=m.qualifier,
    )


class TenantSecurityConditionService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def ingest(self, condition_input: SecurityConditionInput) -> SecurityConditionDTO:
        # Validate evidence_state/source_category against the closed enums —
        # unknown values fail safely rather than being silently persisted.
        try:
            EvidenceState(condition_input.evidence_state)
            SourceCategory(condition_input.source_category)
        except ValueError as exc:
            raise ValidationError(f"Invalid evidence_state/source_category: {exc}") from exc

        identity_key = build_condition_identity_key(
            organization_id=condition_input.organization_id,
            affected_asset_id=condition_input.affected_asset_id,
            source_category=SourceCategory(condition_input.source_category),
            stable_rule_id=condition_input.stable_rule_id,
            qualifier=condition_input.qualifier,
        )

        async with SessionUnitOfWork(self._session_factory) as uow:
            asset_repo = SqlAlchemyAssetRepository(uow.session)
            asset = await asset_repo.get_by_id_for_org(
                condition_input.affected_asset_id, condition_input.organization_id,
            )
            if asset is None:
                raise NotFoundError("Asset", condition_input.affected_asset_id)

            repo = SecurityConditionRepository(uow.session)
            model = await repo.upsert(
                condition_id=str(EntityId.generate()),
                organization_id=condition_input.organization_id,
                affected_asset_id=condition_input.affected_asset_id,
                source_category=condition_input.source_category,
                stable_rule_id=condition_input.stable_rule_id,
                qualifier=condition_input.qualifier,
                identity_key=identity_key,
                evidence_state=condition_input.evidence_state,
                severity=condition_input.severity,
                title=condition_input.title,
                summary=condition_input.summary,
                remediation=condition_input.remediation,
                canonical_references=list(condition_input.canonical_references),
                evidence=sanitize_evidence(condition_input.evidence),
            )
            await uow.commit()

        dto = _to_dto(model)
        await self._project_best_effort(dto)
        return dto

    async def get_for_org(self, condition_id: str, organization_id: str) -> SecurityConditionDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityConditionRepository(uow.session)
            model = await repo.get_by_id_for_org(condition_id, organization_id)
        if model is None:
            raise NotFoundError("SecurityCondition", condition_id)
        return _to_dto(model)

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
    ) -> list[SecurityConditionDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityConditionRepository(uow.session)
            rows = await repo.list_for_org(
                organization_id, evidence_state, severity, source_category,
                asset_kind, lifecycle, limit, offset,
            )
        return [_to_dto(r) for r in rows]

    async def list_active_for_asset(
        self, organization_id: str, affected_asset_id: str
    ) -> list[SecurityConditionDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityConditionRepository(uow.session)
            rows = await repo.list_active_for_asset(organization_id, affected_asset_id)
        return [_to_dto(r) for r in rows]

    async def list_asset_ids_with_multiple_active_conditions(
        self, organization_id: str, minimum_count: int = 2
    ) -> list[str]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityConditionRepository(uow.session)
            return await repo.list_asset_ids_with_multiple_active_conditions(
                organization_id, minimum_count
            )

    async def get_summary_for_org(self, organization_id: str) -> SecurityConditionSummaryDTO:
        """Backend-computed aggregate counts — real GROUP BY queries,
        never a client-side tally over one paginated page."""
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityConditionRepository(uow.session)
            by_evidence_state = await repo.count_by_dimension(organization_id, "evidence_state")
            by_severity = await repo.count_by_dimension(organization_id, "severity")
            by_source_category = await repo.count_by_dimension(organization_id, "source_category")
            by_lifecycle = await repo.count_by_dimension(organization_id, "lifecycle")
        return SecurityConditionSummaryDTO(
            by_evidence_state=by_evidence_state, by_severity=by_severity,
            by_source_category=by_source_category, by_lifecycle=by_lifecycle,
        )

    async def resolve_condition(
        self, condition_id: str, organization_id: str
    ) -> SecurityConditionDTO:
        """Explicit resolution only — never automatic merely because
        one discovery run failed to re-observe the condition."""
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityConditionRepository(uow.session)
            model = await repo.resolve(condition_id, organization_id)
            if model is None:
                raise NotFoundError("SecurityCondition", condition_id)
            await uow.commit()
        return _to_dto(model)

    async def resolve_stale_for_rule_and_asset(
        self,
        organization_id: str,
        stable_rule_id: str,
        affected_asset_id: str,
        still_active_identity_keys: set[str],
    ) -> int:
        """M14 — the one deliberate exception to `resolve_condition()`'s
        own "explicit resolution only" rule above: absence-based
        resolution IS legitimate here because the caller (continuous
        validation's condition reconciliation) has already proven the
        covering step for `stable_rule_id` completed successfully this
        run — this is not "failed to re-observe", it is "genuinely
        re-checked and confirmed absent". See
        application/continuous_validation/condition_reconciliation.py's
        rule-ownership coverage map for the actual eligibility gate;
        this method trusts its caller completely and does no coverage
        checking of its own."""
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityConditionRepository(uow.session)
            resolved_count = await repo.resolve_stale_for_rule_and_asset(
                organization_id, stable_rule_id, affected_asset_id, still_active_identity_keys,
            )
            await uow.commit()
        return resolved_count

    async def _project_best_effort(self, condition: SecurityConditionDTO) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:
                from redforge.application.security_graph import projector as sg_projector
                from redforge.infrastructure.database.repositories import (
                    security_graph_repository as sg_repo,
                )

                repo = sg_repo.SecurityGraphRepository(graph_uow.session)
                projector = sg_projector.SecurityGraphProjector(repo)
                await projector.project_security_condition(
                    organization_id=condition.organization_id,
                    condition_id=condition.id,
                    affected_asset_id=condition.affected_asset_id,
                    stable_rule_id=condition.stable_rule_id,
                    title=condition.title,
                    severity=condition.severity,
                    evidence_state=condition.evidence_state,
                )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: condition projection failed for condition_id=%s",
                condition.id, exc_info=True,
            )
