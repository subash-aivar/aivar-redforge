"""TenantSecurityCorrelationService — M9.

Flow: TENANT CONTEXT -> canonical rule registry -> evaluate each rule
against canonical facts -> derive deterministic identity -> upsert
ACTIVE correlations -> resolve previously-ACTIVE correlations this
rule's CURRENT successful evaluation no longer supports -> return an
evaluation summary. Frontend/routers never construct a correlation
directly and never reach `evaluate()` with rule input of their own —
only the server-controlled `CorrelationRuleRegistry` decides what can
match.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.core.exceptions import NotFoundError
from redforge.domain.security_correlation.value_objects import build_correlation_identity_key
from redforge.infrastructure.database.repositories.security_correlation_repository import (
    SecurityCorrelationRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.security_correlation.rules import CorrelationRuleRegistry
    from redforge.infrastructure.database.models.security_correlation import (
        SecurityCorrelationModel,
    )


@dataclass(frozen=True, slots=True)
class SecurityCorrelationDTO:
    id: str
    organization_id: str
    stable_rule_id: str
    rule_version: int
    evidence_state: str
    lifecycle: str
    title: str
    summary: str
    operator_action: str
    entity_ids: list[str]
    condition_ids: list[str]
    first_observed_at: str
    last_observed_at: str
    resolved_at: str | None
    identity_key: str = ""


@dataclass(frozen=True, slots=True)
class CorrelationEvaluationSummary:
    rules_evaluated: int
    matched: int
    created: int
    updated: int
    resolved: int
    evaluated_at: str


def _to_dto(
    m: SecurityCorrelationModel, entity_ids: list[str], condition_ids: list[str],
) -> SecurityCorrelationDTO:
    return SecurityCorrelationDTO(
        id=m.id, organization_id=m.organization_id, stable_rule_id=m.stable_rule_id,
        rule_version=m.rule_version, evidence_state=m.evidence_state, lifecycle=m.lifecycle,
        title=m.title, summary=m.summary, operator_action=m.operator_action,
        entity_ids=entity_ids, condition_ids=condition_ids,
        first_observed_at=m.first_observed_at.isoformat(),
        last_observed_at=m.last_observed_at.isoformat(),
        resolved_at=m.resolved_at.isoformat() if m.resolved_at else None,
        identity_key=m.identity_key,
    )


class TenantSecurityCorrelationService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        rule_registry: CorrelationRuleRegistry,
    ) -> None:
        self._session_factory = session_factory
        self._rule_registry = rule_registry

    async def evaluate(self, organization_id: str) -> CorrelationEvaluationSummary:
        """One full evaluation cycle. Each rule's fact-gathering and
        persistence happens independently — a single rule raising does
        not corrupt or partially resolve another rule's correlations,
        and is re-raised so the caller/router surfaces a real failure
        rather than a silently-incomplete cycle."""
        from datetime import UTC, datetime

        created = updated = matched = resolved = 0
        rules = self._rule_registry.all_rules()
        for rule in rules:
            results = await rule.evaluate(organization_id)
            active_identity_keys: set[str] = set()
            async with SessionUnitOfWork(self._session_factory) as uow:
                repo = SecurityCorrelationRepository(uow.session)
                for result in results:
                    identity_key = build_correlation_identity_key(
                        organization_id, rule.stable_rule_id, rule.rule_version,
                        result.entity_ids,
                    )
                    active_identity_keys.add(identity_key)
                    existing = await repo.get_by_identity_key(organization_id, identity_key)
                    is_new = existing is None
                    await repo.upsert(
                        correlation_id=str(EntityId.generate()),
                        organization_id=organization_id,
                        stable_rule_id=rule.stable_rule_id,
                        rule_version=rule.rule_version,
                        identity_key=identity_key,
                        evidence_state=result.evidence_state,
                        title=result.title,
                        summary=result.summary,
                        operator_action=result.operator_action,
                        condition_ids=result.condition_ids,
                        entity_ids=result.entity_ids,
                    )
                    matched += 1
                    created += 1 if is_new else 0
                    updated += 0 if is_new else 1

                # Resolution runs only after this rule's fact-gathering
                # and every match's upsert succeeded above — a raised
                # exception anywhere before this point skips resolution
                # entirely, per the evaluation-cycle safety contract.
                resolved += await repo.resolve_stale_for_rule(
                    organization_id, rule.stable_rule_id, active_identity_keys,
                )
                await uow.commit()

        return CorrelationEvaluationSummary(
            rules_evaluated=len(rules), matched=matched, created=created, updated=updated,
            resolved=resolved, evaluated_at=datetime.now(UTC).isoformat(),
        )

    async def get_for_org(
        self, correlation_id: str, organization_id: str
    ) -> SecurityCorrelationDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityCorrelationRepository(uow.session)
            model = await repo.get_by_id_for_org(correlation_id, organization_id)
            if model is None:
                raise NotFoundError("SecurityCorrelation", correlation_id)
            entity_ids = await repo.get_entity_ids(correlation_id, organization_id)
            condition_ids = await repo.get_condition_ids(correlation_id, organization_id)
        return _to_dto(model, entity_ids, condition_ids)

    async def list_for_org(
        self,
        organization_id: str,
        lifecycle: str | None = None,
        stable_rule_id: str | None = None,
        evidence_state: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[SecurityCorrelationDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SecurityCorrelationRepository(uow.session)
            rows = await repo.list_for_org(
                organization_id, lifecycle, stable_rule_id, evidence_state, limit, offset,
            )
            dtos = []
            for row in rows:
                entity_ids = await repo.get_entity_ids(row.id, organization_id)
                condition_ids = await repo.get_condition_ids(row.id, organization_id)
                dtos.append(_to_dto(row, entity_ids, condition_ids))
        return dtos
