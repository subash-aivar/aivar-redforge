"""ExecutionPolicyService — the single canonical decision point for
whether a future active security-testing action is ALLOW / DENY /
APPROVAL_REQUIRED (M10).

This service does not execute anything. It is the mandatory gate that
every execution dispatch boundary (currently: CampaignEngine —
see application/campaigns/campaign_engine.py) must call before
dispatching. No LLM, no arbitrary rule expressions — deterministic
Python control flow only, entirely over server-controlled enums.

Time-of-use: authorization validity is recomputed from `now` on every
call. Nothing here caches an ALLOW result — a revoked or expired
authorization denies on the very next evaluate() call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.authorization.value_objects import (
    CATEGORICALLY_DENIED_ACTION_CLASSES,
    ActionClass,
    AuthorizationScopeEntry,
    AuthorizationStatus,
    ExecutionPolicyDecision,
    PolicyDecision,
    ReasonCode,
    ScopeEntityType,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.authorization.contracts import EntityOwnershipPort
    from redforge.domain.authorization.entity import SecurityAuthorization


@dataclass(frozen=True, slots=True)
class ExecutionPolicyResultDTO:
    """Application-layer result of one evaluate() call. Structurally
    matches application.campaigns.contracts.ExecutionPolicyDecisionResult
    so CampaignEngine can depend on that narrower Protocol without
    importing this bounded context directly."""

    decision: str
    reason_code: str
    decision_id: str
    action_class: str
    authorization_id: str | None


class ExecutionPolicyService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        ownership_checker: EntityOwnershipPort | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._ownership_checker = ownership_checker

    async def evaluate(
        self,
        *,
        organization_id: str,
        actor_user_id: str,
        action_class: str,
        entity_refs: list[tuple[str, str]],
    ) -> ExecutionPolicyResultDTO:
        """Decide ALLOW / DENY / APPROVAL_REQUIRED for one requested
        action. Always persists a decision audit row, including for
        DENY outcomes — every decision is auditable, not just ALLOWs.

        entity_refs: list of (entity_type, entity_id) tuples using the
        canonical ScopeEntityType values ("ai_target", "ai_asset").
        """
        now = utc_now()

        try:
            ac = ActionClass(action_class)
        except ValueError:
            return await self._deny(
                organization_id, actor_user_id, action_class, entity_refs,
                ReasonCode.ACTION_CLASS_DENIED, authorization_id=None,
            )

        if ac in CATEGORICALLY_DENIED_ACTION_CLASSES:
            return await self._deny(
                organization_id, actor_user_id, ac.value, entity_refs,
                ReasonCode.ACTION_CLASS_DENIED, authorization_id=None,
            )

        try:
            entities = {
                AuthorizationScopeEntry(entity_type=ScopeEntityType(et), entity_id=eid)
                for et, eid in entity_refs
            }
        except ValueError:
            return await self._deny(
                organization_id, actor_user_id, ac.value, entity_refs,
                ReasonCode.ENTITY_NOT_IN_SCOPE, authorization_id=None,
            )

        if self._ownership_checker is not None:
            for entity in entities:
                owned = await self._ownership_checker.is_owned_by_organization(
                    entity.entity_type.value, entity.entity_id, organization_id,
                )
                if not owned:
                    return await self._deny(
                        organization_id, actor_user_id, ac.value, entity_refs,
                        ReasonCode.TENANT_MISMATCH, authorization_id=None,
                    )

        # All authorizations for this org, regardless of status or
        # action class — precedence below distinguishes "no
        # authorization exists at all" from "one exists but doesn't
        # cover this entity" from "covers the entity but not this
        # action class", which a single pre-filtered query cannot.
        all_authorizations = await self._find_all(organization_id)
        if not all_authorizations:
            return await self._deny(
                organization_id, actor_user_id, ac.value, entity_refs,
                ReasonCode.AUTHORIZATION_NOT_FOUND, authorization_id=None,
            )

        entity_matched = [a for a in all_authorizations if entities.issubset(a.scope)]
        if not entity_matched:
            return await self._deny(
                organization_id, actor_user_id, ac.value, entity_refs,
                ReasonCode.ENTITY_NOT_IN_SCOPE, authorization_id=str(all_authorizations[0].id),
            )

        action_matched = [a for a in entity_matched if ac in a.action_classes]
        if not action_matched:
            return await self._deny(
                organization_id, actor_user_id, ac.value, entity_refs,
                ReasonCode.ACTION_NOT_IN_SCOPE, authorization_id=str(entity_matched[0].id),
            )

        for candidate in action_matched:
            if candidate.status == AuthorizationStatus.ACTIVE:
                if candidate.validity.contains(now):
                    return await self._allow(
                        organization_id, actor_user_id, ac.value, entity_refs,
                        authorization_id=str(candidate.id),
                    )
                return await self._deny(
                    organization_id, actor_user_id, ac.value, entity_refs,
                    ReasonCode.AUTHORIZATION_EXPIRED, authorization_id=str(candidate.id),
                )

        pending = [c for c in action_matched if c.status == AuthorizationStatus.PENDING_APPROVAL]
        if pending:
            return await self._deny(
                organization_id, actor_user_id, ac.value, entity_refs,
                ReasonCode.APPROVAL_REQUIRED, authorization_id=str(pending[0].id),
                decision=PolicyDecision.APPROVAL_REQUIRED,
            )

        return await self._deny(
            organization_id, actor_user_id, ac.value, entity_refs,
            ReasonCode.AUTHORIZATION_NOT_ACTIVE, authorization_id=str(action_matched[0].id),
        )

    async def list_decisions(
        self, organization_id: str, limit: int, offset: int,
    ) -> list[dict[str, object]]:
        """Tenant-scoped policy decision audit history, newest first."""
        from redforge.infrastructure.database.repositories.authorization import (
            decision_repository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = decision_repository.SqlAlchemyExecutionPolicyDecisionRepository(uow.session)
            return await repo.list_by_organization(
                EntityId.from_string(organization_id), limit, offset,
            )

    # ─── Private ────────────────────────────────────────────────────────

    async def _find_all(self, organization_id: str) -> list[SecurityAuthorization]:
        from redforge.infrastructure.database.repositories.authorization.repository import (
            SqlAlchemySecurityAuthorizationRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemySecurityAuthorizationRepository(uow.session)
            return await repo.list_by_organization(
                EntityId.from_string(organization_id), None, limit=1000, offset=0,
            )

    async def _allow(
        self,
        organization_id: str,
        actor_user_id: str,
        action_class: str,
        entity_refs: list[tuple[str, str]],
        authorization_id: str | None,
    ) -> ExecutionPolicyResultDTO:
        return await self._record(
            organization_id, actor_user_id, action_class, entity_refs,
            PolicyDecision.ALLOW, ReasonCode.ALLOWED_BY_ACTIVE_AUTHORIZATION, authorization_id,
        )

    async def _deny(
        self,
        organization_id: str,
        actor_user_id: str,
        action_class: str,
        entity_refs: list[tuple[str, str]],
        reason_code: ReasonCode,
        authorization_id: str | None,
        decision: PolicyDecision = PolicyDecision.DENY,
    ) -> ExecutionPolicyResultDTO:
        return await self._record(
            organization_id, actor_user_id, action_class, entity_refs,
            decision, reason_code, authorization_id,
        )

    async def _record(
        self,
        organization_id: str,
        actor_user_id: str,
        action_class: str,
        entity_refs: list[tuple[str, str]],
        decision: PolicyDecision,
        reason_code: ReasonCode,
        authorization_id: str | None,
    ) -> ExecutionPolicyResultDTO:
        from redforge.infrastructure.database.repositories.authorization import (
            decision_repository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        try:
            parsed_action_class: ActionClass | None = ActionClass(action_class)
        except ValueError:
            # Genuinely unknown action class string — recorded as None,
            # never coerced into a real enum member. raw_action_class
            # (below) preserves exactly what the caller sent.
            parsed_action_class = None

        entries = tuple(
            AuthorizationScopeEntry(entity_type=ScopeEntityType(et), entity_id=eid)
            for et, eid in entity_refs
            if et in {member.value for member in ScopeEntityType}
        )

        record = ExecutionPolicyDecision(
            decision=decision,
            reason_code=reason_code,
            action_class=parsed_action_class,
            entity_refs=entries,
            authorization_id=authorization_id,
            evaluated_at=utc_now(),
        )

        async with SessionUnitOfWork(self._session_factory) as uow:
            decision_repo = decision_repository.SqlAlchemyExecutionPolicyDecisionRepository(
                uow.session,
            )
            decision_id = await decision_repo.record(
                EntityId.from_string(organization_id),
                EntityId.from_string(actor_user_id),
                record,
                raw_action_class=action_class,
            )
            await uow.commit()

        return ExecutionPolicyResultDTO(
            decision=decision.value,
            reason_code=reason_code.value,
            decision_id=decision_id,
            action_class=action_class,
            authorization_id=authorization_id,
        )
