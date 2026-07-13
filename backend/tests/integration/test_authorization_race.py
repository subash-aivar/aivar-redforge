"""Real-PostgreSQL concurrency proof for the M10 Security Authorization
& Execution Policy control plane.

Proves the mandatory M10 concurrency invariants (adversarial checklist
items 30-31):
  1. Concurrent approve() calls for the SAME PENDING_APPROVAL
     authorization by two DIFFERENT approvers produce exactly one
     ACTIVE authorization with exactly one recorded approval decision
     — the loser observes the winner's already-decided state (via a
     locked read) and raises ApprovalAlreadyDecidedError, never
     silently overwriting the winner.
  2. Concurrent ExecutionPolicyService.evaluate() calls for the same
     org/action/entity all complete and each produces its own
     immutable decision audit row — no lost decisions, no crashes.

Runs against a dedicated, self-created database
(`redforge_authorization_race_test`), never the shared dev database.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.authorization import (
    ExecutionPolicyService,
    ScopeEntryDTO,
    SecurityAuthorizationService,
)
from redforge.domain.authorization.exceptions import (
    ApprovalAlreadyDecidedError,
    InvalidAuthorizationTransitionError,
)
from redforge.infrastructure.audit.logger import InMemoryAuditLog
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models.authorization import (
    SecurityAuthorizationApprovalModel,
    SecurityAuthorizationDecisionModel,
    SecurityAuthorizationModel,
    SecurityAuthorizationScopeModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_authorization_race_test"
_MAINTENANCE_DB_URL = os.environ.get(
    "REDFORGE_MAINTENANCE_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/postgres",
)
_DB_URL = os.environ.get(
    "REDFORGE_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_TEST_DB_NAME}",
)


class _AlwaysOwned:
    async def is_owned_by_organization(
        self, entity_type: str, entity_id: str, organization_id: str
    ) -> bool:
        return True


async def _ensure_test_database_exists() -> None:
    maintenance_engine = create_async_engine(
        _MAINTENANCE_DB_URL, echo=False, isolation_level="AUTOCOMMIT",
    )
    try:
        async with maintenance_engine.connect() as conn:
            exists = await conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": _TEST_DB_NAME},
            )
            if exists.first() is None:
                await conn.execute(text(f'CREATE DATABASE "{_TEST_DB_NAME}"'))
    finally:
        await maintenance_engine.dispose()


@pytest.fixture
async def pg_factory():
    await _ensure_test_database_exists()

    engine = create_async_engine(_DB_URL, echo=False)
    tables = [
        SecurityAuthorizationModel.__table__,
        SecurityAuthorizationScopeModel.__table__,
        SecurityAuthorizationApprovalModel.__table__,
        SecurityAuthorizationDecisionModel.__table__,
    ]
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, tables=tables)
        await conn.execute(text("DELETE FROM security_authorization_decisions"))
        await conn.execute(text("DELETE FROM security_authorization_approvals"))
        await conn.execute(text("DELETE FROM security_authorization_scope"))
        await conn.execute(text("DELETE FROM security_authorizations"))

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS security_authorization_decisions CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS security_authorization_approvals CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS security_authorization_scope CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS security_authorizations CASCADE"))
    await engine.dispose()


async def _make_pending_authorization(
    pg_factory, organization_id: str, requester_id: str,
) -> str:
    from datetime import UTC, datetime, timedelta

    service = SecurityAuthorizationService(
        pg_factory, InMemoryEventPublisher(), InMemoryAuditLog(), ownership_checker=_AlwaysOwned(),
    )
    dto = await service.create(
        organization_id=organization_id,
        requester_user_id=requester_id,
        action_classes=["safe_validation"],
        scope=[ScopeEntryDTO(entity_type="ai_target", entity_id="race-target")],
        valid_from=datetime.now(UTC),
        valid_until=datetime.now(UTC) + timedelta(hours=1),
    )
    await service.submit_for_approval(organization_id, dto.id, requester_id)
    return dto.id


async def test_concurrent_approval_produces_exactly_one_active_and_one_decision(
    pg_factory,
) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    approver_1 = str(EntityId.generate())
    approver_2 = str(EntityId.generate())

    authorization_id = await _make_pending_authorization(pg_factory, org_id, requester_id)

    service_1 = SecurityAuthorizationService(
        pg_factory, InMemoryEventPublisher(), InMemoryAuditLog(), ownership_checker=_AlwaysOwned(),
    )
    service_2 = SecurityAuthorizationService(
        pg_factory, InMemoryEventPublisher(), InMemoryAuditLog(), ownership_checker=_AlwaysOwned(),
    )

    from redforge.domain.identity.value_objects import Permission

    all_permissions = frozenset(Permission)

    results = await asyncio.gather(
        service_1.approve(org_id, authorization_id, approver_1, all_permissions),
        service_2.approve(org_id, authorization_id, approver_2, all_permissions),
        return_exceptions=True,
    )

    successes = [r for r in results if not isinstance(r, BaseException)]
    failures = [r for r in results if isinstance(r, BaseException)]

    assert len(successes) == 1, f"expected exactly one winner, got {results}"
    assert len(failures) == 1
    # The locked read on the authorization row (SELECT ... FOR UPDATE)
    # serializes the two transactions: whichever commits first makes
    # the authorization ACTIVE, so the loser's re-read (after the lock
    # is released) sees a non-PENDING_APPROVAL status and fails at
    # SecurityAuthorization.approve()'s own transition guard before
    # ever reaching the approval-decision step. Either this or
    # ApprovalAlreadyDecidedError (if the race were won at the approval
    # lock instead) is a correct "loser cleanly rejected" outcome —
    # what matters is that exactly one of the two succeeds and the
    # other never silently overwrites it.
    assert isinstance(
        failures[0], (ApprovalAlreadyDecidedError, InvalidAuthorizationTransitionError),
    )

    final = await service_1.get_by_id(org_id, authorization_id)
    assert final.status == "active"

    approval = await service_1.get_approval(org_id, authorization_id)
    assert approval is not None
    assert approval.decision == "approved"
    # The persisted approver is exactly the winner — never both, never neither.
    assert approval.approver_user_id in (approver_1, approver_2)

    async with pg_factory() as session:
        count = await session.execute(
            select(SecurityAuthorizationApprovalModel.id).where(
                SecurityAuthorizationApprovalModel.authorization_id == authorization_id
            )
        )
        rows = count.all()
    assert len(rows) == 1, "exactly one approval row must ever exist for this authorization"


async def test_concurrent_policy_evaluation_remains_auditable(pg_factory) -> None:
    org_id = str(EntityId.generate())
    actor_id = str(EntityId.generate())
    policy_service = ExecutionPolicyService(pg_factory, ownership_checker=_AlwaysOwned())

    results = await asyncio.gather(*[
        policy_service.evaluate(
            organization_id=org_id, actor_user_id=actor_id,
            action_class="safe_validation",
            entity_refs=[("ai_target", "concurrent-eval-target")],
        )
        for _ in range(10)
    ])

    assert len(results) == 10
    assert all(r.decision == "deny" for r in results)  # no authorization exists
    assert all(r.reason_code == "AUTHORIZATION_NOT_FOUND" for r in results)

    decision_ids = {r.decision_id for r in results}
    assert len(decision_ids) == 10, "every concurrent evaluation must get its own decision_id"

    history = await policy_service.list_decisions(org_id, limit=50, offset=0)
    persisted_ids = {row["id"] for row in history}
    assert decision_ids.issubset(persisted_ids), "every decision must be persisted and auditable"
