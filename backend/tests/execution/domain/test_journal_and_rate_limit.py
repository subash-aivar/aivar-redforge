"""Domain tests: journal hash chain and rate limit Destruct NX."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid7

import pytest

from execution.domain.aggregates.execution_journal import ExecutionJournal
from execution.domain.aggregates.rate_limit_bucket import RateLimitBucket
from execution.domain.events.safety_events import JournalChainIntegrityFailed
from execution.domain.services.rate_limit_evaluation_service import RateLimitEvaluationService
from execution.domain.value_objects.enums import (
    ChainIntegrityStatus,
    ImpactCeiling,
    JournalEntryType,
    RateLimitDecision,
)
from execution.domain.value_objects.execution_vos import RateLimitPolicy, TechniqueRef
from execution.domain.value_objects.identifiers import (
    EngagementId,
    OperatorId,
    TargetId,
    TenantId,
)
from execution.infrastructure.redis.in_memory_rate_limit_store import InMemoryRateLimitStore


def test_journal_hash_chain_verified() -> None:
    now = datetime.now(UTC)
    tenant = TenantId.from_uuid(uuid7())
    journal = ExecutionJournal.create(tenant, EngagementId(uuid7()), now)
    op = OperatorId(uuid7())
    journal.append_entry(
        tenant, JournalEntryType.ACTION_STARTED, "start-1", now, attribution=op
    )
    journal.append_entry(
        tenant, JournalEntryType.ACTION_COMPLETED, "done-1", now, attribution=op
    )
    report = journal.verify_chain_integrity(now)
    assert report.status == ChainIntegrityStatus.VERIFIED
    assert report.entry_count == 2


def test_journal_broken_chain_detected() -> None:
    now = datetime.now(UTC)
    tenant = TenantId.from_uuid(uuid7())
    journal = ExecutionJournal.create(tenant, EngagementId(uuid7()), now)
    journal.append_entry(
        tenant, JournalEntryType.ACTION_STARTED, "start", now, system_attribution="sys"
    )
    journal.append_entry(
        tenant, JournalEntryType.ACTION_COMPLETED, "done", now, system_attribution="sys"
    )
    # Tamper with middle entry content without recomputing hash
    journal.entries[0].content = "TAMPERED"
    report = journal.verify_chain_integrity(now)
    assert report.status == ChainIntegrityStatus.BROKEN
    events = journal.pop_events()
    assert any(isinstance(e, JournalChainIntegrityFailed) for e in events)


def test_rate_limit_destruct_decide() -> None:
    decision = RateLimitBucket.decide_from_count(
        1, 10, is_destruct=True, destruct_already_used=False
    )
    assert decision == RateLimitDecision.PERMITTED
    decision2 = RateLimitBucket.decide_from_count(
        1, 10, is_destruct=True, destruct_already_used=True
    )
    assert decision2 == RateLimitDecision.FORBIDDEN


@pytest.mark.asyncio
async def test_rate_limit_destruct_nx_once_per_engagement_target() -> None:
    store = InMemoryRateLimitStore()
    svc = RateLimitEvaluationService(store)
    tenant = TenantId.from_uuid(uuid7())
    target = TargetId(uuid7())
    engagement = uuid7()
    tech = TechniqueRef("T1499", "impact", ImpactCeiling.DESTRUCT)
    policy = RateLimitPolicy(10, 60, "impact")
    first = await svc.evaluate(tenant, target, tech, policy, engagement)
    second = await svc.evaluate(tenant, target, tech, policy, engagement)
    assert first == RateLimitDecision.PERMITTED
    assert second == RateLimitDecision.FORBIDDEN
