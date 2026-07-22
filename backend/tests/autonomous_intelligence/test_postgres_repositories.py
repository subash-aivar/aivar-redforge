"""Integration tests for autonomous_intelligence's Postgres repositories."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from autonomous_intelligence.domain.aggregates.intelligence_suggestion import (
    IntelligenceSuggestion,
)
from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel
from autonomous_intelligence.domain.aggregates.suggestion_outcome import SuggestionOutcome
from autonomous_intelligence.domain.value_objects.enums import SuggestionTargetType
from autonomous_intelligence.domain.value_objects.evidence import (
    SuggestionEvidence,
    SuggestionTargetRef,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId
from autonomous_intelligence.infrastructure.persistence.postgres_repositories import (
    PgAutonomousOperationsPolicyRepository,
    PgIntelligenceSuggestionRepository,
    PgOptimizationModelRepository,
    PgSuggestionOutcomeRepository,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"), reason="requires TEST_DATABASE_URL"
    ),
]

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


@pytest.fixture
def session_factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.mark.asyncio
async def test_suggestion_approval_flow(session_factory) -> None:
    repo = PgIntelligenceSuggestionRepository(session_factory)
    tenant_id = TenantId(uuid7())
    now = datetime.now(UTC)

    suggestion = IntelligenceSuggestion.create(
        tenant_id,
        SuggestionTargetRef(
            target_context="detection_rule",
            target_id=uuid7(),
            target_type=SuggestionTargetType.DETECTION_RULE_TUNING,
            proposed_change_payload={"threshold": 0.8},
        ),
        SuggestionEvidence(
            model_id="model-1",
            model_version=2,
            confidence_score=0.82,
            supporting_signal_refs=("sig-1", "sig-2"),
            rationale_summary="elevated FP rate observed",
            generated_at=now,
        ),
    )
    await repo.save(suggestion, tenant_id)

    fetched = await repo.find_by_id(suggestion.suggestion_id.value, tenant_id)
    assert fetched is not None
    assert fetched.evidence.confidence_score == 0.82
    assert fetched.target_ref.proposed_change_payload == {"threshold": 0.8}

    pending = await repo.find_pending_review(
        tenant_id, SuggestionTargetType.DETECTION_RULE_TUNING, limit=10
    )
    assert any(str(s.suggestion_id) == str(suggestion.suggestion_id) for s in pending)

    fetched.approve(tenant_id, "engineer-1", ("soc:detection_engineer",))
    await repo.save(fetched, tenant_id)

    approved = await repo.find_approved_pending_application(tenant_id)
    assert any(str(s.suggestion_id) == str(suggestion.suggestion_id) for s in approved)


@pytest.mark.asyncio
async def test_expired_pending_suggestions(session_factory) -> None:
    repo = PgIntelligenceSuggestionRepository(session_factory)
    tenant_id = TenantId(uuid7())
    old = datetime.now(UTC) - timedelta(hours=100)

    suggestion = IntelligenceSuggestion.create(
        tenant_id,
        SuggestionTargetRef(
            target_context="playbook",
            target_id=None,
            target_type=SuggestionTargetType.PLAYBOOK_SYNTHESIS,
            proposed_change_payload={},
        ),
        SuggestionEvidence(
            model_id="model-2",
            model_version=1,
            confidence_score=0.7,
            supporting_signal_refs=(),
            rationale_summary="stale suggestion",
            generated_at=old,
        ),
        review_ttl_hours=1,
    )
    # force review_deadline_at into the past for the expiry query
    suggestion.review_deadline_at = datetime.now(UTC) - timedelta(hours=1)
    await repo.save(suggestion, tenant_id)

    expired = await repo.find_expired_pending(datetime.now(UTC))
    assert any(str(s.suggestion_id) == str(suggestion.suggestion_id) for s in expired)


@pytest.mark.asyncio
async def test_optimization_model_deploy_and_find(session_factory) -> None:
    repo = PgOptimizationModelRepository(session_factory)
    tenant_id = TenantId(uuid7())

    model = OptimizationModel.start_training(
        tenant_id, SuggestionTargetType.DETECTION_RULE_TUNING, "model-x", 1
    )
    model.mark_validating({"precision": 0.8, "recall": 0.75})
    await repo.save(model, tenant_id)

    model.deploy(tenant_id, "conformity-ref-1")
    await repo.save(model, tenant_id)

    deployed = await repo.find_deployed(tenant_id, SuggestionTargetType.DETECTION_RULE_TUNING)
    assert deployed is not None
    assert deployed.conformity_assessment_ref == "conformity-ref-1"

    by_id = await repo.find_by_id("model-x", tenant_id)
    assert by_id is not None
    assert by_id.status.value == "deployed"


@pytest.mark.asyncio
async def test_suggestion_outcome_append_and_measurement(session_factory) -> None:
    repo = PgSuggestionOutcomeRepository(session_factory)
    tenant_id = TenantId(uuid7())
    suggestion_id = uuid7()

    outcome = SuggestionOutcome.create_pending(
        suggestion_id, tenant_id, SuggestionTargetType.DETECTION_RULE_TUNING, 30, 0.5
    )
    await repo.append(outcome)

    pending = await repo.find_pending_measurement(datetime.now(UTC), tenant_id)
    assert any(o.outcome_id == outcome.outcome_id for o in pending)

    outcome.record_measurement(0.3, datetime.now(UTC))
    await repo.update_measurement(outcome, tenant_id)

    still_pending = await repo.find_pending_measurement(datetime.now(UTC), tenant_id)
    assert not any(o.outcome_id == outcome.outcome_id for o in still_pending)

    for_suggestion = await repo.find_for_suggestion(suggestion_id, tenant_id)
    assert len(for_suggestion) == 1
    assert for_suggestion[0].observed_metric == 0.3
    assert for_suggestion[0].delta == pytest.approx(-0.2)


@pytest.mark.asyncio
async def test_policy_kill_switch_round_trip(session_factory) -> None:
    repo = PgAutonomousOperationsPolicyRepository(session_factory)
    tenant_id = TenantId(uuid7())

    policy = await repo.get_or_create_default(tenant_id)
    assert policy.kill_switch_active is False

    policy.activate_kill_switch()
    await repo.save(policy, tenant_id)

    reloaded = await repo.get_or_create_default(tenant_id)
    assert reloaded.kill_switch_active is True
