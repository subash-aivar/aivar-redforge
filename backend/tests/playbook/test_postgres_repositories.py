"""Integration tests for playbook's Postgres repositories."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from playbook.domain.aggregates.playbook import Playbook
from playbook.domain.aggregates.playbook_test_result import PlaybookTestResult
from playbook.domain.aggregates.playbook_version import PlaybookVersion
from playbook.domain.value_objects.definitions import (
    ActionStepDefinition,
    RollbackDefinition,
    TargetSelectorExpression,
    TriggerCondition,
)
from playbook.domain.value_objects.enums import (
    ActionImpactLevel,
    ConnectorType,
    TriggerSourceContext,
)
from playbook.domain.value_objects.enums import (
    TestOutcome as PlaybookTestOutcome,
)
from playbook.domain.value_objects.identifiers import TenantId
from playbook.infrastructure.persistence.postgres_repositories import (
    PgAutomationPolicyRepository,
    PgPlaybookRepository,
    PgPlaybookTestResultRepository,
    PgPlaybookVersionRepository,
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
async def test_playbook_approval_quorum_persists(session_factory) -> None:
    repo = PgPlaybookRepository(session_factory)
    tenant_id = TenantId(uuid7())

    pb = Playbook.create(tenant_id, "Isolate compromised host", "auto-contain", "author-1")
    pb.set_current_version(1)
    pb.submit_for_approval(tenant_id)
    await repo.save(pb, tenant_id)

    pb.record_approval(tenant_id, "reviewer-1", "soc:lead", quorum_required=2)
    await repo.save(pb, tenant_id)

    fetched = await repo.get(pb.playbook_id, tenant_id)
    assert fetched is not None
    assert fetched.status.value == "UNDER_REVIEW"
    assert len(fetched.approved_by) == 1
    assert fetched.approved_by[0].approved_by == "reviewer-1"

    fetched.record_approval(tenant_id, "reviewer-2", "soc:manager", quorum_required=2)
    await repo.save(fetched, tenant_id)

    approved = await repo.find_approved_for_trigger(tenant_id, TriggerSourceContext.M34_INCIDENT)
    assert any(str(p.playbook_id) == str(pb.playbook_id) for p in approved)

    listed = await repo.list(tenant_id, status_filter="APPROVED", page=1, page_size=10)
    assert len(listed) == 1


@pytest.mark.asyncio
async def test_playbook_version_with_action_steps_and_triggers(session_factory) -> None:
    repo = PgPlaybookVersionRepository(session_factory)
    playbook_repo = PgPlaybookRepository(session_factory)
    tenant_id = TenantId(uuid7())

    # playbook_versions.playbook_id FKs to playbooks — a real playbook row
    # must exist first.
    pb = Playbook.create(tenant_id, "Contain host", "desc", "author-1")
    await playbook_repo.save(pb, tenant_id)
    playbook_id = pb.playbook_id

    version = PlaybookVersion.create_draft(
        tenant_id,
        playbook_id,
        1,
        [
            ActionStepDefinition(
                step_number=1,
                action_type="isolate_host",
                connector_type=ConnectorType.EDR_CROWDSTRIKE,
                target_selector=TargetSelectorExpression("asset.tag == 'compromised'"),
                parameters={"scope": "network"},
                impact_level=ActionImpactLevel.HIGH,
                rollback_definition=RollbackDefinition(
                    rollback_action_type="rejoin_network",
                    rollback_connector_type=ConnectorType.EDR_CROWDSTRIKE,
                    is_reversible=True,
                ),
            )
        ],
        [
            TriggerCondition(
                source_context=TriggerSourceContext.M34_INCIDENT,
                trigger_type="malware_confirmed",
                severity_threshold="high",
            )
        ],
    )
    await repo.save(version, tenant_id)

    fetched = await repo.get(playbook_id, 1, tenant_id)
    assert fetched is not None
    assert len(fetched.action_steps) == 1
    assert fetched.action_steps[0].action_type == "isolate_host"
    assert fetched.action_steps[0].rollback_definition is not None
    assert fetched.action_steps[0].rollback_definition.is_reversible is True
    assert len(fetched.trigger_configs) == 1
    assert fetched.trigger_configs[0].trigger_type == "malware_confirmed"

    version.publish("engineer-1")
    await repo.save(version, tenant_id)

    latest = await repo.get_latest(playbook_id, tenant_id)
    assert latest is not None
    assert latest.status.value == "PUBLISHED"
    assert latest.content_hash != ""


@pytest.mark.asyncio
async def test_test_result_append_only_and_find_latest(session_factory) -> None:
    playbook_repo = PgPlaybookRepository(session_factory)
    version_repo = PgPlaybookVersionRepository(session_factory)
    repo = PgPlaybookTestResultRepository(session_factory)
    tenant_id = TenantId(uuid7())

    # playbook_versions.playbook_id FKs to playbooks, and
    # playbook_test_results.version_id FKs to playbook_versions — both
    # parent rows must exist first.
    pb = Playbook.create(tenant_id, "Contain host", "desc", "author-1")
    await playbook_repo.save(pb, tenant_id)
    playbook_id = pb.playbook_id

    version = PlaybookVersion.create_draft(tenant_id, playbook_id, 1, [], [])
    await version_repo.save(version, tenant_id)
    version_id = version.version_id

    older = PlaybookTestResult.create(
        tenant_id, playbook_id, version_id, "hash1", PlaybookTestOutcome.PASSED, 5, 5, ["p1"], "tester-1",
        datetime(2026, 1, 1, tzinfo=UTC), 1200,
    )
    newer = PlaybookTestResult.create(
        tenant_id, playbook_id, version_id, "hash1", PlaybookTestOutcome.FAILED, 5, 3, ["p1", "p2"],
        "tester-1", datetime(2026, 1, 2, tzinfo=UTC), 900,
    )
    await repo.append(older, tenant_id)
    await repo.append(newer, tenant_id)

    latest = await repo.find_latest_for_version(playbook_id, version_id, tenant_id)
    assert latest is not None
    assert latest.outcome.value == "FAILED"
    assert latest.steps_passed == 3


@pytest.mark.asyncio
async def test_automation_policy_kill_switch_round_trip(session_factory) -> None:
    repo = PgAutomationPolicyRepository(session_factory)
    tenant_id = TenantId(uuid7())

    policy = await repo.get_or_create_default(tenant_id)
    assert policy.kill_switch_state.value == "ARMED"

    policy.activate_kill_switch("admin-1", "suspicious automation loop")
    await repo.save(policy, tenant_id)

    reloaded = await repo.get_or_create_default(tenant_id)
    assert reloaded.kill_switch_state.value == "TRIGGERED"
    assert reloaded.kill_switch_triggered_by == "admin-1"
