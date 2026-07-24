from __future__ import annotations

from uuid import UUID

import pytest

from playbook.application.commands.playbook_commands import (
    ApprovePlaybook,
    CreatePlaybook,
    DeprecatePlaybook,
    PublishPlaybookVersion,
    RunPlaybookDryRun,
    SubmitPlaybookForApproval,
)
from playbook.domain.exceptions.domain_exceptions import DryRunHashMismatch, DryRunRequired
from playbook.infrastructure.container import PlaybookContainer
from redforge.shared.identifiers import EntityId


def _step(level: str = "LOW") -> dict[str, object]:
    return {
        "step_number": 1,
        "action_type": "create_ticket",
        "connector_type": "ITSM_JIRA",
        "target_selector": "default",
        "parameters": {"project": "SEC"},
        "impact_level": level,
    }


def _trigger() -> dict[str, object]:
    return {
        "source_context": "MANUAL",
        "trigger_type": "manual",
        "severity_threshold": None,
    }


@pytest.mark.asyncio
async def test_full_lifecycle() -> None:
    c = PlaybookContainer()
    tenant = EntityId.generate()
    eng = ("playbook:engineer",)
    analyst = ("soc:analyst",)
    created = await c.app.create(CreatePlaybook(tenant, "PB1", "desc", "eng1", eng))
    pid = UUID(created.playbook_id)
    ver = await c.app.publish_version(
        PublishPlaybookVersion(tenant, pid, [_step()], [_trigger()], "eng1", eng)
    )
    dry = await c.app.dry_run(RunPlaybookDryRun(tenant, pid, UUID(ver.version_id), "eng1", eng))
    assert dry.outcome == "PASSED"
    await c.app.submit_for_approval(SubmitPlaybookForApproval(tenant, pid, 1, "eng1", eng))
    approved = await c.app.approve(ApprovePlaybook(tenant, pid, 1, "a1", "soc:analyst", analyst))
    assert approved.status == "APPROVED"
    dep = await c.app.deprecate(
        DeprecatePlaybook(tenant, pid, "cmd1", "retired", ("soc:commander",))
    )
    assert dep.status == "DEPRECATED"


@pytest.mark.asyncio
async def test_approve_requires_dry_run() -> None:
    c = PlaybookContainer()
    tenant = EntityId.generate()
    eng = ("playbook:engineer",)
    created = await c.app.create(CreatePlaybook(tenant, "PB1", "d", "e", eng))
    pid = UUID(created.playbook_id)
    await c.app.publish_version(
        PublishPlaybookVersion(tenant, pid, [_step()], [_trigger()], "e", eng)
    )
    await c.app.submit_for_approval(SubmitPlaybookForApproval(tenant, pid, 1, "e", eng))
    with pytest.raises(DryRunRequired):
        await c.app.approve(ApprovePlaybook(tenant, pid, 1, "a1", "soc:analyst", ("soc:analyst",)))


@pytest.mark.asyncio
async def test_hash_mismatch_rejects_approval() -> None:
    c = PlaybookContainer()
    tenant = EntityId.generate()
    eng = ("playbook:engineer",)
    created = await c.app.create(CreatePlaybook(tenant, "PB1", "d", "e", eng))
    pid = UUID(created.playbook_id)
    ver = await c.app.publish_version(
        PublishPlaybookVersion(tenant, pid, [_step()], [_trigger()], "e", eng)
    )
    await c.app.dry_run(RunPlaybookDryRun(tenant, pid, UUID(ver.version_id), "e", eng))
    # publish new version changes content while keeping old dry-run
    await c.app.publish_version(
        PublishPlaybookVersion(
            tenant,
            pid,
            [{**_step(), "parameters": {"project": "OTHER"}}],
            [_trigger()],
            "e",
            eng,
        )
    )
    await c.app.submit_for_approval(SubmitPlaybookForApproval(tenant, pid, 2, "e", eng))
    # dry-run was for v1 hash; approving v2 without new dry-run
    # get latest test for v2 — none
    with pytest.raises((DryRunRequired, DryRunHashMismatch)):
        await c.app.approve(ApprovePlaybook(tenant, pid, 2, "a1", "soc:analyst", ("soc:analyst",)))


@pytest.mark.asyncio
async def test_high_requires_dual_approvers() -> None:
    c = PlaybookContainer()
    tenant = EntityId.generate()
    eng = ("playbook:engineer",)
    created = await c.app.create(CreatePlaybook(tenant, "PB1", "d", "e", eng))
    pid = UUID(created.playbook_id)
    ver = await c.app.publish_version(
        PublishPlaybookVersion(tenant, pid, [_step("HIGH")], [_trigger()], "e", eng)
    )
    await c.app.dry_run(RunPlaybookDryRun(tenant, pid, UUID(ver.version_id), "e", eng))
    await c.app.submit_for_approval(SubmitPlaybookForApproval(tenant, pid, 1, "e", eng))
    first = await c.app.approve(
        ApprovePlaybook(tenant, pid, 1, "c1", "soc:commander", ("soc:commander",))
    )
    assert first.status == "UNDER_REVIEW"
    second = await c.app.approve(
        ApprovePlaybook(tenant, pid, 1, "c2", "soc:commander", ("soc:commander",))
    )
    assert second.status == "APPROVED"
