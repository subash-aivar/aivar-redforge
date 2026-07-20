"""Orchestrator pipeline unit tests with injected fakes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

import pytest

from redforge.application.cloud_security.foundation_dtos import (
    CloudAccountDTO,
    CloudAccountPageDTO,
)
from redforge.application.cloud_security.platform.dtos import OrchestratePlatformCommand
from redforge.application.cloud_security.platform.orchestrator import CloudPlatformOrchestrator
from redforge.domain.cloud_security.platform.exceptions import InvalidPlatformArgumentError
from redforge.domain.cloud_security.platform.value_objects import StepName, StepStatus

ORG = "01HXORG0000000000000000001"
ACCOUNT = uuid4()


@dataclass
class _CallLog:
    calls: list[str] = field(default_factory=list)


class _FakeAsset:
    def __init__(self, log: _CallLog, *, fail: bool = False) -> None:
        self.log = log
        self.fail = fail

    async def discover_account(self, command: Any) -> Any:
        self.log.calls.append("DISCOVER_ASSETS")
        if self.fail:
            raise RuntimeError("asset boom")
        return type("R", (), {"discovered_count": 3, "sync_status": "SYNCED"})()


class _FakeIdentity:
    def __init__(self, log: _CallLog, *, fail: bool = False) -> None:
        self.log = log
        self.fail = fail

    async def discover_account(self, command: Any) -> Any:
        self.log.calls.append("DISCOVER_IDENTITY")
        if self.fail:
            raise RuntimeError("identity boom")
        return type("R", (), {"discovered_count": 2, "sync_status": "SYNCED"})()


class _FakeCSPM:
    def __init__(self, log: _CallLog, *, fail: bool = False) -> None:
        self.log = log
        self.fail = fail

    async def trigger_evaluation(self, command: Any) -> Any:
        self.log.calls.append("EVALUATE_CSPM")
        if self.fail:
            raise RuntimeError("cspm boom")
        return type(
            "R",
            (),
            {"evaluation_id": str(uuid4()), "status": "COMPLETED", "findings_opened": 1},
        )()


class _FakeK8s:
    def __init__(self, log: _CallLog) -> None:
        self.log = log

    async def discover_cluster(self, command: Any) -> Any:
        self.log.calls.append("DISCOVER_KUBERNETES")
        return type("R", (), {"cluster_id": uuid4()})()

    async def list_clusters(self, organization_id: str, **kwargs: Any) -> list[Any]:
        return []


class _FakeRuntime:
    def __init__(self, log: _CallLog) -> None:
        self.log = log

    async def ingest(self, command: Any) -> Any:
        self.log.calls.append("INGEST_RUNTIME")
        return type("R", (), {"accepted": len(command.events), "rejected": 0})()


class _FakeRisk:
    def __init__(self, log: _CallLog, *, fail: bool = False) -> None:
        self.log = log
        self.fail = fail
        self.calls = 0

    async def calculate(self, command: Any) -> Any:
        self.log.calls.append("CALCULATE_RISK")
        self.calls += 1
        if self.fail:
            raise RuntimeError("risk boom")
        return type(
            "R",
            (),
            {
                "assessment_id": str(uuid4()),
                "assets_evaluated": 1,
                "status": "COMPLETED",
            },
        )()


class _FakeFoundation:
    def __init__(self, account_ids: list[UUID] | None = None) -> None:
        self.account_ids = account_ids or [ACCOUNT]

    async def list_cloud_accounts(self, query: Any) -> CloudAccountPageDTO:
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        items = [
            CloudAccountDTO(
                account_id=str(aid),
                cloud_provider_id=str(uuid4()),
                organization_id=query.organization_id,
                external_id=f"ext-{i}",
                display_name=f"acct-{i}",
                account_type="STANDALONE",
                credential_reference_id="cred-ref",
                sync_status="SYNCED",
                tags={},
                created_at=now,
                updated_at=now,
                version=1,
            )
            for i, aid in enumerate(self.account_ids)
        ]
        return CloudAccountPageDTO(items=items, page=1, size=50, total=len(items))


def _orchestrator(
    log: _CallLog,
    *,
    asset_fail: bool = False,
    identity_fail: bool = False,
    cspm_fail: bool = False,
    risk_fail: bool = False,
    foundation: _FakeFoundation | None = None,
) -> tuple[CloudPlatformOrchestrator, _FakeRisk]:
    risk = _FakeRisk(log, fail=risk_fail)
    orch = CloudPlatformOrchestrator(
        foundation=foundation or _FakeFoundation(),
        asset_discovery=_FakeAsset(log, fail=asset_fail),
        identity_discovery=_FakeIdentity(log, fail=identity_fail),
        cspm=_FakeCSPM(log, fail=cspm_fail),
        kubernetes=_FakeK8s(log),
        runtime_ingestion=_FakeRuntime(log),
        risk=risk,
    )
    return orch, risk


@pytest.mark.asyncio
async def test_step_order_default() -> None:
    log = _CallLog()
    orch, _ = _orchestrator(log)
    result = await orch.orchestrate(
        OrchestratePlatformCommand(organization_id=ORG, cloud_account_id=ACCOUNT)
    )
    assert log.calls == [
        "DISCOVER_ASSETS",
        "DISCOVER_IDENTITY",
        "EVALUATE_CSPM",
        "CALCULATE_RISK",
    ]
    assert result.status == "COMPLETED"
    skipped = {s.step_name for s in result.steps if s.status == StepStatus.SKIPPED.value}
    assert StepName.DISCOVER_KUBERNETES.value in skipped
    assert StepName.INGEST_RUNTIME.value in skipped


@pytest.mark.asyncio
async def test_include_k8s_and_runtime() -> None:
    log = _CallLog()
    orch, _ = _orchestrator(log)
    result = await orch.orchestrate(
        OrchestratePlatformCommand(
            organization_id=ORG,
            cloud_account_id=ACCOUNT,
            include_k8s=True,
            include_runtime=True,
            runtime_events=[{"event_type": "PROCESS"}],
        )
    )
    assert "DISCOVER_KUBERNETES" in log.calls
    assert "INGEST_RUNTIME" in log.calls
    assert result.status == "COMPLETED"


@pytest.mark.asyncio
async def test_fail_fast_stops_pipeline() -> None:
    log = _CallLog()
    orch, _ = _orchestrator(log, asset_fail=True)
    result = await orch.orchestrate(
        OrchestratePlatformCommand(
            organization_id=ORG,
            cloud_account_id=ACCOUNT,
            fail_fast=True,
        )
    )
    assert result.status == "FAILED"
    assert "DISCOVER_IDENTITY" not in log.calls
    assert "CALCULATE_RISK" not in log.calls


@pytest.mark.asyncio
async def test_partial_continues_after_failure() -> None:
    log = _CallLog()
    orch, _ = _orchestrator(log, identity_fail=True)
    result = await orch.orchestrate(
        OrchestratePlatformCommand(
            organization_id=ORG,
            cloud_account_id=ACCOUNT,
            fail_fast=False,
        )
    )
    assert result.status == "PARTIAL"
    assert "CALCULATE_RISK" in log.calls
    failed = [s for s in result.steps if s.status == StepStatus.FAILED.value]
    assert any(s.step_name == StepName.DISCOVER_IDENTITY.value for s in failed)


@pytest.mark.asyncio
async def test_idempotent_double_run() -> None:
    log = _CallLog()
    orch, risk = _orchestrator(log)
    cmd = OrchestratePlatformCommand(organization_id=ORG, cloud_account_id=ACCOUNT)
    r1 = await orch.orchestrate(cmd)
    r2 = await orch.orchestrate(cmd)
    assert r1.run_id != r2.run_id
    assert risk.calls == 2
    assert r1.status == "COMPLETED"
    assert r2.status == "COMPLETED"


@pytest.mark.asyncio
async def test_requires_account_or_org_wide() -> None:
    log = _CallLog()
    orch, _ = _orchestrator(log)
    with pytest.raises(InvalidPlatformArgumentError):
        await orch.orchestrate(OrchestratePlatformCommand(organization_id=ORG))


@pytest.mark.asyncio
async def test_organization_wide_iterates_accounts() -> None:
    log = _CallLog()
    a1, a2 = uuid4(), uuid4()
    orch, risk = _orchestrator(log, foundation=_FakeFoundation([a1, a2]))
    result = await orch.orchestrate(
        OrchestratePlatformCommand(organization_id=ORG, organization_wide=True)
    )
    assert result.scope == "ORGANIZATION"
    assert risk.calls == 2
    assert result.status == "COMPLETED"


@pytest.mark.parametrize(
    ("fail_flags", "expected_status"),
    [
        ({}, "COMPLETED"),
        ({"cspm_fail": True}, "PARTIAL"),
        ({"risk_fail": True}, "PARTIAL"),
        ({"asset_fail": True}, "PARTIAL"),
    ],
)
@pytest.mark.asyncio
async def test_status_matrix(
    fail_flags: dict[str, bool], expected_status: str
) -> None:
    log = _CallLog()
    orch, _ = _orchestrator(log, **fail_flags)
    result = await orch.orchestrate(
        OrchestratePlatformCommand(organization_id=ORG, cloud_account_id=ACCOUNT)
    )
    assert result.status == expected_status


@pytest.mark.parametrize("include_k8s", [True, False])
@pytest.mark.parametrize("include_runtime", [True, False])
@pytest.mark.parametrize("fail_fast", [False])
@pytest.mark.asyncio
async def test_flag_matrix(
    include_k8s: bool, include_runtime: bool, fail_fast: bool
) -> None:
    log = _CallLog()
    orch, _ = _orchestrator(log)
    result = await orch.orchestrate(
        OrchestratePlatformCommand(
            organization_id=ORG,
            cloud_account_id=ACCOUNT,
            include_k8s=include_k8s,
            include_runtime=include_runtime,
            fail_fast=fail_fast,
            runtime_events=[{"x": 1}] if include_runtime else [],
        )
    )
    assert result.status == "COMPLETED"
    names = {s.step_name: s.status for s in result.steps}
    if include_k8s:
        assert names[StepName.DISCOVER_KUBERNETES.value] == StepStatus.COMPLETED.value
    else:
        assert names[StepName.DISCOVER_KUBERNETES.value] == StepStatus.SKIPPED.value
    if include_runtime:
        assert names[StepName.INGEST_RUNTIME.value] == StepStatus.COMPLETED.value
    else:
        assert names[StepName.INGEST_RUNTIME.value] == StepStatus.SKIPPED.value


@pytest.mark.parametrize("n", range(8))
@pytest.mark.asyncio
async def test_operation_id_on_each_run(n: int) -> None:
    log = _CallLog()
    orch, _ = _orchestrator(log)
    result = await orch.orchestrate(
        OrchestratePlatformCommand(organization_id=ORG, cloud_account_id=ACCOUNT)
    )
    assert result.operation_id.startswith("op_")
    assert result.diagnostics.get("fail_fast") is False
