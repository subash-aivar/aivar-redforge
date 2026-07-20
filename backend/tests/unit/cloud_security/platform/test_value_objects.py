"""Value object / enum exhaustiveness for platform domain."""

from __future__ import annotations

from uuid import uuid4

import pytest

from redforge.domain.cloud_security.platform.value_objects import (
    OrchestrationRunId,
    OrchestrationScope,
    PackageHealthStatus,
    PackageName,
    RunStatus,
    StepName,
    StepStatus,
)

RUN_STATUSES = list(RunStatus)
STEP_STATUSES = list(StepStatus)
STEP_NAMES = list(StepName)
SCOPES = list(OrchestrationScope)
PACKAGES = list(PackageName)
HEALTH_STATUSES = list(PackageHealthStatus)


@pytest.mark.parametrize("status", RUN_STATUSES)
def test_run_status_roundtrip(status: RunStatus) -> None:
    assert RunStatus(status.value) is status


@pytest.mark.parametrize("status", STEP_STATUSES)
def test_step_status_roundtrip(status: StepStatus) -> None:
    assert StepStatus(status.value) is status


@pytest.mark.parametrize("name", STEP_NAMES)
def test_step_name_roundtrip(name: StepName) -> None:
    assert StepName(name.value) is name


@pytest.mark.parametrize("scope", SCOPES)
def test_scope_roundtrip(scope: OrchestrationScope) -> None:
    assert OrchestrationScope(scope.value) is scope


@pytest.mark.parametrize("package", PACKAGES)
def test_package_name_roundtrip(package: PackageName) -> None:
    assert PackageName(package.value) is package


@pytest.mark.parametrize("status", HEALTH_STATUSES)
def test_health_status_roundtrip(status: PackageHealthStatus) -> None:
    assert PackageHealthStatus(status.value) is status


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (RunStatus.PENDING, "PENDING"),
        (RunStatus.RUNNING, "RUNNING"),
        (RunStatus.COMPLETED, "COMPLETED"),
        (RunStatus.PARTIAL, "PARTIAL"),
        (RunStatus.FAILED, "FAILED"),
    ],
)
def test_run_status_values(status: RunStatus, expected: str) -> None:
    assert status.value == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (StepName.REGISTER_PROVIDER, "REGISTER_PROVIDER"),
        (StepName.REGISTER_ACCOUNT, "REGISTER_ACCOUNT"),
        (StepName.DISCOVER_ASSETS, "DISCOVER_ASSETS"),
        (StepName.DISCOVER_IDENTITY, "DISCOVER_IDENTITY"),
        (StepName.EVALUATE_CSPM, "EVALUATE_CSPM"),
        (StepName.DISCOVER_KUBERNETES, "DISCOVER_KUBERNETES"),
        (StepName.INGEST_RUNTIME, "INGEST_RUNTIME"),
        (StepName.CALCULATE_RISK, "CALCULATE_RISK"),
        (StepName.PROJECT_GRAPH, "PROJECT_GRAPH"),
        (StepName.VALIDATE, "VALIDATE"),
    ],
)
def test_step_name_values(name: StepName, expected: str) -> None:
    assert name.value == expected


@pytest.mark.parametrize(
    "package",
    [
        "foundation",
        "inventory",
        "identity",
        "cspm",
        "kubernetes",
        "runtime",
        "risk",
        "security_graph",
        "compliance",
    ],
)
def test_package_name_strings(package: str) -> None:
    assert PackageName(package).value == package


def test_orchestration_run_id_generate() -> None:
    rid = OrchestrationRunId.generate()
    assert isinstance(rid.value, type(uuid4()))
    assert str(rid) == str(rid.value)


def test_orchestration_run_id_from_str() -> None:
    u = uuid4()
    rid = OrchestrationRunId.from_str(str(u))
    assert rid.value == u


def test_run_status_count() -> None:
    assert len(RUN_STATUSES) == 5


def test_step_name_count() -> None:
    assert len(STEP_NAMES) == 10


def test_package_count() -> None:
    assert len(PACKAGES) == 9


@pytest.mark.parametrize("status", STEP_STATUSES)
@pytest.mark.parametrize("name", STEP_NAMES[:5])
def test_step_status_x_name_matrix(status: StepStatus, name: StepName) -> None:
    assert status.value
    assert name.value


@pytest.mark.parametrize("scope", SCOPES)
@pytest.mark.parametrize("status", RUN_STATUSES)
def test_scope_x_run_status_matrix(scope: OrchestrationScope, status: RunStatus) -> None:
    assert f"{scope.value}:{status.value}"
