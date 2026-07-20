"""Validation service matrix tests."""

from __future__ import annotations

import pytest

from redforge.application.cloud_security.platform.validation_service import (
    CloudPlatformValidationService,
)
from redforge.domain.security_graph.ontology import ONTOLOGY_VERSION

CHECK_NAMES = (
    "migration_head",
    "ontology_version",
    "cspm_policies",
    "risk_weight_profile",
    "risk_module",
    "cspm_module",
    "kubernetes_module",
    "runtime_module",
    "foundation_module",
)


@pytest.fixture
def validation() -> CloudPlatformValidationService:
    return CloudPlatformValidationService()


@pytest.mark.asyncio
async def test_validate_passes_core_checks(
    validation: CloudPlatformValidationService,
) -> None:
    report = await validation.validate("01HXORG0000000000000000001", persist=False)
    assert report.organization_id
    assert report.operation_id.startswith("op_")
    names = {c.name for c in report.checks}
    for expected in CHECK_NAMES:
        assert expected in names
    by_name = {c.name: c for c in report.checks}
    assert by_name["ontology_version"].passed is (ONTOLOGY_VERSION == 15)
    assert by_name["migration_head"].passed is True
    assert by_name["risk_weight_profile"].passed is True
    assert by_name["cspm_policies"].passed is True


@pytest.mark.parametrize("check_name", CHECK_NAMES)
@pytest.mark.asyncio
async def test_each_named_check_present(
    validation: CloudPlatformValidationService, check_name: str
) -> None:
    report = await validation.validate("01HXORG0000000000000000001", persist=False)
    match = next(c for c in report.checks if c.name == check_name)
    assert isinstance(match.passed, bool)
    assert match.message


@pytest.mark.parametrize("org", [f"01HXORG{i:019d}" for i in range(12)])
@pytest.mark.asyncio
async def test_validate_org_matrix(
    validation: CloudPlatformValidationService, org: str
) -> None:
    report = await validation.validate(org, persist=False)
    assert report.organization_id == org
    assert len(report.checks) >= 8


@pytest.mark.parametrize("expected_head", ["0053", "0052", "9999"])
@pytest.mark.asyncio
async def test_migration_head_expectation_param(expected_head: str) -> None:
    svc = CloudPlatformValidationService(expected_migration_head=expected_head)
    report = await svc.validate("01HXORG0000000000000000001", persist=False)
    check = next(c for c in report.checks if c.name == "migration_head")
    assert check.details["expected"] == expected_head


@pytest.mark.parametrize("expected_ontology", [12, 11, 99])
@pytest.mark.asyncio
async def test_ontology_expectation_param(expected_ontology: int) -> None:
    svc = CloudPlatformValidationService(expected_ontology_version=expected_ontology)
    report = await svc.validate("01HXORG0000000000000000001", persist=False)
    check = next(c for c in report.checks if c.name == "ontology_version")
    assert check.passed is (expected_ontology == ONTOLOGY_VERSION)


@pytest.mark.asyncio
async def test_last_report_none_without_repo(
    validation: CloudPlatformValidationService,
) -> None:
    assert await validation.get_last_report("01HXORG0000000000000000001") is None


@pytest.mark.parametrize(
    "module_check",
    ["risk_module", "cspm_module", "kubernetes_module", "runtime_module", "foundation_module"],
)
@pytest.mark.asyncio
async def test_module_checks_pass(
    validation: CloudPlatformValidationService, module_check: str
) -> None:
    report = await validation.validate("01HXORG0000000000000000001", persist=False)
    check = next(c for c in report.checks if c.name == module_check)
    assert check.passed is True
