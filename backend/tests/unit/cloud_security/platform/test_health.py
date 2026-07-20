"""Health / readiness matrix tests."""

from __future__ import annotations

import pytest

from redforge.application.cloud_security.platform.dtos import PackageHealthDTO
from redforge.application.cloud_security.platform.health_service import (
    CloudPlatformHealthService,
    CloudPlatformReadinessService,
)
from redforge.domain.cloud_security.platform.value_objects import (
    PackageHealthStatus,
    PackageName,
)

PACKAGES = list(PackageName)
STATUSES = list(PackageHealthStatus)


@pytest.fixture
def health() -> CloudPlatformHealthService:
    return CloudPlatformHealthService()


@pytest.mark.parametrize("package", PACKAGES)
def test_check_package_importable(
    health: CloudPlatformHealthService, package: PackageName
) -> None:
    dto = health.check_package(package)
    assert dto.package == package.value
    assert dto.status in {s.value for s in PackageHealthStatus}
    assert dto.message


@pytest.mark.parametrize("package", PACKAGES)
@pytest.mark.parametrize("status", STATUSES)
def test_health_probe_override_matrix(package: PackageName, status: PackageHealthStatus) -> None:
    def _probe(pkg: PackageName) -> PackageHealthDTO:
        return PackageHealthDTO(
            package=pkg.value,
            status=status.value,
            message=f"forced-{status.value}",
        )

    svc = CloudPlatformHealthService(probes={package: _probe})
    dto = svc.check_package(package)
    assert dto.status == status.value
    # other packages still evaluated via import
    all_health = svc.check_all()
    assert len(all_health.packages) == len(PACKAGES)


def test_check_all_rollup_healthy(health: CloudPlatformHealthService) -> None:
    dto = health.check_all()
    assert dto.overall in {s.value for s in PackageHealthStatus}
    assert len(dto.packages) == 9
    assert dto.operation_id.startswith("op_")


def test_rollup_unhealthy_wins() -> None:
    def unhealthy(pkg: PackageName) -> PackageHealthDTO:
        return PackageHealthDTO(
            package=pkg.value,
            status=PackageHealthStatus.UNHEALTHY.value,
            message="down",
        )

    svc = CloudPlatformHealthService(
        probes={PackageName.RISK: unhealthy}
    )
    dto = svc.check_all()
    assert dto.overall == PackageHealthStatus.UNHEALTHY.value


def test_rollup_degraded() -> None:
    def degraded(pkg: PackageName) -> PackageHealthDTO:
        return PackageHealthDTO(
            package=pkg.value,
            status=PackageHealthStatus.DEGRADED.value,
            message="slow",
        )

    probes = {pkg: degraded for pkg in PackageName}
    # force one healthy to ensure degraded (not unhealthy) rollup
    def healthy(pkg: PackageName) -> PackageHealthDTO:
        return PackageHealthDTO(
            package=pkg.value, status=PackageHealthStatus.HEALTHY.value, message="ok"
        )

    mixed = {**probes, PackageName.FOUNDATION: healthy}
    svc = CloudPlatformHealthService(probes=mixed)
    dto = svc.check_all()
    assert dto.overall == PackageHealthStatus.DEGRADED.value


@pytest.mark.asyncio
async def test_readiness_alias() -> None:
    svc: CloudPlatformReadinessService = CloudPlatformHealthService()
    dto = await svc.readiness("01HXORG0000000000000000001")
    assert dto.packages


@pytest.mark.parametrize(
    "package_str",
    [p.value for p in PackageName],
)
def test_check_package_accepts_str(
    health: CloudPlatformHealthService, package_str: str
) -> None:
    dto = health.check_package(package_str)
    assert dto.package == package_str
