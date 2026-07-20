"""Package health / readiness matrix for M26 Phase 8 platform packages."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

from redforge.application.cloud_security.platform.dtos import (
    PackageHealthDTO,
    PlatformHealthDTO,
)
from redforge.application.cloud_security.platform.observability import new_operation_id
from redforge.domain.cloud_security.platform.value_objects import (
    PackageHealthStatus,
    PackageName,
)

_PACKAGE_MODULES: dict[PackageName, str] = {
    PackageName.FOUNDATION: "redforge.application.cloud_security.foundation_service",
    PackageName.INVENTORY: "redforge.application.cloud_security.asset_discovery_service",
    PackageName.IDENTITY: "redforge.application.cloud_security.identity_discovery_service",
    PackageName.CSPM: "redforge.application.cloud_security.cspm.assessment_service",
    PackageName.KUBERNETES: "redforge.application.cloud_security.kubernetes.security_service",
    PackageName.RUNTIME: "redforge.application.cloud_security.runtime.ingestion_service",
    PackageName.RISK: "redforge.application.cloud_security.risk.calculation_service",
    PackageName.SECURITY_GRAPH: "redforge.domain.security_graph.ontology",
    PackageName.COMPLIANCE: "redforge.application.cloud_security.cspm.compliance_acl",
}


class _HealthProbe(Protocol):
    def __call__(self, package: PackageName) -> PackageHealthDTO: ...


class CloudPlatformHealthService:
    """Evaluates importability / optional probes per package; rolls up overall status."""

    def __init__(
        self,
        *,
        probes: dict[PackageName, _HealthProbe] | None = None,
        session_factory: Any | None = None,
    ) -> None:
        self._probes = probes or {}
        self._session_factory = session_factory

    def check_package(self, package: PackageName | str) -> PackageHealthDTO:
        pkg = PackageName(str(package))
        if pkg in self._probes:
            return self._probes[pkg](pkg)
        module_path = _PACKAGE_MODULES.get(pkg)
        if module_path is None:
            return PackageHealthDTO(
                package=pkg.value,
                status=PackageHealthStatus.UNHEALTHY.value,
                message="unknown package",
            )
        try:
            __import__(module_path)
            return PackageHealthDTO(
                package=pkg.value,
                status=PackageHealthStatus.HEALTHY.value,
                message=f"module importable: {module_path}",
                details={"module": module_path},
            )
        except Exception as exc:
            return PackageHealthDTO(
                package=pkg.value,
                status=PackageHealthStatus.UNHEALTHY.value,
                message=f"import failed: {type(exc).__name__}",
                details={"module": module_path},
            )

    def check_all(self) -> PlatformHealthDTO:
        op_id = new_operation_id()
        packages = [self.check_package(pkg) for pkg in PackageName]
        statuses = {p.status for p in packages}
        if PackageHealthStatus.UNHEALTHY.value in statuses:
            overall = PackageHealthStatus.UNHEALTHY.value
        elif PackageHealthStatus.DEGRADED.value in statuses:
            overall = PackageHealthStatus.DEGRADED.value
        else:
            overall = PackageHealthStatus.HEALTHY.value
        return PlatformHealthDTO(
            overall=overall,
            packages=packages,
            checked_at=datetime.now(UTC),
            operation_id=op_id,
        )

    async def readiness(self, organization_id: str) -> PlatformHealthDTO:
        """Readiness mirrors health; optional single-session table probe avoids N+1."""
        base = self.check_all()
        if self._session_factory is None:
            return base
        from sqlalchemy import text

        try:
            async with self._session_factory() as session:
                result = await session.execute(
                    text(
                        "SELECT COUNT(*) FROM information_schema.tables "
                        "WHERE table_schema = 'cloud_security'"
                    )
                )
                count = int(result.scalar_one())
            packages = list(base.packages)
            if count < 5:
                packages.append(
                    PackageHealthDTO(
                        package="persistence",
                        status=PackageHealthStatus.DEGRADED.value,
                        message=f"only {count} cloud_security tables visible",
                        details={"table_count": count, "organization_id": organization_id},
                    )
                )
                overall = PackageHealthStatus.DEGRADED.value
            else:
                overall = base.overall
            return PlatformHealthDTO(
                overall=overall,
                packages=packages,
                checked_at=datetime.now(UTC),
                operation_id=base.operation_id,
            )
        except Exception as exc:
            packages = list(base.packages)
            packages.append(
                PackageHealthDTO(
                    package="persistence",
                    status=PackageHealthStatus.DEGRADED.value,
                    message=f"readiness probe failed: {type(exc).__name__}",
                )
            )
            return PlatformHealthDTO(
                overall=PackageHealthStatus.DEGRADED.value,
                packages=packages,
                checked_at=datetime.now(UTC),
                operation_id=base.operation_id,
            )


# Alias per mission naming
CloudPlatformReadinessService = CloudPlatformHealthService
