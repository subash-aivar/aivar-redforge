"""Platform validation — migration head, ontology, policies, weights, imports."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from redforge.application.cloud_security.platform.dtos import (
    ValidationCheckDTO,
    ValidationReportDTO,
)
from redforge.application.cloud_security.platform.observability import new_operation_id
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.domain.security_graph.ontology import ONTOLOGY_VERSION

_EXPECTED_ONTOLOGY_VERSION = 15
_MIN_CSPM_POLICIES = 25


class CloudPlatformValidationService:
    def __init__(
        self,
        *,
        session_factory: Any | None = None,
        validation_repo_factory: Any | None = None,
        expected_migration_head: str | None = None,
        expected_ontology_version: int = _EXPECTED_ONTOLOGY_VERSION,
    ) -> None:
        self._session_factory = session_factory
        self._validation_repo_factory = validation_repo_factory
        self._expected_migration_head = expected_migration_head
        self._expected_ontology_version = expected_ontology_version

    async def validate(
        self,
        organization_id: str,
        *,
        persist: bool = True,
    ) -> ValidationReportDTO:
        op_id = new_operation_id()
        checks: list[ValidationCheckDTO] = []

        checks.append(await self._check_migration_head())
        checks.append(self._check_ontology_version())
        checks.append(self._check_cspm_policies())
        checks.append(self._check_risk_weights())
        checks.extend(self._check_module_imports())

        if self._session_factory is not None:
            checks.append(await self._check_tables_exist())

        overall = all(c.passed for c in checks)
        report = ValidationReportDTO(
            organization_id=organization_id,
            overall_passed=overall,
            checks=checks,
            created_at=datetime.now(UTC),
            operation_id=op_id,
        )

        if (
            persist
            and self._session_factory is not None
            and self._validation_repo_factory is not None
        ):
            session_factory = self._session_factory
            validation_repo_factory = self._validation_repo_factory
            payload = {
                "overall_passed": report.overall_passed,
                "operation_id": report.operation_id,
                "checks": [
                    {
                        "name": c.name,
                        "passed": c.passed,
                        "message": c.message,
                        "details": c.details,
                    }
                    for c in report.checks
                ],
                "created_at": report.created_at.isoformat(),
            }
            async with session_factory() as session, session.begin():
                repo = validation_repo_factory(session)
                await repo.save_report(OrganizationId(organization_id), payload)

        return report

    async def get_last_report(self, organization_id: str) -> ValidationReportDTO | None:
        if self._session_factory is None or self._validation_repo_factory is None:
            return None
        async with self._session_factory() as session:
            repo = self._validation_repo_factory(session)
            stored = await repo.get_latest(OrganizationId(organization_id))
        if stored is None:
            return None
        raw = stored.get("report") or {}
        if not isinstance(raw, dict):
            return None
        checks_raw = raw.get("checks") or []
        checks: list[ValidationCheckDTO] = []
        if isinstance(checks_raw, list):
            for item in checks_raw:
                if not isinstance(item, dict):
                    continue
                checks.append(
                    ValidationCheckDTO(
                        name=str(item.get("name") or ""),
                        passed=bool(item.get("passed")),
                        message=str(item.get("message") or ""),
                        details=dict(item.get("details") or {}),
                    )
                )
        created = stored.get("created_at") or raw.get("created_at")
        created_at = (
            datetime.fromisoformat(str(created))
            if created
            else datetime.now(UTC)
        )
        return ValidationReportDTO(
            organization_id=organization_id,
            overall_passed=bool(raw.get("overall_passed")),
            checks=checks,
            created_at=created_at,
            operation_id=str(raw.get("operation_id") or ""),
        )

    async def _check_migration_head(self) -> ValidationCheckDTO:
        from redforge.infrastructure.database.migration_head import get_expected_migration_head

        expected = self._expected_migration_head or get_expected_migration_head()

        if self._session_factory is None:
            return ValidationCheckDTO(
                name="migration_head",
                passed=True,
                message=f"expected migration head {expected} (no session — unverified)",
                details={"expected": expected, "verified": False},
            )

        from sqlalchemy import text

        try:
            async with self._session_factory() as session:
                result = await session.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
                actual = result.scalar_one_or_none()
            passed = actual == expected
            return ValidationCheckDTO(
                name="migration_head",
                passed=passed,
                message=(
                    f"migration head {actual} matches expected {expected}"
                    if passed
                    else f"migration head mismatch: expected {expected}, got {actual}"
                ),
                details={"expected": expected, "actual": actual, "verified": True},
            )
        except Exception as exc:
            return ValidationCheckDTO(
                name="migration_head",
                passed=False,
                message=f"migration head check failed: {type(exc).__name__}",
                details={"expected": expected, "verified": False},
            )

    def _check_ontology_version(self) -> ValidationCheckDTO:
        passed = self._expected_ontology_version == ONTOLOGY_VERSION
        return ValidationCheckDTO(
            name="ontology_version",
            passed=passed,
            message=f"ONTOLOGY_VERSION={ONTOLOGY_VERSION}",
            details={
                "actual": ONTOLOGY_VERSION,
                "expected": self._expected_ontology_version,
            },
        )

    def _check_cspm_policies(self) -> ValidationCheckDTO:
        try:
            from redforge.infrastructure.cloud_security.cspm.policy_loader import (
                load_cspm_policies,
            )

            policies = load_cspm_policies()
            count = len(policies)
            passed = count >= _MIN_CSPM_POLICIES
            return ValidationCheckDTO(
                name="cspm_policies",
                passed=passed,
                message=f"loaded {count} CSPM policies (min {_MIN_CSPM_POLICIES})",
                details={"count": count, "minimum": _MIN_CSPM_POLICIES},
            )
        except Exception as exc:
            return ValidationCheckDTO(
                name="cspm_policies",
                passed=False,
                message=f"policy load failed: {type(exc).__name__}",
                details={},
            )

    def _check_risk_weights(self) -> ValidationCheckDTO:
        try:
            from redforge.domain.cloud_security.risk.value_objects import RiskWeightProfile

            profile = RiskWeightProfile.default()
            total = sum(profile.to_dict().values())
            passed = abs(total - 1.0) <= 1e-6
            return ValidationCheckDTO(
                name="risk_weight_profile",
                passed=passed,
                message=f"default weights sum={total}",
                details=profile.to_dict(),
            )
        except Exception as exc:
            return ValidationCheckDTO(
                name="risk_weight_profile",
                passed=False,
                message=f"weight check failed: {type(exc).__name__}",
            )

    def _check_module_imports(self) -> list[ValidationCheckDTO]:
        modules = (
            ("risk_module", "redforge.application.cloud_security.risk.calculation_service"),
            ("cspm_module", "redforge.application.cloud_security.cspm.assessment_service"),
            (
                "kubernetes_module",
                "redforge.application.cloud_security.kubernetes.security_service",
            ),
            ("runtime_module", "redforge.application.cloud_security.runtime.ingestion_service"),
            ("foundation_module", "redforge.application.cloud_security.foundation_service"),
        )
        results: list[ValidationCheckDTO] = []
        for name, path in modules:
            try:
                __import__(path)
                results.append(
                    ValidationCheckDTO(
                        name=name,
                        passed=True,
                        message=f"importable: {path}",
                        details={"module": path},
                    )
                )
            except Exception as exc:
                results.append(
                    ValidationCheckDTO(
                        name=name,
                        passed=False,
                        message=f"import failed: {type(exc).__name__}",
                        details={"module": path},
                    )
                )
        return results

    async def _check_tables_exist(self) -> ValidationCheckDTO:
        from sqlalchemy import text

        required = (
            "cloud_orchestration_runs",
            "cloud_platform_validation_reports",
            "cloud_risk_scores",
            "cloud_providers",
        )
        assert self._session_factory is not None
        missing: list[str] = []
        try:
            async with self._session_factory() as session:
                for table in required:
                    result = await session.execute(
                        text(
                            "SELECT 1 FROM information_schema.tables "
                            "WHERE table_schema = 'cloud_security' AND table_name = :t"
                        ),
                        {"t": table},
                    )
                    if result.scalar_one_or_none() is None:
                        missing.append(table)
            passed = not missing
            return ValidationCheckDTO(
                name="cloud_security_tables",
                passed=passed,
                message="tables present" if passed else f"missing: {', '.join(missing)}",
                details={"missing": missing, "checked": list(required)},
            )
        except Exception as exc:
            return ValidationCheckDTO(
                name="cloud_security_tables",
                passed=False,
                message=f"table probe failed: {type(exc).__name__}",
            )
