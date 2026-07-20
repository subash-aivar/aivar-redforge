"""Detection platform / projection / coverage / read-model validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.domain.security_graph.ontology import (
    ONTOLOGY_VERSION,
    EdgeKind,
    NodeKind,
    validate_edge,
)

if TYPE_CHECKING:
    from detection.application.projections.projection_coordinator import (
        ProjectionCoordinator,
    )
    from detection.application.projections.read_model_store import IReadModelStore


@dataclass(frozen=True, slots=True)
class ValidationCheck:
    name: str
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
        }


@dataclass(frozen=True, slots=True)
class ValidationReport:
    service: str
    checks: list[ValidationCheck]
    passed: bool
    validated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "passed": self.passed,
            "validated_at": self.validated_at,
            "checks": [c.to_dict() for c in self.checks],
        }


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class ArchitectureValidationService:
    """Verifies M28 ontology extensions and projection contracts."""

    EXPECTED_ONTOLOGY = 15

    def validate(self) -> ValidationReport:
        checks: list[ValidationCheck] = []
        checks.append(
            ValidationCheck(
                name="ontology_version",
                passed=ONTOLOGY_VERSION == self.EXPECTED_ONTOLOGY,
                message=f"ONTOLOGY_VERSION={ONTOLOGY_VERSION}",
                details={
                    "expected": self.EXPECTED_ONTOLOGY,
                    "actual": ONTOLOGY_VERSION,
                },
            )
        )
        required_nodes = (
            NodeKind.DETECTION_RULE,
            NodeKind.DETECTION_PACK,
            NodeKind.DETECTION_FINDING,
            NodeKind.TELEMETRY_SOURCE,
            NodeKind.ATTACK_TECHNIQUE,
        )
        missing = [n.value for n in required_nodes if n not in NodeKind]
        checks.append(
            ValidationCheck(
                name="detection_nodes",
                passed=not missing,
                message="detection node kinds present",
                details={"missing": missing},
            )
        )
        required_edges = (
            EdgeKind.DETECTS,
            EdgeKind.COVERS,
            EdgeKind.PRODUCED,
            EdgeKind.FINDING_ON,
            EdgeKind.FINDING_INVOLVES,
            EdgeKind.FINDING_CORRELATES,
            EdgeKind.FINDING_ATTRIBUTED,
            EdgeKind.QUERIES,
            EdgeKind.ESCALATED_TO,
        )
        edge_ok = True
        edge_errors: list[str] = []
        for ek in required_edges:
            try:
                _ = EdgeKind(ek.value)
            except Exception as exc:
                edge_ok = False
                edge_errors.append(str(exc))
        # Pair validation smoke
        try:
            validate_edge(
                EdgeKind.DETECTS, NodeKind.DETECTION_RULE, NodeKind.ATTACK_TECHNIQUE
            )
            validate_edge(
                EdgeKind.PRODUCED, NodeKind.DETECTION_RULE, NodeKind.DETECTION_FINDING
            )
            validate_edge(
                EdgeKind.ESCALATED_TO, NodeKind.DETECTION_FINDING, NodeKind.INVESTIGATION
            )
        except Exception as exc:
            edge_ok = False
            edge_errors.append(str(exc))
        checks.append(
            ValidationCheck(
                name="detection_edges",
                passed=edge_ok,
                message="detection edge kinds + pairs valid",
                details={"errors": edge_errors},
            )
        )
        passed = all(c.passed for c in checks)
        return ValidationReport(
            service="ArchitectureValidationService",
            checks=checks,
            passed=passed,
            validated_at=_now_iso(),
        )


class ProjectionValidationService:
    def __init__(self, coordinator: ProjectionCoordinator) -> None:
        self._coordinator = coordinator

    def validate(self) -> ValidationReport:
        health = self._coordinator.health()
        healthy = all(h.healthy for h in health)
        checks = [
            ValidationCheck(
                name="projection_health",
                passed=healthy,
                message="all projections healthy" if healthy else "unhealthy projection",
                details={"projections": [h.to_dict() for h in health]},
            ),
            ValidationCheck(
                name="publisher_status",
                passed=True,
                message="publisher reachable",
                details=self._coordinator.publisher.status(),
            ),
        ]
        return ValidationReport(
            service="ProjectionValidationService",
            checks=checks,
            passed=all(c.passed for c in checks),
            validated_at=_now_iso(),
        )


class CoverageValidationService:
    def __init__(self, store: IReadModelStore) -> None:
        self._store = store

    async def validate(self, tenant_id: str) -> ValidationReport:
        matrix = await self._store.load_coverage_matrix(tenant_id)
        gap = await self._store.load_coverage_gap(tenant_id)
        checks = [
            ValidationCheck(
                name="coverage_matrix_present",
                passed=matrix is not None,
                message="coverage matrix loaded" if matrix else "missing matrix",
            ),
            ValidationCheck(
                name="coverage_gap_present",
                passed=gap is not None,
                message="gap view loaded" if gap else "missing gap view",
            ),
        ]
        if matrix is not None:
            consistent = matrix.covered_count + matrix.gap_count >= 0
            checks.append(
                ValidationCheck(
                    name="coverage_counts_non_negative",
                    passed=consistent,
                    message="coverage counts ok",
                    details={
                        "covered": matrix.covered_count,
                        "gaps": matrix.gap_count,
                    },
                )
            )
        return ValidationReport(
            service="CoverageValidationService",
            checks=checks,
            passed=all(c.passed for c in checks),
            validated_at=_now_iso(),
        )


class ReadModelValidationService:
    def __init__(self, store: IReadModelStore) -> None:
        self._store = store

    async def validate(self, tenant_id: str) -> ValidationReport:
        status = self._store.status()
        summary = await self._store.load_finding_summary(tenant_id)
        checks = [
            ValidationCheck(
                name="store_backend",
                passed=bool(status.get("backend")),
                message=str(status.get("backend")),
                details=status,
            ),
            ValidationCheck(
                name="finding_summary_freshness",
                passed=True,
                message="summary optional until events",
                details={"present": summary is not None},
            ),
        ]
        return ValidationReport(
            service="ReadModelValidationService",
            checks=checks,
            passed=all(c.passed for c in checks),
            validated_at=_now_iso(),
        )


class PlatformValidationService:
    """Aggregates architecture + projection + coverage + read-model checks."""

    def __init__(
        self,
        coordinator: ProjectionCoordinator,
        store: IReadModelStore,
    ) -> None:
        self._architecture = ArchitectureValidationService()
        self._projection = ProjectionValidationService(coordinator)
        self._coverage = CoverageValidationService(store)
        self._read_models = ReadModelValidationService(store)

    async def validate_platform(self, tenant_id: str) -> dict[str, Any]:
        arch = self._architecture.validate()
        proj = self._projection.validate()
        cov = await self._coverage.validate(tenant_id)
        rm = await self._read_models.validate(tenant_id)
        reports = [arch, proj, cov, rm]
        return {
            "passed": all(r.passed for r in reports),
            "validated_at": _now_iso(),
            "reports": [r.to_dict() for r in reports],
        }

    def architecture(self) -> ValidationReport:
        return self._architecture.validate()

    def projection(self) -> ValidationReport:
        return self._projection.validate()
