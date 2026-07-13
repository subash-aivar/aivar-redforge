"""Protocol contracts for the Security Posture application layer.

All collaborators (repositories, calculators, stores) are defined here
as @runtime_checkable Protocols. Infrastructure implements these; the
application layer depends only on the protocols.

Design rules (consistent with all other contracts.py files):
- Protocols are @runtime_checkable
- No Protocol has a concrete default
- No framework leakage into protocol signatures
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.posture.entity import ValidationBaseline, ValidationSnapshot
    from redforge.domain.posture.value_objects import (
        ConfigurationFingerprint,
        SecurityPostureScore,
        ValidationTrend,
        ValidationWindow,
    )


# ─── Repository Ports ─────────────────────────────────────────────────────────


@runtime_checkable
class SnapshotRepositoryPort(Protocol):
    """Persistence port for ValidationSnapshot aggregates.

    Implementations: InMemorySnapshotRepository (tests), SqlSnapshotRepository (prod).
    """

    async def save(self, snapshot: ValidationSnapshot) -> None: ...

    async def get_by_id(self, snapshot_id: str) -> ValidationSnapshot | None: ...

    async def list_for_target(
        self,
        organization_id: str,
        target_id: str,
        window: ValidationWindow,
    ) -> list[ValidationSnapshot]: ...

    async def count_for_target(
        self,
        organization_id: str,
        target_id: str,
    ) -> int: ...


@runtime_checkable
class BaselineRepositoryPort(Protocol):
    """Persistence port for ValidationBaseline aggregates.

    Invariant: only one ACTIVE baseline per (organization_id, target_id).
    """

    async def save(self, baseline: ValidationBaseline) -> None: ...

    async def get_active(
        self,
        organization_id: str,
        target_id: str,
    ) -> ValidationBaseline | None: ...

    async def get_by_id(self, baseline_id: str) -> ValidationBaseline | None: ...

    async def list_for_org(
        self,
        organization_id: str,
    ) -> list[ValidationBaseline]: ...


@runtime_checkable
class HistoryRepositoryPort(Protocol):
    """Retrieves ordered snapshot history for trend and posture computation.

    Separates the time-series read concern from the general snapshot repository.
    """

    async def get_ordered_snapshots(
        self,
        organization_id: str,
        target_id: str,
        window: ValidationWindow,
    ) -> list[ValidationSnapshot]: ...

    async def get_latest_snapshot(
        self,
        organization_id: str,
        target_id: str,
    ) -> ValidationSnapshot | None: ...


# ─── Domain Service Ports ──────────────────────────────────────────────────────


@runtime_checkable
class TrendAnalyzerPort(Protocol):
    """Computes ValidationTrend from an ordered list of snapshots."""

    def compute(
        self,
        snapshots: list[ValidationSnapshot],
        window: ValidationWindow,
    ) -> ValidationTrend: ...


@runtime_checkable
class RegressionAnalyzerPort(Protocol):
    """Detects regressions / improvements by comparing snapshot to baseline."""

    from redforge.domain.posture.value_objects import ValidationRegressionDetail

    def analyze(
        self,
        current: ValidationSnapshot,
        baseline: ValidationBaseline,
    ) -> ValidationRegressionDetail | None: ...


@runtime_checkable
class SecurityPostureCalculatorPort(Protocol):
    """Aggregates snapshots into a SecurityPostureScore."""

    def calculate(
        self,
        snapshots: list[ValidationSnapshot],
        window: ValidationWindow,
    ) -> SecurityPostureScore: ...


@runtime_checkable
class ComparisonStrategyPort(Protocol):
    """Pluggable strategy for comparing two ConfigurationFingerprints."""

    from redforge.domain.posture.value_objects import DriftEvent

    def compare(
        self,
        source: ConfigurationFingerprint,
        target: ConfigurationFingerprint,
        source_snapshot_id: str,
        target_snapshot_id: str,
    ) -> DriftEvent | None: ...
