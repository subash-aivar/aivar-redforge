"""Detection correlation — ACL DTOs only (no detection aggregate imports)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from execution.application.projections.projection_coordinator import (
        ProjectionCoordinator,
    )
    from execution.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort


CORRELATION_WINDOW = timedelta(minutes=30)


@dataclass(frozen=True, slots=True)
class DetectionFindingProducedDTO:
    """Inbound ACL DTO for M28 DetectionFindingProduced (no aggregate import)."""

    finding_id: str
    rule_id: str
    asset_id: str
    detected_at: datetime
    tenant_id: str
    related_technique: str | None = None
    action_id: str | None = None


@dataclass(frozen=True, slots=True)
class CorrelateDetectionFinding:
    """Command: explicitly correlate a finding to an attack action."""

    tenant_id: str
    action_id: str
    finding_id: str
    rule_id: str
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    action_id: str
    outcome: str  # caught | evaded | skipped
    rule_id: str
    finding_id: str | None
    coverage_pct: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "outcome": self.outcome,
            "rule_id": self.rule_id,
            "finding_id": self.finding_id,
            "coverage_pct": self.coverage_pct,
        }


class IDetectionCorrelationPort(ABC):
    """Inbound port for detection finding correlation (DTO-only ACL)."""

    @abstractmethod
    async def correlate_finding(
        self, finding: DetectionFindingProducedDTO
    ) -> CorrelationResult | None: ...

    @abstractmethod
    async def correlate_command(
        self, command: CorrelateDetectionFinding
    ) -> CorrelationResult: ...

    @abstractmethod
    async def mark_evaded(
        self,
        *,
        tenant_id: str,
        action_id: str,
        rule_ids: list[str],
        evaluated_at: datetime | None = None,
    ) -> list[CorrelationResult]: ...


class DetectionCorrelationService(IDetectionCorrelationPort):
    """Correlate DetectionFinding within 30 minutes of AttackActionCompleted.

    Within window → CAUGHT_BY_DETECTION edge.
    After window without finding for configured rules → EVADED_DETECTION.
    Updates DetectionCoverageReport: detected_count / total_actions * 100.
    """

    def __init__(
        self,
        coordinator: ProjectionCoordinator,
        graph_port: ISecurityGraphWritePort | None = None,
        *,
        correlation_window: timedelta = CORRELATION_WINDOW,
    ) -> None:
        self._coordinator = coordinator
        self._graph = graph_port or coordinator.graph_port
        self._window = correlation_window
        # action_id -> completion datetime
        self._completions: dict[str, datetime] = {}
        # action_id -> caught rule ids
        self._caught: dict[str, set[str]] = {}

    def register_action_completed(
        self, action_id: str, completed_at: datetime
    ) -> None:
        self._completions[action_id] = completed_at

    def sync_completions_from_projection(self) -> None:
        """Seed completion times from projection action context + publisher history."""
        for record in self._coordinator.publisher.history():
            event = record.domain_event
            name = type(event).__name__
            if name == "AttackActionCompleted":
                action_id = str(getattr(event, "aggregate_id", ""))
                completed = getattr(event, "completion_timestamp", None)
                if action_id and completed is not None:
                    self._completions[action_id] = completed

    async def correlate_finding(
        self, finding: DetectionFindingProducedDTO
    ) -> CorrelationResult | None:
        self.sync_completions_from_projection()
        action_id = finding.action_id
        if action_id is None:
            action_id = self._infer_action(
                tenant_id=finding.tenant_id,
                detected_at=finding.detected_at,
                technique=finding.related_technique,
                asset_id=finding.asset_id,
            )
        if action_id is None:
            return None
        return await self._apply_caught(
            tenant_id=finding.tenant_id,
            action_id=action_id,
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            detected_at=finding.detected_at,
        )

    async def correlate_command(
        self, command: CorrelateDetectionFinding
    ) -> CorrelationResult:
        self.sync_completions_from_projection()
        return await self._apply_caught(
            tenant_id=command.tenant_id,
            action_id=command.action_id,
            finding_id=command.finding_id,
            rule_id=command.rule_id,
            detected_at=command.detected_at,
        )

    async def mark_evaded(
        self,
        *,
        tenant_id: str,
        action_id: str,
        rule_ids: list[str],
        evaluated_at: datetime | None = None,
    ) -> list[CorrelationResult]:
        self.sync_completions_from_projection()
        completed = self._completions.get(action_id)
        now = evaluated_at or datetime.now(UTC)
        results: list[CorrelationResult] = []
        if completed is not None and now - completed < self._window:
            # Still inside correlation window — do not mark evaded yet.
            return results
        caught = self._caught.get(action_id, set())
        coverage = 0.0
        for rule_id in rule_ids:
            if rule_id in caught:
                continue
            await self._graph.project_evaded_detection(
                organization_id=tenant_id,
                action_id=action_id,
                rule_id=rule_id,
                evaluated_at=now.isoformat(),
            )
            report = await self._coordinator.projection_service._rebuild_coverage(
                tenant_id, None
            )
            coverage = report.coverage_pct
            results.append(
                CorrelationResult(
                    action_id=action_id,
                    outcome="evaded",
                    rule_id=rule_id,
                    finding_id=None,
                    coverage_pct=coverage,
                )
            )
        return results

    def _infer_action(
        self,
        *,
        tenant_id: str,
        detected_at: datetime,
        technique: str | None,
        asset_id: str,
    ) -> str | None:
        ctx = self._coordinator.projection_service.action_context
        candidates: list[tuple[datetime, str]] = []
        for action_id, completed_at in self._completions.items():
            delta = detected_at - completed_at
            if delta < timedelta(0) or delta > self._window:
                continue
            meta = ctx.get(action_id, {})
            if technique and meta.get("technique_id") and meta["technique_id"] != technique:
                continue
            if asset_id and meta.get("target_id") and meta["target_id"] != asset_id:
                continue
            candidates.append((completed_at, action_id))
        if not candidates:
            return None
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    async def _apply_caught(
        self,
        *,
        tenant_id: str,
        action_id: str,
        finding_id: str,
        rule_id: str,
        detected_at: datetime,
    ) -> CorrelationResult:
        completed = self._completions.get(action_id)
        if completed is not None:
            delta = detected_at - completed
            if delta < timedelta(0) or delta > self._window:
                return CorrelationResult(
                    action_id=action_id,
                    outcome="skipped",
                    rule_id=rule_id,
                    finding_id=finding_id,
                    coverage_pct=(
                        await self._coordinator.projection_service._rebuild_coverage(
                            tenant_id, None
                        )
                    ).coverage_pct,
                )

        await self._graph.project_caught_by_detection(
            organization_id=tenant_id,
            action_id=action_id,
            rule_id=rule_id,
            detected_at=detected_at.isoformat(),
            finding_id=finding_id,
        )
        await self._graph.project_produced_finding(
            organization_id=tenant_id,
            action_id=action_id,
            finding_id=finding_id,
            finding_type="detection",
        )
        self._caught.setdefault(action_id, set()).add(rule_id)
        report = await self._coordinator.projection_service.mark_action_detected(
            tenant_id, action_id, finding_id
        )
        return CorrelationResult(
            action_id=action_id,
            outcome="caught",
            rule_id=rule_id,
            finding_id=finding_id,
            coverage_pct=report.coverage_pct,
        )
