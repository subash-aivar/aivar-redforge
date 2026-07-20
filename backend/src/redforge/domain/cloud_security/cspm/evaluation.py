"""CSPMEvaluation aggregate — batch/incremental evaluation run record."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from redforge.domain.cloud_security.cspm.entities import EvaluationResult
from redforge.domain.cloud_security.cspm.events import CSPMDomainEvent, CSPMPolicyEvaluated
from redforge.domain.cloud_security.cspm.exceptions import InvalidCSPMArgumentError
from redforge.domain.cloud_security.cspm.value_objects import (
    CSPMEvaluationId,
    EvaluationContext,
    EvaluationStatus,
)
from redforge.domain.cloud_security.value_objects import OrganizationId


@dataclass
class CSPMEvaluation:
    id: CSPMEvaluationId
    organization_id: OrganizationId
    cloud_account_id: str | None
    status: EvaluationStatus
    context: EvaluationContext
    results: list[EvaluationResult]
    assets_evaluated: int
    policies_evaluated: int
    findings_opened: int
    findings_resolved: int
    diagnostics: dict[str, object]
    started_at: datetime
    completed_at: datetime | None
    error_message: str | None
    version: int = 1
    _pending_events: list[CSPMDomainEvent] = field(default_factory=list, repr=False)

    @classmethod
    def start(
        cls,
        *,
        organization_id: OrganizationId,
        context: EvaluationContext,
        cloud_account_id: str | None = None,
        now: datetime | None = None,
        evaluation_id: CSPMEvaluationId | None = None,
    ) -> CSPMEvaluation:
        ts = now or datetime.now(UTC)
        eid = evaluation_id or CSPMEvaluationId.generate()
        return cls(
            id=eid,
            organization_id=organization_id,
            cloud_account_id=cloud_account_id,
            status=EvaluationStatus.RUNNING,
            context=EvaluationContext(
                organization_id=context.organization_id,
                cloud_account_id=context.cloud_account_id,
                evaluation_id=str(eid),
                triggered_by=context.triggered_by,
                incremental=context.incremental,
                policy_ids=context.policy_ids,
                started_at=ts,
            ),
            results=[],
            assets_evaluated=0,
            policies_evaluated=0,
            findings_opened=0,
            findings_resolved=0,
            diagnostics={},
            started_at=ts,
            completed_at=None,
            error_message=None,
            version=1,
        )

    def append_results(self, results: list[EvaluationResult]) -> None:
        self.results.extend(results)
        self.version += 1

    def complete(
        self,
        *,
        assets_evaluated: int,
        policies_evaluated: int,
        findings_opened: int,
        findings_resolved: int,
        diagnostics: dict[str, object] | None = None,
        now: datetime | None = None,
    ) -> None:
        ts = now or datetime.now(UTC)
        self.status = EvaluationStatus.COMPLETED
        self.assets_evaluated = assets_evaluated
        self.policies_evaluated = policies_evaluated
        self.findings_opened = findings_opened
        self.findings_resolved = findings_resolved
        self.diagnostics = dict(diagnostics or {})
        self.completed_at = ts
        self.version += 1
        for policy_id in self.context.policy_ids or ("*",):
            self._pending_events.append(
                CSPMPolicyEvaluated(
                    evaluation_id=str(self.id),
                    organization_id=str(self.organization_id),
                    policy_id=policy_id,
                    findings_opened=findings_opened,
                    findings_resolved=findings_resolved,
                    occurred_at=ts,
                )
            )

    def fail(self, error: str, *, now: datetime | None = None) -> None:
        if not error.strip():
            raise InvalidCSPMArgumentError("error", "required")
        ts = now or datetime.now(UTC)
        self.status = EvaluationStatus.FAILED
        self.error_message = error.strip()[:4000]
        self.completed_at = ts
        self.version += 1

    def pop_events(self) -> list[CSPMDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
