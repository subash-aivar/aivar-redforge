"""CloudSecurityEvaluation aggregate — one security-baseline
evaluation run against one or more `CloudAsset`s under one
`CloudAccount`, via one `CloudProviderRegistration` (M45F).

Owns evaluation lifecycle, evaluated-asset count, finding count,
timestamps, and status only — no compliance-framework logic, no risk
scoring, no remediation execution. It never mutates the `CloudAsset`s
it evaluates — `CloudAsset` (M45B) remains the single, immutable-from-
this-context inventory. Referencing `CloudAccount`/
`CloudProviderRegistration` by id only, never by object reference —
the same cross-aggregate discipline every other `cloud_security`
aggregate follows. `BaselineFinding`s produced during a run are held
directly (they are cheap immutable value objects, not aggregates —
unlike `CloudAsset`, this aggregate is their only home)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.domain.events.evaluation_events import (
    EvaluationCompleted,
    EvaluationFailed,
    EvaluationStarted,
)
from cloud_security.domain.exceptions.domain_exceptions import (
    InvalidEvaluationTransition,
    TenantMismatch,
)
from cloud_security.domain.value_objects.enums import EvaluationStatus

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.events.base import BaseDomainEvent
    from cloud_security.domain.value_objects.baseline_finding import BaselineFinding
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        EvaluationId,
        ProviderId,
        TenantId,
    )

_TERMINATE_FROM = {EvaluationStatus.IN_PROGRESS}


class CloudSecurityEvaluation:
    __slots__ = (
        "_pending_events",
        "account_id",
        "completed_at",
        "evaluated_asset_count",
        "evaluation_id",
        "failed_count",
        "failure_reason",
        "findings",
        "provider_id",
        "started_at",
        "status",
        "tenant_id",
    )

    def __init__(
        self,
        evaluation_id: EvaluationId,
        tenant_id: TenantId,
        account_id: AccountId,
        provider_id: ProviderId,
        status: EvaluationStatus,
        started_at: datetime,
        evaluated_asset_count: int = 0,
        failed_count: int = 0,
        findings: tuple[BaselineFinding, ...] = (),
        completed_at: datetime | None = None,
        failure_reason: str | None = None,
    ) -> None:
        self.evaluation_id = evaluation_id
        self.tenant_id = tenant_id
        self.account_id = account_id
        self.provider_id = provider_id
        self.status = status
        self.started_at = started_at
        self.evaluated_asset_count = evaluated_asset_count
        self.failed_count = failed_count
        self.findings = findings
        self.completed_at = completed_at
        self.failure_reason = failure_reason
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _assert_in_progress(self, to_status: str) -> None:
        if self.status not in _TERMINATE_FROM:
            raise InvalidEvaluationTransition(self.status.value, to_status)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @classmethod
    def start(
        cls,
        evaluation_id: EvaluationId,
        tenant_id: TenantId,
        account_id: AccountId,
        provider_id: ProviderId,
        now: datetime,
    ) -> CloudSecurityEvaluation:
        evaluation = cls(
            evaluation_id=evaluation_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider_id=provider_id,
            status=EvaluationStatus.IN_PROGRESS,
            started_at=now,
        )
        evaluation._emit(
            EvaluationStarted(
                tenant_id=str(tenant_id),
                aggregate_id=str(evaluation_id),
                aggregate_type="CloudSecurityEvaluation",
                occurred_at=now,
                account_id=str(account_id),
                provider_id=str(provider_id),
            )
        )
        return evaluation

    def record_asset_evaluated(
        self, tenant_id: TenantId, asset_findings: tuple[BaselineFinding, ...]
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_in_progress("progress recorded")
        self.evaluated_asset_count += 1
        self.findings = (*self.findings, *asset_findings)

    def record_failure(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        self._assert_in_progress("progress recorded")
        self.failed_count += 1

    def complete(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_in_progress(EvaluationStatus.COMPLETED.value)
        self.status = EvaluationStatus.COMPLETED
        self.completed_at = now
        self._emit(
            EvaluationCompleted(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.evaluation_id),
                aggregate_type="CloudSecurityEvaluation",
                occurred_at=now,
                evaluated_asset_count=self.evaluated_asset_count,
                finding_count=self.finding_count,
                failed_count=self.failed_count,
            )
        )

    def fail(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_in_progress(EvaluationStatus.FAILED.value)
        self.status = EvaluationStatus.FAILED
        self.completed_at = now
        self.failure_reason = reason
        self._emit(
            EvaluationFailed(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.evaluation_id),
                aggregate_type="CloudSecurityEvaluation",
                occurred_at=now,
                reason=reason,
            )
        )
