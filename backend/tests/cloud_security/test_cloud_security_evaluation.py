from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cloud_security.domain.aggregates.cloud_security_evaluation import CloudSecurityEvaluation
from cloud_security.domain.events.evaluation_events import (
    EvaluationCompleted,
    EvaluationFailed,
    EvaluationStarted,
)
from cloud_security.domain.exceptions.domain_exceptions import (
    InvalidEvaluationTransition,
    TenantMismatch,
)
from cloud_security.domain.value_objects.baseline_finding import BaselineFinding
from cloud_security.domain.value_objects.enums import (
    CloudSeverity,
    EvaluationStatus,
    FindingCategory,
    FindingStatus,
)
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    AssetId,
    EvaluationId,
    FindingId,
    ProviderId,
    RuleId,
    TenantId,
)

NOW = datetime.now(UTC)


def _start(**overrides) -> CloudSecurityEvaluation:
    defaults = {
        "evaluation_id": EvaluationId.generate(),
        "tenant_id": TenantId.generate(),
        "account_id": AccountId.generate(),
        "provider_id": ProviderId.generate(),
        "now": NOW,
    }
    defaults.update(overrides)
    return CloudSecurityEvaluation.start(**defaults)


def _finding(asset_id: AssetId | None = None) -> BaselineFinding:
    return BaselineFinding(
        finding_id=FindingId.generate(),
        asset_id=asset_id or AssetId.generate(),
        severity=CloudSeverity.MEDIUM,
        category=FindingCategory.CONFIGURATION,
        rule_id=RuleId("cs-002"),
        rule_name="Public storage",
        description="Bucket is publicly readable",
        recommendation="Restrict bucket ACL",
        evidence_reference="evidence://bucket-1",
        status=FindingStatus.OPEN,
        detected_at=NOW,
    )


def test_start_is_in_progress_and_emits_event() -> None:
    evaluation = _start()
    assert evaluation.status == EvaluationStatus.IN_PROGRESS
    assert evaluation.evaluated_asset_count == 0
    assert evaluation.finding_count == 0
    assert evaluation.failed_count == 0
    assert evaluation.findings == ()

    events = evaluation.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], EvaluationStarted)

    assert evaluation.pop_events() == []


def test_record_asset_evaluated_accumulates_findings() -> None:
    evaluation = _start()
    f1, f2 = _finding(), _finding()

    evaluation.record_asset_evaluated(evaluation.tenant_id, (f1,))
    evaluation.record_asset_evaluated(evaluation.tenant_id, (f2,))

    assert evaluation.evaluated_asset_count == 2
    assert evaluation.finding_count == 2
    assert evaluation.findings == (f1, f2)


def test_record_asset_evaluated_with_no_findings() -> None:
    evaluation = _start()
    evaluation.record_asset_evaluated(evaluation.tenant_id, ())
    assert evaluation.evaluated_asset_count == 1
    assert evaluation.finding_count == 0


def test_record_failure_increments_failed_count() -> None:
    evaluation = _start()
    evaluation.record_failure(evaluation.tenant_id)
    evaluation.record_failure(evaluation.tenant_id)
    assert evaluation.failed_count == 2


def test_complete_emits_event_with_counts() -> None:
    evaluation = _start()
    evaluation.pop_events()
    evaluation.record_asset_evaluated(evaluation.tenant_id, (_finding(),))

    evaluation.complete(evaluation.tenant_id, NOW)

    assert evaluation.status == EvaluationStatus.COMPLETED
    assert evaluation.completed_at == NOW
    events = evaluation.pop_events()
    assert isinstance(events[0], EvaluationCompleted)
    assert events[0].finding_count == 1


def test_fail_emits_event_with_reason() -> None:
    evaluation = _start()
    evaluation.pop_events()

    evaluation.fail(evaluation.tenant_id, "provider unavailable", NOW)

    assert evaluation.status == EvaluationStatus.FAILED
    assert evaluation.failure_reason == "provider unavailable"
    events = evaluation.pop_events()
    assert isinstance(events[0], EvaluationFailed)


@pytest.mark.parametrize("method_name", ["complete", "fail"])
def test_terminal_transition_twice_raises(method_name: str) -> None:
    evaluation = _start()
    evaluation.complete(evaluation.tenant_id, NOW)

    method = getattr(evaluation, method_name)
    with pytest.raises(InvalidEvaluationTransition):
        if method_name == "fail":
            method(evaluation.tenant_id, "x", NOW)
        else:
            method(evaluation.tenant_id, NOW)


def test_record_progress_after_terminal_raises() -> None:
    evaluation = _start()
    evaluation.complete(evaluation.tenant_id, NOW)

    with pytest.raises(InvalidEvaluationTransition):
        evaluation.record_asset_evaluated(evaluation.tenant_id, ())
    with pytest.raises(InvalidEvaluationTransition):
        evaluation.record_failure(evaluation.tenant_id)


def test_wrong_tenant_raises_on_every_mutator() -> None:
    evaluation = _start()
    other_tenant = TenantId.generate()

    with pytest.raises(TenantMismatch):
        evaluation.record_asset_evaluated(other_tenant, ())
    with pytest.raises(TenantMismatch):
        evaluation.record_failure(other_tenant)
    with pytest.raises(TenantMismatch):
        evaluation.complete(other_tenant, NOW)
    with pytest.raises(TenantMismatch):
        evaluation.fail(other_tenant, "x", NOW)
