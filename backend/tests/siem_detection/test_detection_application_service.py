from __future__ import annotations

import dataclasses

import pytest

from redforge.shared.identifiers import EntityId
from siem_detection.application.commands.detection_commands import (
    EvaluateBatchCommand,
    EvaluateCanonicalEventCommand,
)
from siem_detection.application.dtos.detection_result import DetectionStatus
from siem_detection.application.exceptions import (
    ApplicationForbiddenError,
    EmptyBatchEvaluationError,
)
from siem_detection.application.registry.in_memory_detection_evaluator_registry import (
    InMemoryDetectionEvaluatorRegistry,
)
from siem_detection.application.services.detection_application_service import (
    DetectionApplicationService,
)
from siem_shared.domain.value_objects.event_severity import EventSeverity

from .conftest import (
    EXECUTOR_ROLES,
    SCHEMA_V1_0,
    FakeDetectionEvaluator,
    make_active_rule,
    make_canonical_event,
    make_draft_rule,
    matched,
    not_matched,
)


def _service(rule_provider, registry=None):
    return DetectionApplicationService(
        rule_provider=rule_provider, evaluator_registry=registry or InMemoryDetectionEvaluatorRegistry()
    )


# ---------------------------------------------------------------------------
# single rule evaluation
# ---------------------------------------------------------------------------


def test_single_rule_match(rule_provider):
    tenant_id = EntityId.generate()
    rule = make_active_rule(tenant_id)
    rule_provider._rules.append(rule)
    registry = InMemoryDetectionEvaluatorRegistry()
    registry.register(FakeDetectionEvaluator(str(rule.rule_id), evaluator=matched()))
    service = _service(rule_provider, registry)

    result = service.evaluate_event(
        EvaluateCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=make_canonical_event(tenant_id=tenant_id),
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert result.status == DetectionStatus.SUCCEEDED
    assert len(result.matches) == 1
    assert result.matches[0].rule_id == str(rule.rule_id)
    assert result.matches[0].severity == EventSeverity.HIGH


def test_single_rule_no_match(rule_provider):
    tenant_id = EntityId.generate()
    rule = make_active_rule(tenant_id)
    rule_provider._rules.append(rule)
    registry = InMemoryDetectionEvaluatorRegistry()
    registry.register(FakeDetectionEvaluator(str(rule.rule_id), evaluator=not_matched()))
    service = _service(rule_provider, registry)

    result = service.evaluate_event(
        EvaluateCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=make_canonical_event(tenant_id=tenant_id),
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert result.status == DetectionStatus.SUCCEEDED
    assert result.matches == ()
    assert result.outcomes[0].status == DetectionStatus.SUCCEEDED


def test_no_active_rules_is_succeeded_with_no_outcomes(rule_provider):
    tenant_id = EntityId.generate()
    service = _service(rule_provider)

    result = service.evaluate_event(
        EvaluateCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=make_canonical_event(tenant_id=tenant_id),
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert result.status == DetectionStatus.SUCCEEDED
    assert result.outcomes == ()


# ---------------------------------------------------------------------------
# multiple rule evaluation
# ---------------------------------------------------------------------------


def test_multiple_rules_all_match(rule_provider):
    tenant_id = EntityId.generate()
    rule_a = make_active_rule(tenant_id, "rule-a")
    rule_b = make_active_rule(tenant_id, "rule-b")
    rule_provider._rules.extend([rule_a, rule_b])
    registry = InMemoryDetectionEvaluatorRegistry()
    registry.register(FakeDetectionEvaluator(str(rule_a.rule_id), evaluator=matched(reason="a")))
    registry.register(FakeDetectionEvaluator(str(rule_b.rule_id), evaluator=matched(reason="b")))
    service = _service(rule_provider, registry)

    result = service.evaluate_event(
        EvaluateCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=make_canonical_event(tenant_id=tenant_id),
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert result.status == DetectionStatus.SUCCEEDED
    assert len(result.matches) == 2


def test_multiple_rules_mixed_match_and_no_match(rule_provider):
    tenant_id = EntityId.generate()
    rule_a = make_active_rule(tenant_id, "rule-a")
    rule_b = make_active_rule(tenant_id, "rule-b")
    rule_provider._rules.extend([rule_a, rule_b])
    registry = InMemoryDetectionEvaluatorRegistry()
    registry.register(FakeDetectionEvaluator(str(rule_a.rule_id), evaluator=matched()))
    registry.register(FakeDetectionEvaluator(str(rule_b.rule_id), evaluator=not_matched()))
    service = _service(rule_provider, registry)

    result = service.evaluate_event(
        EvaluateCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=make_canonical_event(tenant_id=tenant_id),
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert result.status == DetectionStatus.SUCCEEDED
    assert len(result.matches) == 1


# ---------------------------------------------------------------------------
# disabled / draft rules
# ---------------------------------------------------------------------------


def test_draft_rule_is_disabled_not_evaluated(rule_provider):
    tenant_id = EntityId.generate()
    draft_rule = make_draft_rule(tenant_id)
    rule_provider._rules.append(draft_rule)
    registry = InMemoryDetectionEvaluatorRegistry()
    registry.register(FakeDetectionEvaluator(str(draft_rule.rule_id), evaluator=matched()))
    service = _service(rule_provider, registry)

    result = service.evaluate_event(
        EvaluateCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=make_canonical_event(tenant_id=tenant_id),
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert result.status == DetectionStatus.SUCCEEDED
    assert result.outcomes[0].status == DetectionStatus.RULE_DISABLED
    assert result.matches == ()


# ---------------------------------------------------------------------------
# unsupported evaluator / invalid rule
# ---------------------------------------------------------------------------


def test_active_rule_with_no_registered_evaluator_is_skipped(rule_provider):
    tenant_id = EntityId.generate()
    rule = make_active_rule(tenant_id)
    rule_provider._rules.append(rule)
    service = _service(rule_provider)  # empty registry

    result = service.evaluate_event(
        EvaluateCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=make_canonical_event(tenant_id=tenant_id),
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert result.status == DetectionStatus.SUCCEEDED
    assert result.outcomes[0].status == DetectionStatus.RULE_SKIPPED
    assert result.outcomes[0].failures[0].error_type == "UnsupportedEvaluatorError"


def test_evaluator_raising_exception_produces_failed_outcome(rule_provider):
    def _explode(event):
        raise RuntimeError("malformed rule execution")

    tenant_id = EntityId.generate()
    rule = make_active_rule(tenant_id)
    rule_provider._rules.append(rule)
    registry = InMemoryDetectionEvaluatorRegistry()
    registry.register(FakeDetectionEvaluator(str(rule.rule_id), evaluator=_explode))
    service = _service(rule_provider, registry)

    result = service.evaluate_event(
        EvaluateCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=make_canonical_event(tenant_id=tenant_id),
            actor_roles=EXECUTOR_ROLES,
        )
    )

    assert result.status == DetectionStatus.FAILED
    assert result.outcomes[0].status == DetectionStatus.FAILED
    assert result.outcomes[0].failures[0].error_type == "RuntimeError"
    assert result.matches == ()


def test_evaluation_never_crashes_the_pipeline(rule_provider):
    """M37 §2.4 discipline extended to detection: an untrusted evaluator
    raising anything must still produce a typed result."""

    def _explode(event):
        raise KeyError("unexpected event shape")

    tenant_id = EntityId.generate()
    rule = make_active_rule(tenant_id)
    rule_provider._rules.append(rule)
    registry = InMemoryDetectionEvaluatorRegistry()
    registry.register(FakeDetectionEvaluator(str(rule.rule_id), evaluator=_explode))
    service = _service(rule_provider, registry)

    result = service.evaluate_event(
        EvaluateCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=make_canonical_event(tenant_id=tenant_id),
            actor_roles=EXECUTOR_ROLES,
        )
    )
    assert result.status == DetectionStatus.FAILED


# ---------------------------------------------------------------------------
# tenant validation
# ---------------------------------------------------------------------------


def test_tenant_mismatch_is_rejected(rule_provider):
    tenant_id = EntityId.generate()
    other_event = make_canonical_event(tenant_id=EntityId.generate())
    service = _service(rule_provider)

    result = service.evaluate_event(
        EvaluateCanonicalEventCommand(
            tenant_id=tenant_id, canonical_event=other_event, actor_roles=EXECUTOR_ROLES
        )
    )

    assert result.status == DetectionStatus.EVALUATION_REJECTED
    assert result.failures[0].error_type == "TenantContextMismatchError"
    assert result.outcomes == ()


# ---------------------------------------------------------------------------
# authorization
# ---------------------------------------------------------------------------


def test_without_executor_role_raises_forbidden(rule_provider):
    tenant_id = EntityId.generate()
    service = _service(rule_provider)

    with pytest.raises(ApplicationForbiddenError):
        service.evaluate_event(
            EvaluateCanonicalEventCommand(
                tenant_id=tenant_id,
                canonical_event=make_canonical_event(tenant_id=tenant_id),
                actor_roles=(),
            )
        )


# ---------------------------------------------------------------------------
# batch evaluation
# ---------------------------------------------------------------------------


def test_batch_evaluation_all_succeed(rule_provider):
    tenant_id = EntityId.generate()
    rule = make_active_rule(tenant_id)
    rule_provider._rules.append(rule)
    registry = InMemoryDetectionEvaluatorRegistry()
    registry.register(FakeDetectionEvaluator(str(rule.rule_id), evaluator=matched()))
    service = _service(rule_provider, registry)

    events = tuple(make_canonical_event(tenant_id=tenant_id) for _ in range(3))
    result = service.evaluate_batch(
        EvaluateBatchCommand(tenant_id=tenant_id, events=events, actor_roles=EXECUTOR_ROLES)
    )

    assert result.status == DetectionStatus.SUCCEEDED
    assert result.succeeded_count == 3
    assert len(result.matches) == 3


def test_batch_evaluation_partial_failure(rule_provider):
    tenant_id = EntityId.generate()
    other_tenant_event = make_canonical_event(tenant_id=EntityId.generate())
    service = _service(rule_provider)

    events = (make_canonical_event(tenant_id=tenant_id), other_tenant_event)
    result = service.evaluate_batch(
        EvaluateBatchCommand(tenant_id=tenant_id, events=events, actor_roles=EXECUTOR_ROLES)
    )

    assert result.status == DetectionStatus.PARTIALLY_SUCCEEDED
    assert result.succeeded_count == 1
    assert result.failed_count == 1


def test_batch_evaluation_empty_raises(rule_provider):
    service = _service(rule_provider)
    with pytest.raises(EmptyBatchEvaluationError):
        service.evaluate_batch(
            EvaluateBatchCommand(
                tenant_id=EntityId.generate(), events=(), actor_roles=EXECUTOR_ROLES
            )
        )


def test_batch_without_role_raises_forbidden(rule_provider):
    service = _service(rule_provider)
    with pytest.raises(ApplicationForbiddenError):
        service.evaluate_batch(
            EvaluateBatchCommand(
                tenant_id=EntityId.generate(),
                events=(make_canonical_event(),),
                actor_roles=(),
            )
        )


# ---------------------------------------------------------------------------
# schema version routing
# ---------------------------------------------------------------------------


def test_evaluator_routed_by_event_schema_version(rule_provider):
    tenant_id = EntityId.generate()
    rule = make_active_rule(tenant_id)
    rule_provider._rules.append(rule)
    registry = InMemoryDetectionEvaluatorRegistry()
    registry.register(
        FakeDetectionEvaluator(str(rule.rule_id), SCHEMA_V1_0, evaluator=matched())
    )
    service = _service(rule_provider, registry)

    result = service.evaluate_event(
        EvaluateCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=make_canonical_event(tenant_id=tenant_id),
            actor_roles=EXECUTOR_ROLES,
        )
    )
    assert len(result.matches) == 1


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_event_detection_result_is_frozen(rule_provider):
    tenant_id = EntityId.generate()
    service = _service(rule_provider)
    result = service.evaluate_event(
        EvaluateCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=make_canonical_event(tenant_id=tenant_id),
            actor_roles=EXECUTOR_ROLES,
        )
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.status = DetectionStatus.FAILED  # type: ignore[misc]
