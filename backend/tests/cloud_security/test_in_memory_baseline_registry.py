from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cloud_security.application.exceptions import DuplicateEvaluationError
from cloud_security.application.registry.in_memory_baseline_registry import (
    InMemoryBaselineRegistry,
)
from cloud_security.domain.aggregates.cloud_security_evaluation import CloudSecurityEvaluation
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    EvaluationId,
    ProviderId,
    TenantId,
)

NOW = datetime.now(UTC)


def _start(tenant_id, account_id=None, provider_id=None, **overrides) -> CloudSecurityEvaluation:
    defaults = {
        "evaluation_id": EvaluationId.generate(),
        "tenant_id": tenant_id,
        "account_id": account_id or AccountId.generate(),
        "provider_id": provider_id or ProviderId.generate(),
        "now": NOW,
    }
    defaults.update(overrides)
    return CloudSecurityEvaluation.start(**defaults)


def test_register_then_get_returns_same_evaluation() -> None:
    registry = InMemoryBaselineRegistry()
    tenant_id = TenantId.generate()
    evaluation = _start(tenant_id)
    registry.register(evaluation)

    assert registry.get(tenant_id, evaluation.evaluation_id) is evaluation


def test_get_wrong_tenant_returns_none() -> None:
    registry = InMemoryBaselineRegistry()
    evaluation = _start(TenantId.generate())
    registry.register(evaluation)

    assert registry.get(TenantId.generate(), evaluation.evaluation_id) is None


def test_get_unknown_id_returns_none() -> None:
    registry = InMemoryBaselineRegistry()
    assert registry.get(TenantId.generate(), EvaluationId.generate()) is None


def test_duplicate_active_evaluation_for_same_account_provider_raises() -> None:
    registry = InMemoryBaselineRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    registry.register(_start(tenant_id, account_id, provider_id))

    with pytest.raises(DuplicateEvaluationError):
        registry.register(_start(tenant_id, account_id, provider_id))


def test_different_providers_same_account_do_not_conflict() -> None:
    registry = InMemoryBaselineRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    registry.register(_start(tenant_id, account_id, ProviderId.generate()))
    registry.register(_start(tenant_id, account_id, ProviderId.generate()))  # no raise


def test_has_active_evaluation() -> None:
    registry = InMemoryBaselineRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    registry.register(_start(tenant_id, account_id, provider_id))

    assert registry.has_active_evaluation(tenant_id, account_id, provider_id) is True
    assert registry.has_active_evaluation(tenant_id, account_id, ProviderId.generate()) is False


def test_list_scoped_to_tenant_and_account() -> None:
    registry = InMemoryBaselineRegistry()
    tenant_a, tenant_b = TenantId.generate(), TenantId.generate()
    account_x = AccountId.generate()
    eval_a = _start(tenant_a, account_x)
    eval_b = _start(tenant_b)
    registry.register(eval_a)
    registry.register(eval_b)

    assert registry.list(tenant_a) == (eval_a,)
    assert registry.list(tenant_a, account_id=account_x) == (eval_a,)
    assert registry.list(tenant_a, account_id=AccountId.generate()) == ()


def test_list_failed_only_returns_failed() -> None:
    registry = InMemoryBaselineRegistry()
    tenant_id = TenantId.generate()
    failed = _start(tenant_id)
    completed = _start(tenant_id)
    registry.register(failed)
    registry.register(completed)
    failed.fail(tenant_id, "boom", NOW)
    completed.complete(tenant_id, NOW)

    assert registry.list_failed(tenant_id) == (failed,)


def test_release_frees_slot_for_new_evaluation() -> None:
    registry = InMemoryBaselineRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    evaluation = _start(tenant_id, account_id, provider_id)
    registry.register(evaluation)

    evaluation.complete(tenant_id, NOW)
    registry.release(evaluation)

    assert registry.has_active_evaluation(tenant_id, account_id, provider_id) is False
    registry.register(_start(tenant_id, account_id, provider_id))  # no raise


def test_release_is_noop_while_in_progress() -> None:
    registry = InMemoryBaselineRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    evaluation = _start(tenant_id, account_id, provider_id)
    registry.register(evaluation)

    registry.release(evaluation)  # still IN_PROGRESS, must not free the slot

    assert registry.has_active_evaluation(tenant_id, account_id, provider_id) is True
