"""InMemoryBaselineRegistry — the one concrete registry this milestone
implements (M45F). Stores `CloudSecurityEvaluation` aggregates
in-memory, keyed by `evaluation_id`, with a secondary uniqueness
constraint of one *active* (`IN_PROGRESS`) evaluation per
`(tenant_id, account_id, provider_id)`. No persistence, no DI
container wiring, no cloud SDK calls."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.application.exceptions import DuplicateEvaluationError
from cloud_security.domain.value_objects.enums import EvaluationStatus

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.domain.aggregates.cloud_security_evaluation import (
        CloudSecurityEvaluation,
    )
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        EvaluationId,
        ProviderId,
        TenantId,
    )


class InMemoryBaselineRegistry:
    def __init__(self) -> None:
        self._by_evaluation_id: dict[str, CloudSecurityEvaluation] = {}
        self._active_by_tenant_account_provider: dict[tuple[str, str, str], str] = {}

    def register(self, evaluation: CloudSecurityEvaluation) -> None:
        key = (
            str(evaluation.tenant_id),
            str(evaluation.account_id),
            str(evaluation.provider_id),
        )
        if key in self._active_by_tenant_account_provider:
            raise DuplicateEvaluationError(evaluation.account_id, evaluation.provider_id)
        self._by_evaluation_id[str(evaluation.evaluation_id)] = evaluation
        self._active_by_tenant_account_provider[key] = str(evaluation.evaluation_id)

    def get(
        self, tenant_id: TenantId, evaluation_id: EvaluationId
    ) -> CloudSecurityEvaluation | None:
        evaluation = self._by_evaluation_id.get(str(evaluation_id))
        if evaluation is None or evaluation.tenant_id != tenant_id:
            return None
        return evaluation

    def list(
        self, tenant_id: TenantId, account_id: AccountId | None = None
    ) -> Sequence[CloudSecurityEvaluation]:
        results = (e for e in self._by_evaluation_id.values() if e.tenant_id == tenant_id)
        if account_id is not None:
            results = (e for e in results if e.account_id == account_id)
        return tuple(results)

    def list_failed(
        self, tenant_id: TenantId, account_id: AccountId | None = None
    ) -> Sequence[CloudSecurityEvaluation]:
        return tuple(
            e for e in self.list(tenant_id, account_id) if e.status == EvaluationStatus.FAILED
        )

    def has_active_evaluation(
        self, tenant_id: TenantId, account_id: AccountId, provider_id: ProviderId
    ) -> bool:
        return (str(tenant_id), str(account_id), str(provider_id)) in (
            self._active_by_tenant_account_provider
        )

    def release(self, evaluation: CloudSecurityEvaluation) -> None:
        if evaluation.status == EvaluationStatus.IN_PROGRESS:
            return
        key = (
            str(evaluation.tenant_id),
            str(evaluation.account_id),
            str(evaluation.provider_id),
        )
        self._active_by_tenant_account_provider.pop(key, None)
