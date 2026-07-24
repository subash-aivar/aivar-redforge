"""IBaselineReader — the read-side extension point for a future
persistence-backed evaluation store (M45F), mirroring `IDiscoveryReader`
(M45E). No concrete implementation exists in this milestone —
`InMemoryBaselineRegistry` serves reads directly this milestone; this
port exists for a future infrastructure milestone to swap in real
storage without changing the application service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.application.dtos.baseline_evaluation_record import (
        BaselineEvaluationRecord,
    )
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        EvaluationId,
        TenantId,
    )


class IBaselineReader(Protocol):
    def get(
        self, tenant_id: TenantId, evaluation_id: EvaluationId
    ) -> BaselineEvaluationRecord | None: ...

    def list(
        self, tenant_id: TenantId, account_id: AccountId | None = None
    ) -> Sequence[BaselineEvaluationRecord]: ...
