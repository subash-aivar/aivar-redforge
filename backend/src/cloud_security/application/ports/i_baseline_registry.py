"""IBaselineRegistry — the Security Baseline framework's own
tenant-isolated store of `CloudSecurityEvaluation` aggregates (M45F),
mirroring `IDiscoveryRegistry` (M45E): the registry *is* the
framework's in-memory store, not a plug-in resolver. Provider-plugin
resolution (`IBaselineProvider`) is a separate, deliberately
non-tenant-scoped concern — the same precedent `ICloudProviderRegistry`
(M45A), `IAssetInventoryRegistry` (M45B), and `IDiscoveryRegistry`
(M45E) already set: a baseline provider implementation is shared code,
not per-tenant data. `InMemoryBaselineRegistry` (M45F) is this
milestone's one concrete implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

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


class IBaselineRegistry(Protocol):
    def register(self, evaluation: CloudSecurityEvaluation) -> None:
        """Raises `DuplicateEvaluationError` if the same
        `(tenant_id, account_id, provider_id)` already has an
        `IN_PROGRESS` evaluation."""
        ...

    def get(
        self, tenant_id: TenantId, evaluation_id: EvaluationId
    ) -> CloudSecurityEvaluation | None: ...

    def list(
        self, tenant_id: TenantId, account_id: AccountId | None = None
    ) -> Sequence[CloudSecurityEvaluation]: ...

    def list_failed(
        self, tenant_id: TenantId, account_id: AccountId | None = None
    ) -> Sequence[CloudSecurityEvaluation]: ...

    def has_active_evaluation(
        self, tenant_id: TenantId, account_id: AccountId, provider_id: ProviderId
    ) -> bool: ...

    def release(self, evaluation: CloudSecurityEvaluation) -> None:
        """Free the `(tenant, account, provider)` uniqueness slot once
        `evaluation` has reached a terminal status, so a fresh
        evaluation for the same pair can proceed. A no-op while still
        `IN_PROGRESS`."""
        ...
