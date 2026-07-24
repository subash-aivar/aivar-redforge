"""Immutable CQRS command objects for the Security Baseline / CSPM
Foundation (M45F). `CloudSecurityEvaluation` remains the single
aggregate these commands act against; evaluated `CloudAsset`s are
never mutated — `CloudAsset` (M45B) remains the single, read-only-from-
this-context inventory."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        AssetId,
        EvaluationId,
        ProviderId,
        TenantId,
    )


@dataclass(frozen=True, slots=True)
class EvaluateAssetCommand:
    tenant_id: TenantId
    account_id: AccountId
    provider_id: ProviderId
    asset_id: AssetId


@dataclass(frozen=True, slots=True)
class EvaluateAccountCommand:
    tenant_id: TenantId
    account_id: AccountId
    provider_id: ProviderId


@dataclass(frozen=True, slots=True)
class EvaluateOrganizationCommand:
    tenant_id: TenantId
    provider_id: ProviderId
    account_ids: tuple[AccountId, ...]


@dataclass(frozen=True, slots=True)
class RefreshBaselineCommand:
    tenant_id: TenantId
    evaluation_id: EvaluationId


@dataclass(frozen=True, slots=True)
class BatchBaselineCommand:
    tenant_id: TenantId
    commands: tuple[EvaluateAccountCommand, ...] = field(default_factory=tuple)
