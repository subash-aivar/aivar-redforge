"""Immutable CQRS query objects for the Security Baseline / CSPM
Foundation (M45F)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        EvaluationId,
        TenantId,
    )


@dataclass(frozen=True, slots=True)
class GetBaselineResultQuery:
    tenant_id: TenantId
    evaluation_id: EvaluationId


@dataclass(frozen=True, slots=True)
class ListBaselineFindingsQuery:
    tenant_id: TenantId
    evaluation_id: EvaluationId


@dataclass(frozen=True, slots=True)
class ListFailedEvaluationsQuery:
    tenant_id: TenantId
    account_id: AccountId | None = None


@dataclass(frozen=True, slots=True)
class BaselineStatisticsQuery:
    tenant_id: TenantId
    account_id: AccountId | None = None
