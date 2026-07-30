"""Immutable CQRS query objects for risk_engine (M48C)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from risk_engine.domain.value_objects.enums import RiskProfileStatus
    from risk_engine.domain.value_objects.identifiers import (
        CorrelationSetId,
        RiskProfileId,
        TenantId,
    )


@dataclass(frozen=True, slots=True)
class GetEnterpriseRiskProfileQuery:
    tenant_id: TenantId
    profile_id: RiskProfileId


@dataclass(frozen=True, slots=True)
class ListEnterpriseRiskProfilesQuery:
    tenant_id: TenantId
    status: RiskProfileStatus | None = None
    subject_reference: str | None = None


@dataclass(frozen=True, slots=True)
class GetRiskTimelineQuery:
    tenant_id: TenantId
    profile_id: RiskProfileId
    since: datetime | None = None
    until: datetime | None = None


@dataclass(frozen=True, slots=True)
class GetRiskCorrelationSetQuery:
    tenant_id: TenantId
    correlation_set_id: CorrelationSetId
