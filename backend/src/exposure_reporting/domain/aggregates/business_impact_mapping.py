"""BusinessImpactMapping aggregate — Finalization Phase 5."""

from __future__ import annotations

from typing import TYPE_CHECKING

from exposure_reporting.domain.events.reporting_events import (
    BusinessImpactMappingCreated,
    BusinessImpactMappingUpdated,
)
from exposure_reporting.domain.exceptions.domain_exceptions import TenantMismatch
from exposure_reporting.domain.value_objects.enums import (
    BusinessCriticality,
    ImpactDomain,
)

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from exposure_reporting.domain.events.base import BaseDomainEvent
    from exposure_reporting.domain.value_objects.identifiers import (
        BusinessImpactMappingId,
        TenantId,
    )


class BusinessImpactMapping:
    __slots__ = (
        "_pending_events",
        "asset_ref_id",
        "authored_by",
        "business_process_ref",
        "business_unit_ref",
        "created_at",
        "criticality",
        "financial_impact_estimate",
        "impact_domain",
        "mapping_id",
        "regulatory_scope",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        mapping_id: BusinessImpactMappingId,
        tenant_id: TenantId,
        asset_ref_id: UUID,
        criticality: BusinessCriticality,
        impact_domain: ImpactDomain,
        authored_by: str,
        created_at: datetime,
        updated_at: datetime,
        business_process_ref: str | None = None,
        business_unit_ref: str | None = None,
        financial_impact_estimate: float | None = None,
        regulatory_scope: list[str] | None = None,
    ) -> None:
        self.mapping_id = mapping_id
        self.tenant_id = tenant_id
        self.asset_ref_id = asset_ref_id
        self.criticality = criticality
        self.impact_domain = impact_domain
        self.authored_by = authored_by
        self.created_at = created_at
        self.updated_at = updated_at
        self.business_process_ref = business_process_ref
        self.business_unit_ref = business_unit_ref
        self.financial_impact_estimate = financial_impact_estimate
        self.regulatory_scope = list(regulatory_scope or [])
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    @classmethod
    def create(
        cls,
        mapping_id: BusinessImpactMappingId,
        tenant_id: TenantId,
        asset_ref_id: UUID,
        criticality: BusinessCriticality,
        impact_domain: ImpactDomain,
        authored_by: str,
        at: datetime,
        *,
        business_process_ref: str | None = None,
        business_unit_ref: str | None = None,
        financial_impact_estimate: float | None = None,
        regulatory_scope: list[str] | None = None,
    ) -> BusinessImpactMapping:
        mapping = cls(
            mapping_id,
            tenant_id,
            asset_ref_id,
            criticality,
            impact_domain,
            authored_by,
            at,
            at,
            business_process_ref=business_process_ref,
            business_unit_ref=business_unit_ref,
            financial_impact_estimate=financial_impact_estimate,
            regulatory_scope=regulatory_scope,
        )
        mapping._emit(
            BusinessImpactMappingCreated(
                tenant_id=str(tenant_id),
                aggregate_id=str(mapping_id),
                asset_ref_id=str(asset_ref_id),
                criticality=criticality.value,
            )
        )
        return mapping

    def update(
        self,
        tenant_id: TenantId,
        *,
        criticality: BusinessCriticality,
        impact_domain: ImpactDomain,
        authored_by: str,
        at: datetime,
        business_process_ref: str | None = None,
        business_unit_ref: str | None = None,
        financial_impact_estimate: float | None = None,
        regulatory_scope: list[str] | None = None,
    ) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch on mapping update")
        self.criticality = criticality
        self.impact_domain = impact_domain
        self.authored_by = authored_by
        self.updated_at = at
        if business_process_ref is not None:
            self.business_process_ref = business_process_ref
        if business_unit_ref is not None:
            self.business_unit_ref = business_unit_ref
        if financial_impact_estimate is not None:
            self.financial_impact_estimate = financial_impact_estimate
        if regulatory_scope is not None:
            self.regulatory_scope = list(regulatory_scope)
        self._emit(
            BusinessImpactMappingUpdated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.mapping_id),
                asset_ref_id=str(self.asset_ref_id),
                criticality=criticality.value,
            )
        )
