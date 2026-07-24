"""BusinessImpactMappingService — CRUD (Phase 5)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from exposure_reporting.application._auth import require_at_least
from exposure_reporting.application.dtos.reporting_dtos import BusinessImpactMappingDTO
from exposure_reporting.application.exceptions import (
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from exposure_reporting.domain.aggregates.business_impact_mapping import (
    BusinessImpactMapping,
)
from exposure_reporting.domain.exceptions.domain_exceptions import (
    ExposureReportingDomainError,
)
from exposure_reporting.domain.value_objects.enums import (
    BusinessCriticality,
    ImpactDomain,
    ReportingRole,
)
from exposure_reporting.domain.value_objects.identifiers import (
    BusinessImpactMappingId,
    TenantId,
)

if TYPE_CHECKING:
    from uuid import UUID

    from exposure_reporting.application.commands.reporting_commands import (
        CreateBusinessImpactMappingCommand,
        UpdateBusinessImpactMappingCommand,
    )
    from exposure_reporting.application.ports.i_event_publisher import IEventPublisher
    from exposure_reporting.domain.repositories.i_business_impact_mapping_repository import (
        IBusinessImpactMappingRepository,
    )


def _to_dto(m: BusinessImpactMapping) -> BusinessImpactMappingDTO:
    return BusinessImpactMappingDTO(
        mapping_id=str(m.mapping_id),
        tenant_id=str(m.tenant_id),
        asset_ref_id=str(m.asset_ref_id),
        criticality=m.criticality.value,
        impact_domain=m.impact_domain.value,
        authored_by=m.authored_by,
        created_at=m.created_at.isoformat(),
        updated_at=m.updated_at.isoformat(),
        business_process_ref=m.business_process_ref,
        business_unit_ref=m.business_unit_ref,
        financial_impact_estimate=m.financial_impact_estimate,
        regulatory_scope=list(m.regulatory_scope),
    )


class BusinessImpactMappingService:
    def __init__(
        self,
        repo: IBusinessImpactMappingRepository,
        event_publisher: IEventPublisher,
    ) -> None:
        self._repo = repo
        self._events = event_publisher

    async def create(self, cmd: CreateBusinessImpactMappingCommand) -> BusinessImpactMappingDTO:
        require_at_least(cmd.actor_roles, ReportingRole.ENGINEER)
        tenant = cmd.tenant_id
        existing = await self._repo.find_by_asset(tenant, cmd.asset_ref_id)
        if existing is not None:
            raise ApplicationConflictError("mapping already exists for asset")
        try:
            criticality = BusinessCriticality(cmd.criticality)
            impact = ImpactDomain(cmd.impact_domain)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        now = datetime.now(UTC)
        mapping = BusinessImpactMapping.create(
            BusinessImpactMappingId.generate(),
            tenant,
            cmd.asset_ref_id,
            criticality,
            impact,
            cmd.authored_by,
            now,
            business_process_ref=cmd.business_process_ref,
            business_unit_ref=cmd.business_unit_ref,
            financial_impact_estimate=cmd.financial_impact_estimate,
            regulatory_scope=list(cmd.regulatory_scope),
        )
        await self._repo.save(tenant, mapping)
        await self._events.publish_batch(mapping.pop_events())
        return _to_dto(mapping)

    async def update(self, cmd: UpdateBusinessImpactMappingCommand) -> BusinessImpactMappingDTO:
        require_at_least(cmd.actor_roles, ReportingRole.ENGINEER)
        tenant = cmd.tenant_id
        mapping = await self._repo.find_by_asset(tenant, cmd.asset_ref_id)
        if mapping is None:
            raise ApplicationNotFoundError(str(cmd.asset_ref_id))
        try:
            criticality = BusinessCriticality(cmd.criticality)
            impact = ImpactDomain(cmd.impact_domain)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        try:
            mapping.update(
                tenant,
                criticality=criticality,
                impact_domain=impact,
                authored_by=cmd.authored_by,
                at=datetime.now(UTC),
                business_process_ref=cmd.business_process_ref,
                business_unit_ref=cmd.business_unit_ref,
                financial_impact_estimate=cmd.financial_impact_estimate,
                regulatory_scope=(
                    list(cmd.regulatory_scope) if cmd.regulatory_scope is not None else None
                ),
            )
        except ExposureReportingDomainError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        await self._repo.save(tenant, mapping)
        await self._events.publish_batch(mapping.pop_events())
        return _to_dto(mapping)

    async def get_by_asset(
        self, tenant_id: TenantId, asset_ref_id: UUID, actor_roles: tuple[str, ...]
    ) -> BusinessImpactMappingDTO:
        require_at_least(actor_roles, ReportingRole.VIEWER)
        mapping = await self._repo.find_by_asset(tenant_id, asset_ref_id)
        if mapping is None:
            raise ApplicationNotFoundError(str(asset_ref_id))
        return _to_dto(mapping)

    async def list_mappings(
        self, tenant_id: TenantId, actor_roles: tuple[str, ...]
    ) -> list[BusinessImpactMappingDTO]:
        require_at_least(actor_roles, ReportingRole.VIEWER)
        rows = await self._repo.list_by_tenant(tenant_id)
        return [_to_dto(m) for m in rows]

    async def criticality_for_asset(self, tenant_id: TenantId, asset_ref_id: UUID) -> str | None:
        mapping = await self._repo.find_by_asset(tenant_id, asset_ref_id)
        return mapping.criticality.value if mapping else None
