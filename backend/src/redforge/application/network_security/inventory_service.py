"""NetworkInventoryService — M16.

Backend-derived network inventory read model. Never computed in the
frontend — every field here is sourced from canonical AIAsset/
SecurityCondition/SecurityCorrelation/NetworkMonitoringPolicy state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from redforge.domain.network_security.address import (
    NetworkAddressError,
    normalize_and_classify,
)
from redforge.domain.network_security.value_objects import PolicyLifecycle
from redforge.infrastructure.database.repositories.network_security.policy_repository import (
    SqlAlchemyNetworkMonitoringPolicyRepository,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.inventory.tenant_asset_service import TenantAssetService
    from redforge.application.security_conditions.service import TenantSecurityConditionService
    from redforge.application.security_correlation.rules import CorrelationRuleRegistry
    from redforge.domain.network_security.entity import NetworkMonitoringPolicy


@dataclass(frozen=True, slots=True)
class NetworkInventoryEntryDTO:
    asset_id: str
    address: str
    address_classification: str
    observed_services: list[str] = field(default_factory=list)
    active_condition_count: int = 0
    last_observed_at: str = ""
    monitoring_status: str = "not_monitored"


@dataclass(frozen=True, slots=True)
class NetworkAssetDetailDTO:
    asset_id: str
    address: str
    address_classification: str
    first_observed_at: str
    last_observed_at: str
    services: list[dict[str, str]]
    active_conditions: list[dict[str, str]]
    active_correlations: list[dict[str, str]]
    monitoring_policy_id: str | None
    monitoring_lifecycle: str | None


class NetworkInventoryService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_inventory(
        self, organization_id: str, limit: int = 100, offset: int = 0,
    ) -> list[NetworkInventoryEntryDTO]:
        from redforge.application.inventory.tenant_asset_service import TenantAssetService
        from redforge.application.security_conditions.service import (
            TenantSecurityConditionService,
        )

        asset_service = TenantAssetService(self._session_factory)
        condition_service = TenantSecurityConditionService(self._session_factory)

        ip_assets = await asset_service.list_for_org(
            organization_id, asset_type="ip_address", limit=limit, offset=offset,
        )
        policies_by_target = await self._monitoring_status_by_target(organization_id)

        entries: list[NetworkInventoryEntryDTO] = []
        for asset in ip_assets:
            raw_ip = asset.external_id.partition(":")[2]
            try:
                classification = normalize_and_classify(raw_ip).address_class.value
            except NetworkAddressError:
                classification = "unknown"

            relationships = await asset_service.get_relationships_for_org(
                asset.id, organization_id,
            )
            services: list[str] = []
            for rel in relationships:
                if rel["relationship_type"] != "ip_assigned_to_host":
                    continue
                host_relationships = await asset_service.get_relationships_for_org(
                    rel["target_asset_id"], organization_id,
                )
                for host_rel in host_relationships:
                    if host_rel["relationship_type"] == "host_exposes_service":
                        svc = await asset_service.get_for_org(
                            host_rel["target_asset_id"], organization_id,
                        )
                        services.append(svc.name)

            conditions = await condition_service.list_active_for_asset(organization_id, asset.id)
            entries.append(
                NetworkInventoryEntryDTO(
                    asset_id=asset.id, address=raw_ip, address_classification=classification,
                    observed_services=services, active_condition_count=len(conditions),
                    last_observed_at=asset.last_observed_at,
                    monitoring_status=policies_by_target.get(asset.id, "not_monitored"),
                )
            )
        return entries

    async def get_asset_detail(
        self, organization_id: str, asset_id: str,
    ) -> NetworkAssetDetailDTO:
        from redforge.application.inventory.tenant_asset_service import TenantAssetService
        from redforge.application.security_conditions.service import (
            TenantSecurityConditionService,
        )
        from redforge.application.security_correlation.service import (
            TenantSecurityCorrelationService,
        )
        from redforge.core.exceptions import NotFoundError

        asset_service = TenantAssetService(self._session_factory)
        condition_service = TenantSecurityConditionService(self._session_factory)

        asset = await asset_service.get_for_org(asset_id, organization_id)
        if asset.asset_type not in ("ip_address", "network"):
            raise NotFoundError("NetworkAsset", asset_id)

        raw_value = asset.external_id.partition(":")[2]
        try:
            classification = normalize_and_classify(raw_value).address_class.value
        except NetworkAddressError:
            classification = "unknown"

        relationships = await asset_service.get_relationships_for_org(asset_id, organization_id)
        services: list[dict[str, str]] = []
        for rel in relationships:
            if rel["relationship_type"] != "ip_assigned_to_host":
                continue
            host_relationships = await asset_service.get_relationships_for_org(
                rel["target_asset_id"], organization_id,
            )
            for host_rel in host_relationships:
                if host_rel["relationship_type"] == "host_exposes_service":
                    svc = await asset_service.get_for_org(
                        host_rel["target_asset_id"], organization_id,
                    )
                    services.append({
                        "id": svc.id, "name": svc.name, "external_id": svc.external_id,
                        "metadata": str(svc.metadata),
                    })

        conditions = await condition_service.list_active_for_asset(organization_id, asset_id)
        registry = _default_correlation_registry(asset_service, condition_service)
        correlation_service = TenantSecurityCorrelationService(self._session_factory, registry)
        correlations = await correlation_service.list_for_org(
            organization_id, lifecycle="active", limit=200,
        )
        related_correlations = [c for c in correlations if asset_id in c.entity_ids]

        policy = await self._monitoring_policy_for_target(organization_id, asset_id)

        return NetworkAssetDetailDTO(
            asset_id=asset.id, address=raw_value, address_classification=classification,
            first_observed_at=asset.first_observed_at, last_observed_at=asset.last_observed_at,
            services=services,
            active_conditions=[
                {"stable_rule_id": c.stable_rule_id, "severity": c.severity, "title": c.title,
                 "summary": c.summary}
                for c in conditions
            ],
            active_correlations=[
                {"stable_rule_id": c.stable_rule_id, "title": c.title, "summary": c.summary}
                for c in related_correlations
            ],
            monitoring_policy_id=str(policy.id) if policy else None,
            monitoring_lifecycle=str(policy.lifecycle) if policy else None,
        )

    async def _monitoring_status_by_target(self, organization_id: str) -> dict[str, str]:
        async with self._session_factory() as session:
            repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
            policies = await repo.list_for_organization(
                EntityId.from_string(organization_id), None, 500, 0,
            )
        return {
            str(p.target_asset_id): (
                "monitored" if p.lifecycle == PolicyLifecycle.ACTIVE else str(p.lifecycle)
            )
            for p in policies
        }

    async def _monitoring_policy_for_target(
        self, organization_id: str, asset_id: str,
    ) -> NetworkMonitoringPolicy | None:
        async with self._session_factory() as session:
            repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
            policies = await repo.list_for_organization(
                EntityId.from_string(organization_id), None, 500, 0,
            )
        for p in policies:
            if str(p.target_asset_id) == asset_id:
                return p
        return None


def _default_correlation_registry(
    asset_service: TenantAssetService, condition_service: TenantSecurityConditionService,
) -> CorrelationRuleRegistry:
    from redforge.application.security_correlation.rules import (
        CorrelationRuleRegistry,
        MultipleSecurityConditionsOnAssetRule,
        PublicSensitiveServiceContextRule,
    )

    registry = CorrelationRuleRegistry()
    registry.register(PublicSensitiveServiceContextRule(asset_service, condition_service))
    registry.register(MultipleSecurityConditionsOnAssetRule(condition_service))
    return registry
