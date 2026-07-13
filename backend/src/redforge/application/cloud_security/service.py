"""TenantCloudSecurityService — M7.

Orchestrates: PROVIDER ADAPTER -> TYPED OBSERVATIONS -> canonical
CLOUD_ACCOUNT/CLOUD_RESOURCE asset resolution (reusing the M3 `AIAsset`
aggregate and `TenantAssetService`, exactly like M6's network
discovery — not a disconnected cloud inventory) -> canonical
CLOUD_ACCOUNT_CONTAINS_RESOURCE relationship persistence -> best-effort
Security Graph projection (already wired into `TenantAssetService`) ->
deterministic cloud exposure analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.application.cloud_security.analysis_service import (
    CloudSecurityObservation,
    analyze,
)
from redforge.application.cloud_security.observations import (
    CloudDiscoveryResult,
    CloudResourceObservation,
)
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import (
    AssetDiscoverySource,
    AssetRelationshipType,
    AssetType,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from redforge.application.inventory.tenant_asset_service import TenantAssetService
    from redforge.application.security_conditions.service import TenantSecurityConditionService

# Deterministic, backend-derived severity per rule ID — mirrors the M6
# network analysis pattern; no producing source has a real CVSS score.
_RULE_SEVERITY: dict[str, str] = {
    "PUBLIC_STORAGE_CONFIGURATION": "high",
    "PUBLIC_COMPUTE_ENDPOINT": "medium",
}


@dataclass(frozen=True, slots=True)
class CloudDiscoverySummary:
    account_observed: bool
    resources_observed: int
    errors: tuple[str, ...]


def _describe_resource(resource: CloudResourceObservation) -> str:
    return (
        f"provider={resource.provider.value};class={resource.resource_class.value};"
        f"region={resource.region};public={'true' if resource.public else 'false'};"
        f"native_type={resource.native_type}"
    )


class TenantCloudSecurityService:
    def __init__(
        self,
        asset_service: TenantAssetService,
        condition_service: TenantSecurityConditionService | None = None,
    ) -> None:
        self._asset_service = asset_service
        self._condition_service = condition_service

    async def run_discovery(
        self, organization_id: str, connector_id: str, result: CloudDiscoveryResult
    ) -> CloudDiscoverySummary:
        asset_service = self._asset_service

        account_asset = await asset_service.resolve_asset(
            organization_id=organization_id,
            asset_type=AssetType.CLOUD_ACCOUNT,
            scheme=IdentityScheme.CLOUD_ACCOUNT_ID,
            raw_external_id=f"{result.account.provider.value}:{result.account.account_identifier}",
            name=result.account.display_name,
            description=f"provider={result.account.provider.value}",
            discovery_source=AssetDiscoverySource.API_SCAN,
        )

        for resource in result.resources:
            resource_asset = await asset_service.resolve_asset(
                organization_id=organization_id,
                asset_type=AssetType.CLOUD_RESOURCE,
                scheme=IdentityScheme.CLOUD_RESOURCE_ID,
                raw_external_id=resource.native_resource_id,
                name=resource.display_name,
                description=_describe_resource(resource),
                discovery_source=AssetDiscoverySource.API_SCAN,
            )
            await asset_service.add_relationship_for_org(
                organization_id, account_asset.id, resource_asset.id,
                AssetRelationshipType.CLOUD_ACCOUNT_CONTAINS_RESOURCE,
            )

        return CloudDiscoverySummary(
            account_observed=True, resources_observed=len(result.resources), errors=result.errors,
        )

    async def list_exposure_observations(
        self, organization_id: str
    ) -> list[CloudSecurityObservation]:
        rows = await self._asset_service.list_for_org(
            organization_id, asset_type="cloud_resource", limit=200,
        )
        resources = [{"id": r.id, "name": r.name, "description": r.description} for r in rows]
        observations = analyze(resources)
        await self._ingest_conditions_best_effort(organization_id, observations)
        return observations

    async def _ingest_conditions_best_effort(
        self, organization_id: str, observations: list[CloudSecurityObservation]
    ) -> None:
        """Routes eligible deterministic observations through the M8
        SecurityCondition ingestion port. Best-effort: an ingestion
        failure for one observation never blocks serving the live
        read-time observation list to the caller."""
        if self._condition_service is None:
            return
        from redforge.application.security_conditions.ingestion import SecurityConditionInput

        for obs in observations:
            severity = _RULE_SEVERITY.get(obs.rule_id)
            if severity is None:
                continue
            try:
                await self._condition_service.ingest(
                    SecurityConditionInput(
                        organization_id=organization_id,
                        affected_asset_id=obs.affected_asset_id,
                        source_category="cloud_configuration",
                        stable_rule_id=obs.rule_id,
                        evidence_state="observed",
                        severity=severity,
                        title=obs.title,
                        summary=obs.summary,
                    )
                )
            except Exception:
                logger.warning(
                    "cloud_security: security condition ingestion failed for rule_id=%s "
                    "asset_id=%s", obs.rule_id, obs.affected_asset_id, exc_info=True,
                )
