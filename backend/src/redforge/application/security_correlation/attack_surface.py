"""TenantAttackSurfaceService — M9.

Backend-computed, transparent read model over canonical AIAsset +
SecurityCondition + SecurityCorrelation state. No magic 0-100 risk
score — every field here is a directly countable/derivable canonical
fact, and severity/exposure precedence is explicit, never alphabetical.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.application.security_correlation import facts
from redforge.domain.security_correlation.value_objects import (
    ExternalExposureClassification,
    strongest_classification,
)

if TYPE_CHECKING:
    from redforge.application.inventory.tenant_asset_service import TenantAssetService
    from redforge.application.security_conditions.service import TenantSecurityConditionService
    from redforge.application.security_correlation.service import TenantSecurityCorrelationService

_SEVERITY_PRECEDENCE: tuple[str, ...] = (
    "informational", "low", "medium", "high", "critical",
)

_CLOUD_ENDPOINT_RULE_IDS = frozenset({"PUBLIC_STORAGE_CONFIGURATION", "PUBLIC_COMPUTE_ENDPOINT"})


def _highest_severity(severities: list[str]) -> str:
    """Explicit precedence order — never alphabetical sort. Unknown
    values are ignored for ranking purposes but never silently promoted
    to a known severity."""
    known = [s for s in severities if s in _SEVERITY_PRECEDENCE]
    if not known:
        return "UNKNOWN" if severities else "none"
    return max(known, key=_SEVERITY_PRECEDENCE.index)


@dataclass(frozen=True, slots=True)
class AssetExposureSummaryDTO:
    asset_id: str
    asset_name: str
    asset_kind: str
    external_classification: str
    active_condition_count: int
    observed_condition_count: int
    inferred_condition_count: int
    validated_condition_count: int
    highest_active_severity: str
    active_source_categories: list[str]
    sensitive_service_count: int
    active_correlation_count: int
    last_condition_observed_at: str | None


@dataclass(frozen=True, slots=True)
class AttackSurfaceSummaryDTO:
    assets_with_active_conditions: int
    assets_with_multiple_active_conditions: int
    active_correlations: int
    external_classification_breakdown: dict[str, int]
    evidence_state_breakdown: dict[str, int]


class TenantAttackSurfaceService:
    def __init__(
        self,
        asset_service: TenantAssetService,
        condition_service: TenantSecurityConditionService,
        correlation_service: TenantSecurityCorrelationService,
    ) -> None:
        self._asset_service = asset_service
        self._condition_service = condition_service
        self._correlation_service = correlation_service

    async def _exposed_asset_ids(self, organization_id: str) -> set[str]:
        public_ips = await facts.public_ip_asset_ids(self._asset_service, organization_id)
        public_hosts = await facts.public_host_asset_ids(
            self._asset_service, organization_id, public_ips
        )
        return public_ips | public_hosts

    async def get_summary_for_org(self, organization_id: str) -> AttackSurfaceSummaryDTO:
        condition_summary = await self._condition_service.get_summary_for_org(organization_id)
        multi_asset_ids = (
            await self._condition_service.list_asset_ids_with_multiple_active_conditions(
                organization_id,
            )
        )
        active_correlations = await self._correlation_service.list_for_org(
            organization_id, lifecycle="active", limit=500,
        )
        exposed_ids = await self._exposed_asset_ids(organization_id)
        active_conditions = await self._condition_service.list_for_org(
            organization_id, evidence_state=None, limit=500,
        )
        active_asset_ids = {
            c.affected_asset_id for c in active_conditions if c.lifecycle == "active"
        }

        classification_breakdown: dict[str, int] = {}
        for asset_id in active_asset_ids:
            classification = strongest_classification(
                [ExternalExposureClassification.PUBLIC_ADDRESS_OBSERVED]
                if asset_id in exposed_ids else []
            )
            classification_breakdown[classification.value] = (
                classification_breakdown.get(classification.value, 0) + 1
            )

        return AttackSurfaceSummaryDTO(
            assets_with_active_conditions=len(active_asset_ids),
            assets_with_multiple_active_conditions=len(multi_asset_ids),
            active_correlations=len(active_correlations),
            external_classification_breakdown=classification_breakdown,
            evidence_state_breakdown=dict(condition_summary.by_evidence_state),
        )

    async def get_asset_exposure_summary(
        self, organization_id: str, asset_id: str
    ) -> AssetExposureSummaryDTO:
        asset = await self._asset_service.get_for_org(asset_id, organization_id)
        active_conditions = await self._condition_service.list_active_for_asset(
            organization_id, asset_id,
        )
        exposed_ids = await self._exposed_asset_ids(organization_id)
        correlations = await self._correlation_service.list_for_org(
            organization_id, lifecycle="active", limit=500,
        )
        active_correlation_count = sum(1 for c in correlations if asset_id in c.entity_ids)

        endpoint_conditions = [
            c for c in active_conditions if c.stable_rule_id in _CLOUD_ENDPOINT_RULE_IDS
        ]
        is_exposed = asset_id in exposed_ids
        has_endpoint = bool(endpoint_conditions)
        classification = strongest_classification([
            *([ExternalExposureClassification.PUBLIC_ADDRESS_OBSERVED] if is_exposed else []),
            *([ExternalExposureClassification.PUBLIC_ENDPOINT_CONFIGURED] if has_endpoint else []),
        ])

        by_evidence_state: dict[str, int] = {}
        for c in active_conditions:
            by_evidence_state[c.evidence_state] = by_evidence_state.get(c.evidence_state, 0) + 1

        sensitive_service_count = sum(
            1 for c in active_conditions if c.stable_rule_id == "SENSITIVE_SERVICE_OBSERVED"
        )
        last_observed = max(
            (c.last_observed_at for c in active_conditions), default=None,
        )

        return AssetExposureSummaryDTO(
            asset_id=asset.id, asset_name=asset.name, asset_kind=asset.asset_type,
            external_classification=classification.value,
            active_condition_count=len(active_conditions),
            observed_condition_count=by_evidence_state.get("observed", 0),
            inferred_condition_count=by_evidence_state.get("inferred", 0),
            validated_condition_count=by_evidence_state.get("validated", 0),
            highest_active_severity=_highest_severity([c.severity for c in active_conditions]),
            active_source_categories=sorted({c.source_category for c in active_conditions}),
            sensitive_service_count=sensitive_service_count,
            active_correlation_count=active_correlation_count,
            last_condition_observed_at=last_observed,
        )
