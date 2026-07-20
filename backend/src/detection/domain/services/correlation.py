"""CorrelationService — assembles CorrelationContext from ACL adapters."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid7

from detection.domain.value_objects.enums import CorrelationStatus
from detection.domain.value_objects.execution_finding import (
    CorrelationContext,
    FindingCorrelation,
)

if TYPE_CHECKING:
    from detection.domain.aggregates.detection_finding import DetectionFinding
    from detection.domain.ports.correlation_ports import (
        IBehavioralSignalAdapter,
        ICloudContextAdapter,
        IComplianceAdapter,
        IInventoryAdapter,
        IThreatIntelAdapter,
        IVulnerabilityContextAdapter,
    )
    from detection.domain.value_objects.identifiers import TenantId

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CorrelationResult:
    correlation: FindingCorrelation
    status: CorrelationStatus
    sources_succeeded: int
    sources_failed: int
    errors: list[str]


class CorrelationService:
    """Calls ACL adapters in parallel; graceful degradation per source."""

    def __init__(
        self,
        inventory: IInventoryAdapter,
        cloud: ICloudContextAdapter,
        vulnerability: IVulnerabilityContextAdapter,
        threat_intel: IThreatIntelAdapter,
        compliance: IComplianceAdapter,
        behavioral: IBehavioralSignalAdapter,
    ) -> None:
        self._inventory = inventory
        self._cloud = cloud
        self._vulnerability = vulnerability
        self._threat_intel = threat_intel
        self._compliance = compliance
        self._behavioral = behavioral

    async def correlate(
        self,
        finding: DetectionFinding,
        tenant_id: TenantId,
        *,
        sibling_finding_refs: tuple[str, ...] = (),
        identity_ref: str | None = None,
        now: datetime | None = None,
    ) -> CorrelationResult:
        when = now or datetime.now(UTC)
        asset_id = finding.asset_ref.asset_id
        rule_id = finding.rule_ref.rule_id
        succeeded = 0
        failed = 0
        errors: list[str] = []

        asset_metadata: dict[str, Any] = {}
        cloud_context: dict[str, Any] = {}
        vuln_refs: tuple[str, ...] = ()
        threat_refs: tuple[str, ...] = ()
        controls: tuple[str, ...] = ()
        behavioral_meta: dict[str, Any] = {}

        async def _safe(name: str, coro: Any) -> Any:
            nonlocal succeeded, failed
            try:
                result = await coro
                succeeded += 1
                return result
            except Exception as exc:
                failed += 1
                errors.append(f"{name}: {exc}")
                logger.warning(
                    "correlation_acl_degraded",
                    extra={"adapter": name, "error": str(exc)},
                )
                return None

        asset_r, cloud_r, vuln_r, threat_r, comp_r, behav_r = await asyncio.gather(
            _safe("inventory", self._inventory.resolve_asset(asset_id, tenant_id)),
            _safe("cloud", self._cloud.resolve_cloud(asset_id, tenant_id)),
            _safe(
                "vulnerability",
                self._vulnerability.resolve_vulnerabilities(asset_id, tenant_id),
            ),
            _safe(
                "threat_intel",
                self._threat_intel.resolve_threat_actors(
                    asset_id=asset_id, rule_id=rule_id, tenant_id=tenant_id
                ),
            ),
            _safe("compliance", self._compliance.resolve_controls(rule_id, tenant_id)),
            _safe(
                "behavioral", self._behavioral.resolve_behavioral(asset_id, tenant_id)
            ),
        )

        if asset_r is not None:
            asset_metadata = {
                "asset_id": asset_r.asset_id,
                "asset_type": asset_r.asset_type,
                "business_criticality": asset_r.business_criticality,
                "tags": list(asset_r.tags),
                **dict(asset_r.metadata),
            }
        if cloud_r is not None:
            cloud_context = {
                "asset_id": cloud_r.asset_id,
                "internet_exposed": cloud_r.internet_exposed,
                "publicly_reachable": cloud_r.publicly_reachable,
                "cloud_provider": cloud_r.cloud_provider,
                "region": cloud_r.region,
                **dict(cloud_r.extra),
            }
        if vuln_r is not None:
            vuln_refs = tuple(vuln_r)
        if threat_r is not None:
            threat_refs = tuple(threat_r)
        if comp_r is not None:
            controls = tuple(comp_r)
        if behav_r is not None:
            behavioral_meta = {
                "anomaly_score": behav_r.anomaly_score,
                **dict(behav_r.signals),
            }
            asset_metadata = {**asset_metadata, "behavioral": behavioral_meta}

        context = CorrelationContext(
            asset_metadata=asset_metadata,
            vulnerability_instances=vuln_refs,
            cloud_context=cloud_context,
            identity_ref=identity_ref,
            threat_actor_refs=threat_refs,
            compliance_controls=controls,
            sibling_finding_refs=sibling_finding_refs,
            correlated_at=when,
        )
        correlation = FindingCorrelation(
            correlation_id=str(uuid7()),
            context=context,
            enriched=True,
        )

        if failed == 0 and succeeded > 0:
            status = CorrelationStatus.COMPLETED
        elif succeeded > 0:
            status = CorrelationStatus.PARTIAL
        else:
            status = CorrelationStatus.FAILED

        return CorrelationResult(
            correlation=correlation,
            status=status,
            sources_succeeded=succeeded,
            sources_failed=failed,
            errors=errors,
        )
