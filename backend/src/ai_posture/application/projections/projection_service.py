"""Apply M31 domain events to Security Graph + read-model projections."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ai_posture.application.projections.read_models import (
    PROJECTION_VERSION,
    AIAgentDeviationReport,
    AIAssetInventoryDashboard,
    AICompliancePostureReport,
    AIRiskRegister,
    AISupplyChainIntegrityReport,
    EnvelopeHumanApprovalAudit,
    ShadowAIDiscoveryReport,
)
from ai_posture.domain.events.posture_events import (
    AIComplianceGapIdentified,
    AIComplianceMappingRecorded,
    AIRiskScoreComputed,
    AISystemAssetRegistered,
    ShadowAIAlertRaised,
)

if TYPE_CHECKING:
    from ai_posture.application.projections.read_model_store import IReadModelStore
    from ai_posture.domain.events.base import BaseDomainEvent
    from ai_posture.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort


class M31ProjectionService:
    """Idempotent projection updater — safe under event replay."""

    def __init__(
        self,
        store: IReadModelStore,
        graph: ISecurityGraphWritePort,
    ) -> None:
        self._store = store
        self._graph = graph
        self._seen: set[str] = set()

    async def apply(self, event: BaseDomainEvent) -> None:
        if event.event_id in self._seen:
            return
        self._seen.add(event.event_id)
        tenant = str(event.tenant_id)
        if isinstance(event, AISystemAssetRegistered):
            await self._on_asset_registered(tenant, event)
        elif isinstance(event, AIRiskScoreComputed):
            await self._on_risk_computed(tenant, event)
        elif isinstance(event, ShadowAIAlertRaised):
            await self._on_shadow_raised(tenant, event)
        elif isinstance(event, AIComplianceMappingRecorded):
            await self._on_compliance_recorded(tenant, event)
        elif isinstance(event, AIComplianceGapIdentified):
            await self._on_compliance_gap(tenant, event)
        # Cross-BC normalized events arrive as generic payloads via apply_fact
        await self._graph_from_event(tenant, event)

    async def apply_fact(self, tenant_id: str, fact_type: str, payload: dict[str, Any]) -> None:
        """Apply normalized cross-context facts (supply chain / agent) without BC imports."""
        event_id = str(payload.get("event_id", f"{fact_type}:{payload.get('id', '')}"))
        if event_id in self._seen:
            return
        self._seen.add(event_id)
        if fact_type == "provenance":
            await self._apply_provenance_fact(tenant_id, payload, event_id)
        elif fact_type == "deviation":
            await self._apply_deviation_fact(tenant_id, payload, event_id)
        elif fact_type == "discovery_scan":
            await self._apply_discovery_fact(tenant_id, payload, event_id)
        elif fact_type == "human_approval_change":
            await self._apply_approval_audit(tenant_id, payload, event_id)

    async def rebuild_markers(self) -> dict[str, Any]:
        return {"seen_events": len(self._seen), "projection_version": PROJECTION_VERSION}

    async def _on_asset_registered(self, tenant: str, event: AISystemAssetRegistered) -> None:
        view = await self._store.load_inventory(tenant) or AIAssetInventoryDashboard(
            tenant_id=tenant
        )
        asset_id = event.aggregate_id
        existing = {a.get("asset_id") for a in view.assets}
        if asset_id not in existing:
            view.assets.append(
                {
                    "asset_id": asset_id,
                    "ai_system_kind": event.ai_system_kind,
                    "lifecycle_state": "Registered",
                }
            )
        view.last_event_id = event.event_id
        view.projection_version = PROJECTION_VERSION
        await self._store.save_inventory(view)

    async def _on_risk_computed(self, tenant: str, event: AIRiskScoreComputed) -> None:
        view = await self._store.load_risk_register(tenant) or AIRiskRegister(tenant_id=tenant)
        entry = {
            "asset_id": event.ai_system_asset_id,
            "composite_score": event.composite_score,
            "score_input_version": event.score_input_version,
            "computed_at": event.occurred_at.isoformat(),
            "is_stale": False,
        }
        view.entries = [e for e in view.entries if e.get("asset_id") != entry["asset_id"]]
        view.entries.append(entry)
        view.trend.append(
            {
                "asset_id": event.ai_system_asset_id,
                "composite_score": event.composite_score,
                "score_input_version": event.score_input_version,
                "computed_at": event.occurred_at.isoformat(),
            }
        )
        view.last_event_id = event.event_id
        await self._store.save_risk_register(view)

    async def _on_shadow_raised(self, tenant: str, event: ShadowAIAlertRaised) -> None:
        view = await self._store.load_shadow_report(tenant) or ShadowAIDiscoveryReport(
            tenant_id=tenant
        )
        view.alerts.append(
            {
                "alert_id": event.aggregate_id,
                "fingerprint_hash": event.fingerprint_hash,
                "discovery_source": event.discovery_source,
            }
        )
        view.last_event_id = event.event_id
        await self._store.save_shadow_report(view)

    async def _on_compliance_recorded(
        self, tenant: str, event: AIComplianceMappingRecorded
    ) -> None:
        view = await self._store.load_compliance_posture(
            tenant, event.framework_id
        ) or AICompliancePostureReport(tenant_id=tenant, framework_id=event.framework_id)
        row = {
            "control_id": event.control_id,
            "control_status": event.control_status,
            "requires_human_attestation": event.requires_human_attestation,
            "evaluation_mode": event.evaluation_mode,
            "asset_id": event.ai_system_asset_id,
            "label": (
                "Human-Attested"
                if event.evaluation_mode == "HumanAttested"
                else (
                    "Pending Attestation"
                    if event.evaluation_mode == "PendingAttestation"
                    else "Auto-Evaluated"
                )
            ),
        }
        view.controls = [
            c
            for c in view.controls
            if not (
                c.get("control_id") == row["control_id"] and c.get("asset_id") == row["asset_id"]
            )
        ]
        view.controls.append(row)
        view.gap_count = sum(1 for c in view.controls if c.get("control_status") == "Gap")
        view.last_event_id = event.event_id
        await self._store.save_compliance_posture(view)

    async def _on_compliance_gap(self, tenant: str, event: AIComplianceGapIdentified) -> None:
        # Gap count refreshed via MappingRecorded; ensure gap edge exists
        await self._graph.upsert_edge(
            tenant_id=tenant,
            edge_type="MAPPED_TO_CONTROL",
            from_key=f"AISystemNode:{event.ai_system_asset_id}",
            to_key=f"ComplianceControlNode:{event.framework_id}:{event.control_id}",
            properties={"control_status": "Gap"},
            event_id=event.event_id,
        )

    async def _apply_provenance_fact(
        self, tenant_id: str, payload: dict[str, Any], event_id: str
    ) -> None:
        view = await self._store.load_supply_chain(tenant_id) or AISupplyChainIntegrityReport(
            tenant_id=tenant_id
        )
        method = str(payload.get("verification_method", "IndependentHash"))
        tier_label = "Provider-Attested" if method == "ProviderAttestation" else "IndependentHash"
        row = {
            "asset_id": str(payload.get("asset_id", "")),
            "provenance_id": str(payload.get("provenance_id", "")),
            "integrity_status": str(payload.get("integrity_status", "Unverified")),
            "verification_method": method,
            "tier_label": tier_label,
            "trust_delegation_note": str(payload.get("trust_delegation_note", "")),
        }
        view.models = [m for m in view.models if m.get("provenance_id") != row["provenance_id"]]
        view.models.append(row)
        view.last_event_id = event_id
        await self._store.save_supply_chain(view)
        await self._graph.upsert_node(
            tenant_id=tenant_id,
            node_type="ModelProvenanceNode",
            node_key=row["provenance_id"],
            properties={
                "provenance_id": row["provenance_id"],
                "provenance_integrity_status": row["integrity_status"],
                "verification_method": method,
            },
            event_id=event_id,
        )

    async def _apply_deviation_fact(
        self, tenant_id: str, payload: dict[str, Any], event_id: str
    ) -> None:
        view = await self._store.load_deviation_report(tenant_id) or AIAgentDeviationReport(
            tenant_id=tenant_id
        )
        row = {
            "deviation_id": str(payload.get("deviation_id", "")),
            "asset_id": str(payload.get("asset_id", "")),
            "deviation_type": str(payload.get("deviation_type", "")),
            "severity": str(payload.get("severity", "")),
            "review_state": str(payload.get("review_state", "")),
        }
        view.deviations = [
            d for d in view.deviations if d.get("deviation_id") != row["deviation_id"]
        ]
        view.deviations.append(row)
        view.last_event_id = event_id
        await self._store.save_deviation_report(view)
        await self._graph.upsert_node(
            tenant_id=tenant_id,
            node_type="AIAgentNode",
            node_key=row["asset_id"],
            properties={"ai_system_asset_id": row["asset_id"]},
            event_id=event_id,
        )
        await self._graph.upsert_edge(
            tenant_id=tenant_id,
            edge_type="DEVIATED_FROM_ENVELOPE",
            from_key=f"AIAgentNode:{row['asset_id']}",
            to_key="AIThreatNode:AgentPrivilegeAbuse",
            properties={
                "deviation_severity": row["severity"],
                "detected_at": str(payload.get("detected_at", "")),
            },
            event_id=event_id,
        )

    async def _apply_discovery_fact(
        self, tenant_id: str, payload: dict[str, Any], event_id: str
    ) -> None:
        inventory = await self._store.load_inventory(tenant_id) or AIAssetInventoryDashboard(
            tenant_id=tenant_id
        )
        ended = payload.get("ended_at")
        if isinstance(ended, str):
            inventory.last_scan_at = datetime.fromisoformat(ended)
        elif isinstance(ended, datetime):
            inventory.last_scan_at = ended
        else:
            inventory.last_scan_at = datetime.now(UTC)
        sources = payload.get("sources") or []
        inventory.configured_discovery_sources = [str(s) for s in sources]
        inventory.coverage_scope = str(payload.get("coverage_scope", "configured_sources_only"))
        inventory.last_event_id = event_id
        await self._store.save_inventory(inventory)

        shadow = await self._store.load_shadow_report(tenant_id) or ShadowAIDiscoveryReport(
            tenant_id=tenant_id
        )
        shadow.scope_of_report = {
            "sources": inventory.configured_discovery_sources,
            "last_successful_scan_at": (
                inventory.last_scan_at.isoformat() if inventory.last_scan_at else None
            ),
            "coverage_scope": inventory.coverage_scope,
        }
        if payload.get("partial"):
            shadow.partial_scans.append(
                {
                    "scan_run_id": str(payload.get("scan_run_id", "")),
                    "partial": True,
                    "failed_partitions": list(payload.get("failed_partitions") or []),
                }
            )
        shadow.last_event_id = event_id
        await self._store.save_shadow_report(shadow)

    async def _apply_approval_audit(
        self, tenant_id: str, payload: dict[str, Any], event_id: str
    ) -> None:
        envelope_id = str(payload.get("envelope_id", ""))
        view = await self._store.load_approval_audit(
            tenant_id, envelope_id
        ) or EnvelopeHumanApprovalAudit(tenant_id=tenant_id, envelope_id=envelope_id)
        view.history.append(
            {
                "changed_at": str(payload.get("changed_at", "")),
                "action": str(payload.get("action", "")),
                "categories": list(payload.get("categories") or []),
                "actor_id": str(payload.get("actor_id", "")),
                "envelope_version": str(payload.get("envelope_version", "")),
            }
        )
        view.last_event_id = event_id
        await self._store.save_approval_audit(view)

    async def _graph_from_event(self, tenant: str, event: BaseDomainEvent) -> None:
        if isinstance(event, AISystemAssetRegistered):
            await self._graph.upsert_node(
                tenant_id=tenant,
                node_type="AISystemNode",
                node_key=event.aggregate_id,
                properties={
                    "ai_system_asset_id": event.aggregate_id,
                    "ai_system_kind": event.ai_system_kind,
                    "lifecycle_state": "Registered",
                },
                event_id=event.event_id,
            )
            await self._graph.upsert_edge(
                tenant_id=tenant,
                edge_type="EXTENDS_ASSET",
                from_key=f"AISystemNode:{event.aggregate_id}",
                to_key=f"AssetNode:{event.aggregate_id}",
                properties={},
                event_id=event.event_id,
            )
        if isinstance(event, AIComplianceMappingRecorded):
            await self._graph.upsert_edge(
                tenant_id=tenant,
                edge_type="MAPPED_TO_CONTROL",
                from_key=f"AISystemNode:{event.ai_system_asset_id}",
                to_key=(f"ComplianceControlNode:{event.framework_id}:{event.control_id}"),
                properties={"control_status": event.control_status},
                event_id=event.event_id,
            )
