"""Phase 5 ACL adapters — compliance, provenance, agent, discovery facts."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_posture.domain.ports.i_agent_deviation_stats_port import IAgentDeviationStatsPort
from ai_posture.domain.ports.i_compliance_query_port import IComplianceQueryPort
from ai_posture.domain.ports.i_discovery_scan_facts_port import IDiscoveryScanFactsPort
from ai_posture.domain.ports.i_provenance_integrity_query_port import (
    IProvenanceIntegrityQueryPort,
)
from ai_posture.domain.value_objects.compliance_vos import (
    AIComplianceFrameworkRef,
    ApplicableControl,
)
from ai_posture.domain.value_objects.enums import (
    AISystemKind,
    ComplianceFrameworkId,
    DataSensitivityClassification,
)

if TYPE_CHECKING:
    from uuid import UUID

    from ai_posture.domain.value_objects.identifiers import TenantId


_LOCAL_CONTROLS: dict[ComplianceFrameworkId, list[tuple[str, str, bool]]] = {
    ComplianceFrameworkId.EU_AI_ACT: [
        ("Art9_RiskManagement", "EU AI Act Art. 9 Risk Management", True),
        ("Art15_AccuracyRobustness", "EU AI Act Art. 15 Accuracy & Robustness", False),
        ("Art13_Transparency", "EU AI Act Art. 13 Transparency", False),
        ("SupplyChainIntegrity", "EU AI Act Supply Chain Integrity", False),
        ("AgentGovernance", "EU AI Act Agent Governance Controls", False),
    ],
    ComplianceFrameworkId.NIST_AI_RMF: [
        ("GOVERN_1", "NIST AI RMF GOVERN 1", True),
        ("MAP_1", "NIST AI RMF MAP 1 Threat Mapping", False),
        ("MEASURE_2", "NIST AI RMF MEASURE 2 Provenance", False),
        ("MANAGE_Agent", "NIST AI RMF Agent Oversight", False),
    ],
    ComplianceFrameworkId.ISO_42001: [
        ("Clause5_Leadership", "ISO 42001 Clause 5 Leadership", True),
        ("Clause8_Operations", "ISO 42001 Clause 8 Operations", False),
        ("Clause6_Risk", "ISO 42001 Clause 6 Risk", False),
    ],
}


class LocalComplianceCatalogAdapter(IComplianceQueryPort):
    """Production Phase 5 compliance catalog (local M24 classification fallback).

    Intended default until a live M24 catalog adapter is injected by ops.
    """

    async def resolve_applicable_controls(
        self,
        framework_id: ComplianceFrameworkId,
        ai_system_kind: AISystemKind,
        data_sensitivity: DataSensitivityClassification,
        tenant_id: TenantId,
    ) -> list[ApplicableControl]:
        del data_sensitivity, tenant_id
        rows = _LOCAL_CONTROLS.get(framework_id, [])
        result: list[ApplicableControl] = []
        for control_id, title, attestation in rows:
            if "Agent" in control_id and ai_system_kind != AISystemKind.AI_AGENT:
                continue
            result.append(
                ApplicableControl(
                    AIComplianceFrameworkRef(framework_id, control_id, title),
                    requires_human_attestation=attestation,
                )
            )
        return result


# Back-compat alias for tests that still construct the Phase 5 catalog by the stub name.
StubComplianceQueryAdapter = LocalComplianceCatalogAdapter


class StubProvenanceIntegrityAdapter(IProvenanceIntegrityQueryPort):
    def __init__(self) -> None:
        self.by_asset: dict[tuple[str, str], str] = {}
        self.rows: dict[str, list[dict[str, str]]] = {}

    def seed(
        self,
        tenant_id: UUID,
        asset_id: UUID,
        status: str,
        *,
        provenance_id: str = "",
        verification_method: str = "IndependentHash",
        trust_delegation_note: str = "",
    ) -> None:
        self.by_asset[(str(tenant_id), str(asset_id))] = status
        self.rows.setdefault(str(tenant_id), []).append(
            {
                "event_id": f"prov:{asset_id}:{status}",
                "asset_id": str(asset_id),
                "provenance_id": provenance_id or str(asset_id),
                "integrity_status": status,
                "verification_method": verification_method,
                "trust_delegation_note": trust_delegation_note,
            }
        )

    async def get_integrity_status(self, tenant_id: TenantId, asset_id: UUID) -> str | None:
        return self.by_asset.get((str(tenant_id), str(asset_id)))

    async def list_integrity_rows(self, tenant_id: TenantId) -> list[dict[str, str]]:
        return list(self.rows.get(str(tenant_id), []))


class StubAgentDeviationStatsAdapter(IAgentDeviationStatsPort):
    def __init__(self) -> None:
        self.counts: dict[tuple[str, str], int] = {}
        self.envelopes: set[tuple[str, str]] = set()
        self.deviations: dict[str, list[dict[str, str]]] = {}
        self.audits: dict[tuple[str, str], list[dict[str, str]]] = {}

    def seed_envelope(self, tenant_id: UUID, asset_id: UUID) -> None:
        self.envelopes.add((str(tenant_id), str(asset_id)))

    def seed_deviation(
        self,
        tenant_id: UUID,
        *,
        asset_id: UUID,
        deviation_id: str,
        deviation_type: str,
        severity: str,
        review_state: str = "Unreviewed",
    ) -> None:
        key = (str(tenant_id), str(asset_id))
        self.counts[key] = self.counts.get(key, 0) + 1
        self.deviations.setdefault(str(tenant_id), []).append(
            {
                "event_id": f"dev:{deviation_id}",
                "deviation_id": deviation_id,
                "asset_id": str(asset_id),
                "deviation_type": deviation_type,
                "severity": severity,
                "review_state": review_state,
                "detected_at": "2026-07-21T12:00:00+00:00",
            }
        )

    def seed_approval_history(
        self, tenant_id: UUID, envelope_id: UUID, history: list[dict[str, str]]
    ) -> None:
        self.audits[(str(tenant_id), str(envelope_id))] = list(history)

    async def recent_deviation_count(
        self, tenant_id: TenantId, asset_id: UUID, *, limit: int = 100
    ) -> int:
        return min(self.counts.get((str(tenant_id), str(asset_id)), 0), limit)

    async def list_deviation_summaries(self, tenant_id: TenantId) -> list[dict[str, str]]:
        return list(self.deviations.get(str(tenant_id), []))

    async def has_active_envelope(self, tenant_id: TenantId, asset_id: UUID) -> bool:
        return (str(tenant_id), str(asset_id)) in self.envelopes

    async def human_approval_history(
        self, tenant_id: TenantId, envelope_id: UUID
    ) -> list[dict[str, str]]:
        return list(self.audits.get((str(tenant_id), str(envelope_id)), []))


class StubDiscoveryScanFactsAdapter(IDiscoveryScanFactsPort):
    def __init__(self) -> None:
        self.scans: dict[str, dict[str, object]] = {}
        self.sources: dict[str, list[str]] = {}

    def seed(
        self,
        tenant_id: UUID,
        *,
        sources: list[str],
        partial: bool = False,
        failed_partitions: list[str] | None = None,
        ended_at: str = "2026-07-21T12:00:00+00:00",
        scan_run_id: str = "scan-1",
    ) -> None:
        tid = str(tenant_id)
        self.sources[tid] = list(sources)
        self.scans[tid] = {
            "event_id": f"scan:{scan_run_id}",
            "scan_run_id": scan_run_id,
            "sources": list(sources),
            "ended_at": ended_at,
            "partial": partial,
            "failed_partitions": list(failed_partitions or []),
            "coverage_scope": "configured_sources_only",
        }

    async def latest_scan_summary(self, tenant_id: TenantId) -> dict[str, object] | None:
        return self.scans.get(str(tenant_id))

    async def configured_sources(self, tenant_id: TenantId) -> list[str]:
        return list(self.sources.get(str(tenant_id), []))
