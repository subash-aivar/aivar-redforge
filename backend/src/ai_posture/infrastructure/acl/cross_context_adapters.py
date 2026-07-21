"""Phase 5 production ACL adapters — in-process reads from sibling M31 BCs.

These adapters live in ``ai_posture.infrastructure.acl`` and may import sibling
BC domain types (platform ACL rule). They are the default wiring for provenance,
agent deviation, and discovery facts when a composition root does not inject
custom ports.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_agent_governance.domain.value_objects.identifiers import (
    AgentOperationalEnvelopeId,
)
from ai_agent_governance.domain.value_objects.identifiers import (
    AISystemAssetId as AgentAssetId,
)
from ai_agent_governance.domain.value_objects.identifiers import (
    TenantId as AgentTenantId,
)
from ai_posture.domain.ports.i_agent_deviation_stats_port import IAgentDeviationStatsPort
from ai_posture.domain.ports.i_discovery_scan_facts_port import IDiscoveryScanFactsPort
from ai_posture.domain.ports.i_provenance_integrity_query_port import (
    IProvenanceIntegrityQueryPort,
)
from ai_supply_chain.domain.value_objects.identifiers import (
    AISystemAssetId as SupplyAssetId,
)
from ai_supply_chain.domain.value_objects.identifiers import (
    TenantId as SupplyTenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

    from ai_agent_governance.application.ports.i_unit_of_work import (
        IUnitOfWork as AgentUoW,
    )
    from ai_posture.domain.value_objects.identifiers import TenantId
    from ai_supply_chain.application.ports.i_unit_of_work import (
        IUnitOfWork as SupplyUoW,
    )


class InProcessProvenanceIntegrityAdapter(IProvenanceIntegrityQueryPort):
    """Reads integrity status from ``ai_supply_chain`` via its unit of work."""

    def __init__(self, uow_factory: Callable[[], SupplyUoW]) -> None:
        self._uow_factory = uow_factory

    async def get_integrity_status(self, tenant_id: TenantId, asset_id: UUID) -> str | None:
        async with self._uow_factory() as uow:
            prov = await uow.provenances.find_by_asset(
                SupplyAssetId(asset_id), SupplyTenantId(tenant_id.value)
            )
            if prov is None:
                return None
            return prov.integrity_status.value

    async def list_integrity_rows(self, tenant_id: TenantId) -> list[dict[str, str]]:
        async with self._uow_factory() as uow:
            st = SupplyTenantId(tenant_id.value)
            items = getattr(uow.provenances, "items", None)
            if not isinstance(items, dict):
                mismatched = await uow.provenances.find_mismatched(st)
                return [_provenance_row(p) for p in mismatched]
            rows: list[dict[str, str]] = []
            for prov in items.values():
                if prov.tenant_id != st:
                    continue
                rows.append(_provenance_row(prov))
            return rows


def _provenance_row(prov: object) -> dict[str, str]:
    from ai_supply_chain.domain.aggregates.model_provenance import ModelProvenance

    assert isinstance(prov, ModelProvenance)
    method = ""
    note = ""
    if prov.chain_entries:
        last = prov.chain_entries[-1]
        if last.verification_method is not None:
            method = last.verification_method.value
        note = last.trust_delegation_note or ""
    return {
        "event_id": f"prov:{prov.provenance_id}:{prov.integrity_status.value}",
        "asset_id": str(prov.ai_system_asset_id),
        "provenance_id": str(prov.provenance_id),
        "integrity_status": prov.integrity_status.value,
        "verification_method": method or "IndependentHash",
        "trust_delegation_note": note,
    }


class InProcessAgentDeviationStatsAdapter(IAgentDeviationStatsPort):
    """Reads deviation/envelope facts from ``ai_agent_governance``."""

    def __init__(self, uow_factory: Callable[[], AgentUoW]) -> None:
        self._uow_factory = uow_factory

    async def recent_deviation_count(
        self, tenant_id: TenantId, asset_id: UUID, *, limit: int = 100
    ) -> int:
        async with self._uow_factory() as uow:
            rows = await uow.deviations.find_by_asset(
                AgentAssetId(asset_id), AgentTenantId(tenant_id.value), limit
            )
            return len(rows)

    async def list_deviation_summaries(self, tenant_id: TenantId) -> list[dict[str, str]]:
        async with self._uow_factory() as uow:
            at = AgentTenantId(tenant_id.value)
            items = getattr(uow.deviations, "items", None)
            if isinstance(items, dict):
                deviations = [d for d in items.values() if d.tenant_id == at]
            else:
                deviations = await uow.deviations.find_unreviewed_by_tenant(at)
            return [
                {
                    "event_id": f"dev:{d.deviation_id}",
                    "deviation_id": str(d.deviation_id),
                    "asset_id": str(d.ai_system_asset_id),
                    "deviation_type": d.deviation_type.value,
                    "severity": d.severity.value,
                    "review_state": d.review_state.value,
                    "detected_at": d.detected_at.isoformat(),
                }
                for d in deviations
            ]

    async def has_active_envelope(self, tenant_id: TenantId, asset_id: UUID) -> bool:
        async with self._uow_factory() as uow:
            env = await uow.envelopes.find_by_asset(
                AgentAssetId(asset_id), AgentTenantId(tenant_id.value)
            )
            return env is not None

    async def human_approval_history(
        self, tenant_id: TenantId, envelope_id: UUID
    ) -> list[dict[str, str]]:
        async with self._uow_factory() as uow:
            env = await uow.envelopes.find_by_id(
                AgentOperationalEnvelopeId(envelope_id), AgentTenantId(tenant_id.value)
            )
            if env is None:
                return []
            approver = env.approved_by.approver_id if env.approved_by is not None else ""
            return [
                {
                    "envelope_id": str(env.envelope_id),
                    "category": category.value,
                    "approved_by": approver,
                    "envelope_version": str(env.envelope_version),
                }
                for category in sorted(env.requires_human_approval_for, key=lambda c: c.value)
            ]


class InProcessDiscoveryScanFactsAdapter(IDiscoveryScanFactsPort):
    """Reads discovery scan bookkeeping from ``ai_supply_chain``."""

    def __init__(self, uow_factory: Callable[[], SupplyUoW]) -> None:
        self._uow_factory = uow_factory

    async def latest_scan_summary(self, tenant_id: TenantId) -> dict[str, object] | None:
        async with self._uow_factory() as uow:
            runs = await uow.scans.find_recent(SupplyTenantId(tenant_id.value), 1)
            if not runs:
                return None
            run = runs[0]
            sources = [s.value for s in run.sources]
            return {
                "event_id": f"scan:{run.scan_run_id}",
                "scan_run_id": str(run.scan_run_id),
                "sources": sources,
                "ended_at": run.ended_at.isoformat() if run.ended_at else "",
                "partial": run.partial,
                "failed_partitions": list(run.failed_partitions),
                "coverage_scope": "configured_sources_only",
            }

    async def configured_sources(self, tenant_id: TenantId) -> list[str]:
        summary = await self.latest_scan_summary(tenant_id)
        if summary is None:
            return []
        sources = summary.get("sources", [])
        if isinstance(sources, list):
            return [str(s) for s in sources]
        return []
