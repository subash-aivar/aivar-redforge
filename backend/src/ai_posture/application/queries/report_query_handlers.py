"""Phase 5 report / dashboard query handlers."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ai_posture.application._auth import require_at_least
from ai_posture.application.exceptions import ApplicationNotFoundError
from ai_posture.domain.value_objects.enums import AIPostureRole

if TYPE_CHECKING:
    from ai_posture.application.projections.read_model_store import IReadModelStore
    from ai_posture.application.queries.report_queries import (
        GetAgentDeviationReportQuery,
        GetCompliancePostureQuery,
        GetEnvelopeApprovalAuditQuery,
        GetInventoryDashboardQuery,
        GetRiskRegisterQuery,
        GetShadowAIDiscoveryReportQuery,
        GetSupplyChainIntegrityQuery,
    )


class ReportQueryHandler:
    def __init__(self, store: IReadModelStore) -> None:
        self._store = store

    async def inventory(self, query: GetInventoryDashboardQuery) -> dict[str, Any]:
        require_at_least(query.actor_roles, AIPostureRole.READER)
        view = await self._store.load_inventory(str(query.tenant_id))
        if view is None:
            raise ApplicationNotFoundError("AIAssetInventoryDashboard", str(query.tenant_id))
        payload = asdict(view)
        return payload

    async def risk_register(self, query: GetRiskRegisterQuery) -> dict[str, Any]:
        require_at_least(query.actor_roles, AIPostureRole.READER)
        view = await self._store.load_risk_register(str(query.tenant_id))
        if view is None:
            raise ApplicationNotFoundError("AIRiskRegister", str(query.tenant_id))
        now = datetime.now(UTC)
        # Surface staleness on trend + entries when computed_at older than 24h
        for entry in view.entries:
            computed = datetime.fromisoformat(entry["computed_at"])
            entry["is_stale"] = (now - computed).total_seconds() > 24 * 3600
            entry.setdefault("score_input_version", "unknown")
        versions = {t.get("score_input_version") for t in view.trend}
        payload = asdict(view)
        if len(versions) > 1:
            payload["score_input_version_warning"] = (
                "Multiple ScoreInputVersion values present in trend window"
            )
        return payload

    async def shadow_discovery(self, query: GetShadowAIDiscoveryReportQuery) -> dict[str, Any]:
        require_at_least(query.actor_roles, AIPostureRole.READER)
        view = await self._store.load_shadow_report(str(query.tenant_id))
        if view is None:
            raise ApplicationNotFoundError("ShadowAIDiscoveryReport", str(query.tenant_id))
        payload = asdict(view)
        if not payload.get("scope_of_report"):
            payload["scope_of_report"] = {
                "sources": [],
                "last_successful_scan_at": None,
                "coverage_scope": "unknown",
            }
        return payload

    async def compliance_posture(self, query: GetCompliancePostureQuery) -> dict[str, Any]:
        require_at_least(query.actor_roles, AIPostureRole.READER)
        view = await self._store.load_compliance_posture(str(query.tenant_id), query.framework_id)
        if view is None:
            raise ApplicationNotFoundError(
                "AICompliancePostureReport", f"{query.tenant_id}:{query.framework_id}"
            )
        return asdict(view)

    async def supply_chain(self, query: GetSupplyChainIntegrityQuery) -> dict[str, Any]:
        require_at_least(query.actor_roles, AIPostureRole.READER)
        view = await self._store.load_supply_chain(str(query.tenant_id))
        if view is None:
            raise ApplicationNotFoundError("AISupplyChainIntegrityReport", str(query.tenant_id))
        return asdict(view)

    async def agent_deviations(self, query: GetAgentDeviationReportQuery) -> dict[str, Any]:
        require_at_least(query.actor_roles, AIPostureRole.READER)
        view = await self._store.load_deviation_report(str(query.tenant_id))
        if view is None:
            raise ApplicationNotFoundError("AIAgentDeviationReport", str(query.tenant_id))
        return asdict(view)

    async def approval_audit(self, query: GetEnvelopeApprovalAuditQuery) -> dict[str, Any]:
        require_at_least(query.actor_roles, AIPostureRole.READER)
        view = await self._store.load_approval_audit(str(query.tenant_id), str(query.envelope_id))
        if view is None:
            raise ApplicationNotFoundError("EnvelopeHumanApprovalAudit", str(query.envelope_id))
        return asdict(view)
