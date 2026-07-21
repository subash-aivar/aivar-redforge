"""Export services for Phase 5 executive / reporting APIs."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Protocol

from ai_posture.application._auth import require_at_least
from ai_posture.domain.value_objects.enums import AIPostureRole

if TYPE_CHECKING:
    from ai_posture.application.queries.report_query_handlers import ReportQueryHandler


class _HasActorRoles(Protocol):
    actor_roles: tuple[str, ...]


class ReportExportService:
    def __init__(self, queries: ReportQueryHandler) -> None:
        self._queries = queries

    async def export_json(self, report_name: str, query: _HasActorRoles) -> str:
        require_at_least(query.actor_roles, AIPostureRole.READER)
        payload = await self._dispatch(report_name, query)
        return json.dumps(payload, default=str, indent=2, sort_keys=True)

    async def _dispatch(self, report_name: str, query: _HasActorRoles) -> dict[str, Any]:
        if report_name == "inventory":
            return await self._queries.inventory(query)  # type: ignore[arg-type]
        if report_name == "risk-register":
            return await self._queries.risk_register(query)  # type: ignore[arg-type]
        if report_name == "shadow-ai-discovery":
            return await self._queries.shadow_discovery(query)  # type: ignore[arg-type]
        if report_name == "compliance-posture":
            return await self._queries.compliance_posture(query)  # type: ignore[arg-type]
        if report_name == "supply-chain-integrity":
            return await self._queries.supply_chain(query)  # type: ignore[arg-type]
        raise ValueError(f"Unknown report: {report_name}")
