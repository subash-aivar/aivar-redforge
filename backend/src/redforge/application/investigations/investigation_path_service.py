"""Link investigations to attack paths — M22 Phase 6.

Debounced recompute on investigation evidence updates. Selects a fused
technique seed from case evidence / technique coverage hints; never
fabricates graph structure.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.application.attack_path.attack_path_service import AttackPathService
from redforge.domain.threat_intel.fusion_value_objects import (
    FusedIndicatorType,
    IndicatorLifecycle,
)
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.attack_path_repository import (
    SqlAlchemyAttackPathRepository,
)
from redforge.infrastructure.database.repositories.threat_fusion_repository import (
    SqlAlchemyFusedIndicatorRepository,
)
from redforge.infrastructure.database.repositories.threat_intel_sync_repository import (
    SqlAlchemyInvestigationPathComputeStateRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class InvestigationPathService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        attack_path_service: AttackPathService | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._attack_path_service = attack_path_service or AttackPathService(
            session_factory
        )

    async def list_linked_paths(
        self, *, organization_id: str, investigation_id: str
    ) -> list[Any]:
        async with self._session_factory() as session, session.begin():
            repo = SqlAlchemyAttackPathRepository(session)
            return await repo.list_for_investigation(
                organization_id, investigation_id, limit=20
            )

    async def maybe_recompute_for_investigation(
        self,
        *,
        organization_id: str,
        investigation_id: str,
        actor_id: str,
        force: bool = False,
    ) -> dict[str, Any]:
        """Debounced path compute linked to an investigation."""
        now = datetime.now(UTC)
        async with self._session_factory() as session, session.begin():
            debounce_repo = SqlAlchemyInvestigationPathComputeStateRepository(session)
            state = await debounce_repo.record_evidence(
                organization_id, investigation_id, now=now
            )
            if not force and not debounce_repo.may_compute(state, now=now):
                return {
                    "computed": False,
                    "reason": "debounced",
                    "pending_evidence_count": state.pending_evidence_count,
                }

            fused_repo = SqlAlchemyFusedIndicatorRepository(session)
            techniques = await fused_repo.list_by_type(
                FusedIndicatorType.TECHNIQUE,
                lifecycle=IndicatorLifecycle.ACTIVE,
                limit=50,
                offset=0,
            )
            seed = next((t for t in techniques if t.confidence is not None), None)
            if seed is None:
                return {"computed": False, "reason": "no_active_technique_seed"}

        try:
            result = await self._attack_path_service.compute(
                organization_id=organization_id,
                seed_indicator_id=seed.id,
                actor_id=actor_id,
                investigation_id=investigation_id,
            )
        except Exception as exc:
            return {
                "computed": False,
                "reason": "compute_failed",
                "error": type(exc).__name__,
            }

        async with self._session_factory() as session, session.begin():
            debounce_repo = SqlAlchemyInvestigationPathComputeStateRepository(session)
            await debounce_repo.mark_computed(
                organization_id, investigation_id, now=datetime.now(UTC)
            )
            await PostgresPlatformAuditLog(session).record(
                AuditEntry(
                    action=AuditAction.INVESTIGATION_ATTACK_PATH_LINKED,
                    actor_id=actor_id[:26],
                    resource_type="investigation",
                    resource_id=investigation_id,
                    metadata={
                        "organization_id": organization_id,
                        "attack_path_id": result.path.id,
                    },
                )
            )
        return {
            "computed": True,
            "attack_path_id": result.path.id,
            "step_count": result.path.step_count,
            "path_confidence": result.path.path_confidence.value,
        }
