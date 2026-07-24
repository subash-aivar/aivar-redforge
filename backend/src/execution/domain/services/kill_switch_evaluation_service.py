"""KillSwitchEvaluationService — fail-safe at domain layer (ADR-M29-004 / Hardening §1)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from execution.domain.ports.i_kill_switch_store import KillSwitchStoreUnavailable
from execution.domain.value_objects.enums import KillSwitchArmedState, KillSwitchScope

if TYPE_CHECKING:
    from uuid import UUID

    from execution.domain.ports.i_kill_switch_store import IKillSwitchStore
    from execution.domain.value_objects.identifiers import (
        EngagementId,
        OperationId,
        TenantId,
    )

logger = logging.getLogger(__name__)


class KillSwitchEvaluationService:
    """
    Evaluates kill switch state for authorization.

    Order: platform-wide → engagement → operation.
    ANY read error/timeout/unavailable → Triggered (fail-safe).
    Missing key → Armed (not yet triggered).
    """

    def __init__(self, store: IKillSwitchStore) -> None:
        self._store = store

    async def evaluate(
        self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        operation_id: OperationId | None = None,
    ) -> KillSwitchArmedState:
        platform = await self._safe_get(
            tenant_id, KillSwitchScope.PLATFORM_WIDE, tenant_id.value.to_uuid()
        )
        if platform == KillSwitchArmedState.TRIGGERED:
            return KillSwitchArmedState.TRIGGERED

        engagement = await self._safe_get(
            tenant_id, KillSwitchScope.ENGAGEMENT, engagement_id.value
        )
        if engagement == KillSwitchArmedState.TRIGGERED:
            return KillSwitchArmedState.TRIGGERED

        if operation_id is not None:
            operation = await self._safe_get(
                tenant_id, KillSwitchScope.OPERATION, operation_id.value
            )
            if operation == KillSwitchArmedState.TRIGGERED:
                return KillSwitchArmedState.TRIGGERED

        # Released is not Armed — treat non-Armed as blocking for safety.
        for state in (platform, engagement):
            if state is not None and state != KillSwitchArmedState.ARMED:
                return KillSwitchArmedState.TRIGGERED
        if operation_id is not None:
            # re-read not needed; already checked Triggered above
            pass
        return KillSwitchArmedState.ARMED

    async def _safe_get(
        self,
        tenant_id: TenantId,
        scope: KillSwitchScope,
        scope_ref: UUID,
    ) -> KillSwitchArmedState | None:
        try:
            return await self._store.get_state(tenant_id, scope, scope_ref)
        except KillSwitchStoreUnavailable:
            logger.warning(
                "kill_switch_store_unavailable fail_safe_triggered scope=%s ref=%s",
                scope.value,
                scope_ref,
            )
            return KillSwitchArmedState.TRIGGERED
        except Exception:
            logger.exception(
                "kill_switch_store_error fail_safe_triggered scope=%s ref=%s",
                scope.value,
                scope_ref,
            )
            return KillSwitchArmedState.TRIGGERED
