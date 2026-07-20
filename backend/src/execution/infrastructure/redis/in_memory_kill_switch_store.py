"""In-memory kill switch store for unit tests (can simulate unavailability)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from execution.domain.ports.i_kill_switch_store import (
    IKillSwitchStore,
    KillSwitchStoreUnavailable,
)

if TYPE_CHECKING:
    from uuid import UUID

    from execution.domain.aggregates.kill_switch_state import KillSwitchState
    from execution.domain.value_objects.enums import KillSwitchArmedState, KillSwitchScope
    from execution.domain.value_objects.identifiers import TenantId


class InMemoryKillSwitchStore(IKillSwitchStore):
    def __init__(self, *, unavailable: bool = False) -> None:
        self._states: dict[tuple[str, str, str], KillSwitchArmedState] = {}
        self.unavailable = unavailable

    def simulate_unavailability(self, unavailable: bool = True) -> None:
        self.unavailable = unavailable

    def _key(
        self, tenant_id: TenantId, scope: KillSwitchScope, scope_ref: UUID
    ) -> tuple[str, str, str]:
        return (str(tenant_id), scope.value, str(scope_ref))

    async def get_state(
        self,
        tenant_id: TenantId,
        scope: KillSwitchScope,
        scope_ref: UUID,
    ) -> KillSwitchArmedState | None:
        if self.unavailable:
            raise KillSwitchStoreUnavailable("kill switch store unavailable")
        return self._states.get(self._key(tenant_id, scope, scope_ref))

    async def set_state(self, kill_switch: KillSwitchState) -> None:
        if self.unavailable:
            raise KillSwitchStoreUnavailable("kill switch store unavailable")
        self._states[
            self._key(kill_switch.tenant_id, kill_switch.scope, kill_switch.scope_ref)
        ] = kill_switch.armed_state
