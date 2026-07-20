"""Redis-backed kill switch store — short timeout; write-through from PG."""

from __future__ import annotations

from typing import TYPE_CHECKING

from execution.domain.ports.i_kill_switch_store import (
    IKillSwitchStore,
    KillSwitchStoreUnavailable,
)
from execution.domain.value_objects.enums import KillSwitchArmedState

if TYPE_CHECKING:
    from uuid import UUID

    from redis.asyncio import Redis

    from execution.domain.aggregates.kill_switch_state import KillSwitchState
    from execution.domain.value_objects.enums import KillSwitchScope
    from execution.domain.value_objects.identifiers import TenantId

# Hardening §1: explicit short timeout for kill switch reads (< 2ms conceptual;
# use a tight socket timeout so unavailable Redis fails fast).
_DEFAULT_SOCKET_TIMEOUT_S = 0.05


class RedisKillSwitchStore(IKillSwitchStore):
    def __init__(self, redis: Redis, *, socket_timeout: float = _DEFAULT_SOCKET_TIMEOUT_S) -> None:
        self._redis = redis
        self._socket_timeout = socket_timeout

    @staticmethod
    def _key(tenant_id: TenantId, scope: KillSwitchScope, scope_ref: UUID) -> str:
        return f"{tenant_id}:killswitch:{scope.value}:{scope_ref}"

    async def get_state(
        self,
        tenant_id: TenantId,
        scope: KillSwitchScope,
        scope_ref: UUID,
    ) -> KillSwitchArmedState | None:
        try:
            raw = await self._redis.get(self._key(tenant_id, scope, scope_ref))
        except Exception as exc:
            raise KillSwitchStoreUnavailable(str(exc)) from exc
        if raw is None:
            return None
        text = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        try:
            return KillSwitchArmedState(text)
        except ValueError as exc:
            raise KillSwitchStoreUnavailable(f"invalid kill switch value: {text}") from exc

    async def set_state(self, kill_switch: KillSwitchState) -> None:
        key = self._key(
            kill_switch.tenant_id, kill_switch.scope, kill_switch.scope_ref
        )
        try:
            await self._redis.set(key, kill_switch.armed_state.value)
        except Exception as exc:
            raise KillSwitchStoreUnavailable(str(exc)) from exc
