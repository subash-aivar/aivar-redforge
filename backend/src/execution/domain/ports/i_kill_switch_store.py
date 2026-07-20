"""IKillSwitchStore — Redis-primary kill switch read/write with fail visibility."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from execution.domain.aggregates.kill_switch_state import KillSwitchState
    from execution.domain.value_objects.enums import KillSwitchArmedState, KillSwitchScope
    from execution.domain.value_objects.identifiers import TenantId


class KillSwitchStoreUnavailable(Exception):
    """Raised on any read/write error or timeout — domain fail-safes to Triggered."""


class IKillSwitchStore(ABC):
    @abstractmethod
    async def get_state(
        self,
        tenant_id: TenantId,
        scope: KillSwitchScope,
        scope_ref: UUID,
    ) -> KillSwitchArmedState | None:
        """
        Return current armed state or None if no key exists (treat as Armed).

        MUST raise KillSwitchStoreUnavailable on error/timeout — never return
        a stale Armed value silently.
        """
        ...

    @abstractmethod
    async def set_state(self, kill_switch: KillSwitchState) -> None:
        """Write-through cache of kill switch state."""
        ...
