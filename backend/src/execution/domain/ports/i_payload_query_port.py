"""IPayloadQueryPort — pre-dispatch payload approval and hash checks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class PayloadDispatchCheck:
    """Result of verifying a payload is safe to dispatch."""

    approved: bool
    hash_ok: bool
    failure_reason: str | None = None


class IPayloadQueryPort(ABC):
    @abstractmethod
    async def verify_for_dispatch(
        self,
        tenant_id: UUID,
        payload_id: UUID,
        expected_hash: str | None = None,
    ) -> PayloadDispatchCheck:
        """Verify payload is Approved and optionally hash-matches expected_hash."""
        ...
