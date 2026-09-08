"""IThreatActorIdentityPort — the read-only ACL contract over threat
actor identity, owned by the `threat_actor_intel` bounded context.

Existence-check only; see `IIocIdentityPort`'s docstring for the
identical rationale and constraints.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class IThreatActorIdentityPort(ABC):
    @abstractmethod
    async def exists(self, threat_actor_id: str) -> bool:
        """True iff `threat_actor_id` identifies a persisted threat actor."""
        ...
