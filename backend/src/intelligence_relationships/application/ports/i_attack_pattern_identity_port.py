"""IAttackPatternIdentityPort — the read-only ACL contract over attack
pattern identity, owned by the `attack_pattern_intel` bounded context.

Existence-check only; see `IIocIdentityPort`'s docstring for the
identical rationale and constraints.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class IAttackPatternIdentityPort(ABC):
    @abstractmethod
    async def exists(self, attack_pattern_id: str) -> bool:
        """True iff `attack_pattern_id` identifies a persisted attack pattern."""
        ...
