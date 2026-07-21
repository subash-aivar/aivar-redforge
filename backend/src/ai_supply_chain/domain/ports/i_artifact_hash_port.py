"""IArtifactHashPort — independent streaming hash computation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_supply_chain.domain.value_objects.enums import ChecksumAlgorithm
    from ai_supply_chain.domain.value_objects.supply_chain_vos import CurrentChecksum


class IArtifactHashPort(ABC):
    @abstractmethod
    async def compute_hash(
        self, retrieval_uri: str, algorithm: ChecksumAlgorithm
    ) -> CurrentChecksum:
        """Stream artifact bytes and compute independent hash. Never trusts provider metadata."""
        ...
