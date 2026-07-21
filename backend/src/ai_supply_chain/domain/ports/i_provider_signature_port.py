"""IProviderSignaturePort — Tier 2 provider attestation verification."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_supply_chain.domain.value_objects.supply_chain_vos import SignatureChainRef


class IProviderSignaturePort(ABC):
    @abstractmethod
    async def verify_provider_signature(
        self, signature_chain: SignatureChainRef, declared_checksum: str
    ) -> bool: ...
