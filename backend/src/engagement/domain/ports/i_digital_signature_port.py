"""IDigitalSignaturePort — approval and RoE signing."""

from __future__ import annotations

from abc import ABC, abstractmethod


class IDigitalSignaturePort(ABC):
    @abstractmethod
    def sign(self, payload: str) -> str:
        """Produce a signature for the given payload."""

    @abstractmethod
    def verify(self, payload: str, signature: str, identity: str) -> bool:
        """Verify signature for payload under identity."""
