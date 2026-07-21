"""Two-tier provenance verification policy (Decision 5)."""

from __future__ import annotations

from ai_supply_chain.domain.exceptions.domain_exceptions import SizeThresholdTooLow
from ai_supply_chain.domain.value_objects.enums import VerificationMethod
from ai_supply_chain.domain.value_objects.supply_chain_vos import (
    MIN_SIZE_THRESHOLD_BYTES,
    select_verification_method,
    trust_delegation_note,
)


class VerificationTierPolicy:
    def validate_threshold(self, threshold_bytes: int) -> None:
        if threshold_bytes < MIN_SIZE_THRESHOLD_BYTES:
            raise SizeThresholdTooLow(MIN_SIZE_THRESHOLD_BYTES)

    def select_method(self, size_bytes: int, threshold_bytes: int) -> VerificationMethod:
        self.validate_threshold(threshold_bytes)
        return select_verification_method(size_bytes, threshold_bytes=threshold_bytes)

    def build_trust_note(
        self,
        *,
        provider: str,
        size_bytes: int,
        threshold_bytes: int,
        signing_key_fingerprint: str,
    ) -> str:
        return trust_delegation_note(
            provider=provider,
            size_bytes=size_bytes,
            threshold_bytes=threshold_bytes,
            signing_key_fingerprint=signing_key_fingerprint,
        )
