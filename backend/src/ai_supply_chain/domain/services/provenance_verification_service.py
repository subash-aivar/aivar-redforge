"""ProvenanceVerificationService — two-tier deterministic verification."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_supply_chain.domain.exceptions.domain_exceptions import (
    VerificationBudgetExhausted,
)
from ai_supply_chain.domain.policies.verification_tier_policy import VerificationTierPolicy
from ai_supply_chain.domain.value_objects.enums import (
    ChecksumAlgorithm,
    VerificationMethod,
)
from ai_supply_chain.domain.value_objects.supply_chain_vos import CurrentChecksum

if TYPE_CHECKING:
    from datetime import datetime

    from ai_supply_chain.domain.aggregates.model_provenance import ModelProvenance
    from ai_supply_chain.domain.ports.i_artifact_hash_port import IArtifactHashPort
    from ai_supply_chain.domain.ports.i_provider_signature_port import (
        IProviderSignaturePort,
    )
    from ai_supply_chain.domain.repositories.i_tenant_verification_settings_repository import (
        TenantVerificationSettings,
    )
    from ai_supply_chain.domain.value_objects.identifiers import TenantId
    from ai_supply_chain.domain.value_objects.supply_chain_vos import ArtifactDescriptor


class ProvenanceVerificationService:
    """Pure orchestration of verification against ports — full recompute on every attempt."""

    def __init__(
        self,
        hash_port: IArtifactHashPort,
        signature_port: IProviderSignaturePort,
        policy: VerificationTierPolicy | None = None,
    ) -> None:
        self._hash = hash_port
        self._signature = signature_port
        self._policy = policy or VerificationTierPolicy()

    async def verify(
        self,
        provenance: ModelProvenance,
        tenant_id: TenantId,
        artifact: ArtifactDescriptor,
        settings: TenantVerificationSettings,
        now: datetime,
    ) -> ModelProvenance:
        method = self._policy.select_method(artifact.size_bytes, settings.size_threshold_bytes)
        if method == VerificationMethod.INDEPENDENT_HASH:
            if (
                settings.egress_bytes_used + artifact.size_bytes
                > settings.monthly_egress_budget_bytes
            ):
                provenance.pause_for_budget(tenant_id)
                raise VerificationBudgetExhausted(str(tenant_id))
            try:
                computed = await self._hash.compute_hash(
                    artifact.retrieval_uri, ChecksumAlgorithm.SHA256
                )
            except Exception as exc:
                provenance.mark_verification_failed(tenant_id, now, str(exc))
                return provenance
            settings.egress_bytes_used += artifact.size_bytes
            expected = artifact.provider_reported_checksum
            provenance.mark_verified(
                tenant_id,
                computed,
                method,
                now,
                expected_checksum=expected,
            )
            return provenance

        # Tier 2 — ProviderAttestation
        if artifact.signature_chain is None:
            provenance.mark_verification_failed(
                tenant_id, now, "missing SignatureChainRef for Tier 2"
            )
            return provenance
        try:
            ok = await self._signature.verify_provider_signature(
                artifact.signature_chain,
                artifact.provider_reported_checksum or "",
            )
        except Exception as exc:
            provenance.mark_verification_failed(tenant_id, now, str(exc))
            return provenance
        if not ok:
            fake = CurrentChecksum(
                ChecksumAlgorithm.PROVIDER_SIGNATURE,
                artifact.provider_reported_checksum or "invalid",
            )
            provenance.mark_mismatched(
                tenant_id,
                fake,
                method,
                now,
                expected="valid-provider-signature",
            )
            return provenance
        note = self._policy.build_trust_note(
            provider=artifact.signature_chain.provider,
            size_bytes=artifact.size_bytes,
            threshold_bytes=settings.size_threshold_bytes,
            signing_key_fingerprint=artifact.signature_chain.signing_key_fingerprint,
        )
        attested = CurrentChecksum(
            ChecksumAlgorithm.PROVIDER_SIGNATURE,
            artifact.provider_reported_checksum or artifact.signature_chain.signing_key_fingerprint,
        )
        provenance.mark_verified(
            tenant_id,
            attested,
            method,
            now,
            trust_delegation_note=note,
            signature_chain_ref=artifact.signature_chain,
        )
        return provenance
