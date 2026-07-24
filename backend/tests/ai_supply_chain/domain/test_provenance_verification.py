from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from ai_supply_chain.domain.aggregates.model_provenance import ModelProvenance
from ai_supply_chain.domain.exceptions.domain_exceptions import (
    ChainEntryImmutable,
    UnknownOriginCannotVerify,
)
from ai_supply_chain.domain.repositories.i_tenant_verification_settings_repository import (
    TenantVerificationSettings,
)
from ai_supply_chain.domain.services.provenance_verification_service import (
    ProvenanceVerificationService,
)
from ai_supply_chain.domain.value_objects.enums import (
    ModelOrigin,
    ProvenanceIntegrityStatus,
    VerificationMethod,
)
from ai_supply_chain.domain.value_objects.identifiers import (
    AISystemAssetId,
    ModelProvenanceId,
    TenantId,
)
from ai_supply_chain.domain.value_objects.supply_chain_vos import (
    ArtifactDescriptor,
    SignatureChainRef,
)
from ai_supply_chain.infrastructure.providers.hash_and_signature_adapters import (
    ProviderSignatureVerificationAdapter,
    StreamingArtifactHashAdapter,
)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def tenant() -> TenantId:
    return TenantId.generate()


def _prov(
    tenant: TenantId,
    now: datetime,
    *,
    origin: ModelOrigin = ModelOrigin.OPEN_SOURCE_REGISTRY,
    size: int = 1024,
) -> ModelProvenance:
    return ModelProvenance.record(
        ModelProvenanceId.generate(),
        tenant,
        AISystemAssetId(uuid4()),
        origin,
        None,
        None,
        size,
        now,
    )


@pytest.mark.asyncio
async def test_tier1_independent_hash_verified(tenant: TenantId, now: datetime) -> None:
    hash_port = StreamingArtifactHashAdapter()
    content = b"model-bytes"
    hash_port.put_artifact("s3://m/a.bin", content)
    import hashlib

    digest = hashlib.sha256(content).hexdigest()
    svc = ProvenanceVerificationService(hash_port, ProviderSignatureVerificationAdapter())
    prov = _prov(tenant, now, size=len(content))
    settings = TenantVerificationSettings()
    await svc.verify(
        prov,
        tenant,
        ArtifactDescriptor(len(content), "s3://m/a.bin", digest),
        settings,
        now,
    )
    assert prov.integrity_status == ProvenanceIntegrityStatus.VERIFIED
    assert any(
        e.verification_method == VerificationMethod.INDEPENDENT_HASH for e in prov.chain_entries
    )
    assert hash_port.compute_count == 1


@pytest.mark.asyncio
async def test_verified_failed_retry_recomputes_full_hash(tenant: TenantId, now: datetime) -> None:
    hash_port = StreamingArtifactHashAdapter()
    content = b"clean-model"
    uri = "s3://m/retry.bin"
    hash_port.put_artifact(uri, content)
    import hashlib

    digest = hashlib.sha256(content).hexdigest()
    svc = ProvenanceVerificationService(hash_port, ProviderSignatureVerificationAdapter())
    prov = _prov(tenant, now, size=len(content))
    settings = TenantVerificationSettings()
    await svc.verify(prov, tenant, ArtifactDescriptor(len(content), uri, digest), settings, now)
    assert prov.integrity_status == ProvenanceIntegrityStatus.VERIFIED
    hash_port.fail_uri(uri)
    await svc.verify(prov, tenant, ArtifactDescriptor(len(content), uri, digest), settings, now)
    assert prov.integrity_status.value == ProvenanceIntegrityStatus.VERIFICATION_FAILED.value
    hash_port._fail_uris.clear()
    await svc.verify(prov, tenant, ArtifactDescriptor(len(content), uri, digest), settings, now)
    assert prov.integrity_status.value == ProvenanceIntegrityStatus.VERIFIED.value
    assert hash_port.compute_count >= 3  # no shortcut


@pytest.mark.asyncio
async def test_verified_failed_retry_mismatched(tenant: TenantId, now: datetime) -> None:
    hash_port = StreamingArtifactHashAdapter()
    uri = "s3://m/tamper.bin"
    hash_port.put_artifact(uri, b"v1")
    import hashlib

    d1 = hashlib.sha256(b"v1").hexdigest()
    svc = ProvenanceVerificationService(hash_port, ProviderSignatureVerificationAdapter())
    prov = _prov(tenant, now, size=2)
    settings = TenantVerificationSettings()
    await svc.verify(prov, tenant, ArtifactDescriptor(2, uri, d1), settings, now)
    hash_port.fail_uri(uri)
    await svc.verify(prov, tenant, ArtifactDescriptor(2, uri, d1), settings, now)
    hash_port._fail_uris.clear()
    hash_port.put_artifact(uri, b"v2-tampered")
    await svc.verify(prov, tenant, ArtifactDescriptor(11, uri, d1), settings, now)
    assert prov.integrity_status == ProvenanceIntegrityStatus.MISMATCHED


@pytest.mark.asyncio
async def test_tier2_provider_attestation(tenant: TenantId, now: datetime) -> None:
    hash_port = StreamingArtifactHashAdapter()
    sig = ProviderSignatureVerificationAdapter()
    sig.trust("fp-1")
    svc = ProvenanceVerificationService(hash_port, sig)
    size = 11 * 1024 * 1024 * 1024
    prov = _prov(tenant, now, size=size)
    settings = TenantVerificationSettings()
    await svc.verify(
        prov,
        tenant,
        ArtifactDescriptor(
            size,
            "s3://huge",
            "attested",
            SignatureChainRef("huggingface", "model.sha256", "fp-1"),
        ),
        settings,
        now,
    )
    assert prov.integrity_status == ProvenanceIntegrityStatus.VERIFIED
    assert any(
        e.verification_method == VerificationMethod.PROVIDER_ATTESTATION
        and "trust-delegated" in e.trust_delegation_note
        for e in prov.chain_entries
        if e.verification_method
    )
    assert hash_port.compute_count == 0


def test_unknown_origin_cannot_verify(tenant: TenantId, now: datetime) -> None:
    prov = _prov(tenant, now, origin=ModelOrigin.UNKNOWN)
    from ai_supply_chain.domain.value_objects.enums import ChecksumAlgorithm
    from ai_supply_chain.domain.value_objects.supply_chain_vos import CurrentChecksum

    with pytest.raises(UnknownOriginCannotVerify):
        prov.mark_verified(
            tenant,
            CurrentChecksum(ChecksumAlgorithm.SHA256, "abc"),
            VerificationMethod.INDEPENDENT_HASH,
            now,
        )


def test_chain_entry_immutable(tenant: TenantId, now: datetime) -> None:
    prov = _prov(tenant, now)
    entry = prov.chain_entries[0]
    with pytest.raises(ChainEntryImmutable):
        entry.mutate()
