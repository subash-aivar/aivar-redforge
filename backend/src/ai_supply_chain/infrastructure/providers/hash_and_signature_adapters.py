"""Concrete hash and signature adapters — deterministic, streaming-ready."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from ai_supply_chain.domain.ports.i_artifact_hash_port import IArtifactHashPort
from ai_supply_chain.domain.ports.i_provider_signature_port import IProviderSignaturePort
from ai_supply_chain.domain.value_objects.enums import ChecksumAlgorithm
from ai_supply_chain.domain.value_objects.supply_chain_vos import CurrentChecksum

if TYPE_CHECKING:
    from ai_supply_chain.domain.value_objects.supply_chain_vos import SignatureChainRef


class StreamingArtifactHashAdapter(IArtifactHashPort):
    """Computes independent hash from artifact store keyed by retrieval_uri.

    Production wires an object-storage streamer; this adapter uses an injectable
    byte store so verification always recomputes from content (no metadata shortcut).
    """

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}
        self._fail_uris: set[str] = set()
        self.compute_count = 0

    def put_artifact(self, uri: str, content: bytes) -> None:
        self._store[uri] = content

    def fail_uri(self, uri: str) -> None:
        self._fail_uris.add(uri)

    async def compute_hash(
        self, retrieval_uri: str, algorithm: ChecksumAlgorithm
    ) -> CurrentChecksum:
        self.compute_count += 1
        if retrieval_uri in self._fail_uris:
            raise RuntimeError(f"artifact retrieval failed: {retrieval_uri}")
        content = self._store.get(retrieval_uri)
        if content is None:
            raise RuntimeError(f"artifact not found: {retrieval_uri}")
        if algorithm == ChecksumAlgorithm.SHA512:
            digest = hashlib.sha512(content).hexdigest()
        else:
            digest = hashlib.sha256(content).hexdigest()
        return CurrentChecksum(algorithm, digest)


class ProviderSignatureVerificationAdapter(IProviderSignaturePort):
    def __init__(self) -> None:
        self._valid_fingerprints: set[str] = set()
        self._unreachable: set[str] = set()

    def trust(self, fingerprint: str) -> None:
        self._valid_fingerprints.add(fingerprint)

    def mark_unreachable(self, fingerprint: str) -> None:
        self._unreachable.add(fingerprint)

    async def verify_provider_signature(
        self, signature_chain: SignatureChainRef, declared_checksum: str
    ) -> bool:
        if signature_chain.signing_key_fingerprint in self._unreachable:
            raise RuntimeError("provider signature endpoint unreachable")
        return signature_chain.signing_key_fingerprint in self._valid_fingerprints
