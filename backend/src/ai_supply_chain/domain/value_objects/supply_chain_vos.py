"""Value objects for ai_supply_chain."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ai_supply_chain.domain.value_objects.enums import (
    ChecksumAlgorithm,
    DiscoverySourceType,
    MBOMComponentType,
    VerificationMethod,
)
from ai_supply_chain.domain.value_objects.identifiers import (
    AISystemAssetId,
    ModelProvenanceId,
)


@dataclass(frozen=True, slots=True)
class AISystemAssetRef:
    asset_id: AISystemAssetId


@dataclass(frozen=True, slots=True)
class ModelProvenanceRef:
    provenance_id: ModelProvenanceId


@dataclass(frozen=True, slots=True)
class SourceRegistryRef:
    provider: str
    registry_id: str


@dataclass(frozen=True, slots=True)
class TrainingDataLineageRef:
    description: str
    source_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CurrentChecksum:
    algorithm: ChecksumAlgorithm
    value: str


@dataclass(frozen=True, slots=True)
class LastVerifiedChecksum:
    algorithm: ChecksumAlgorithm
    value: str
    verified_at: datetime


@dataclass(frozen=True, slots=True)
class SignatureChainRef:
    provider: str
    signature_location: str
    signing_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class MBOMComponent:
    component_type: MBOMComponentType
    name: str
    version: str
    source: str
    checksum: str
    known_cve_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DiscoveredAIService:
    discovery_source: DiscoverySourceType
    cloud_account: str
    resource_identifier: str
    service_type: str
    region: str
    metadata: dict[str, str]


@dataclass(frozen=True, slots=True)
class ArtifactDescriptor:
    """Describes a model artifact for verification dispatch."""

    size_bytes: int
    retrieval_uri: str
    provider_reported_checksum: str | None = None
    signature_chain: SignatureChainRef | None = None


DEFAULT_SIZE_THRESHOLD_BYTES = 10 * 1024 * 1024 * 1024  # 10 GiB
MIN_SIZE_THRESHOLD_BYTES = 1 * 1024 * 1024 * 1024  # 1 GiB


def select_verification_method(
    size_bytes: int, *, threshold_bytes: int = DEFAULT_SIZE_THRESHOLD_BYTES
) -> VerificationMethod:
    if size_bytes <= threshold_bytes:
        return VerificationMethod.INDEPENDENT_HASH
    return VerificationMethod.PROVIDER_ATTESTATION


def trust_delegation_note(
    *,
    provider: str,
    size_bytes: int,
    threshold_bytes: int,
    signing_key_fingerprint: str,
) -> str:
    size_gb = size_bytes / (1024**3)
    threshold_gb = threshold_bytes / (1024**3)
    return (
        f"Verification is trust-delegated to {provider}. "
        f"Independent hash not computed due to size threshold "
        f"({size_gb:.2f} GB exceeds {threshold_gb:.2f} GB). "
        f"Provider signature verified against {signing_key_fingerprint}."
    )
