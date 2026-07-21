from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class RecordModelProvenanceCommand:
    tenant_id: UUID
    asset_id: UUID
    model_origin: str
    artifact_size_bytes: int
    registry_provider: str = ""
    registry_id: str = ""
    training_data_description: str = ""
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VerifyModelProvenanceCommand:
    tenant_id: UUID
    provenance_id: UUID
    retrieval_uri: str
    provider_reported_checksum: str | None = None
    signature_provider: str | None = None
    signature_location: str | None = None
    signing_key_fingerprint: str | None = None
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ManualResetVerificationCommand:
    tenant_id: UUID
    provenance_id: UUID
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BuildMBOMCommand:
    tenant_id: UUID
    provenance_id: UUID
    components: tuple[dict[str, str], ...] = ()
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RunDiscoveryScanCommand:
    tenant_id: UUID
    sources: tuple[str, ...] = ()
    cloud_accounts: tuple[str, ...] = ()
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SetVerificationThresholdCommand:
    tenant_id: UUID
    size_threshold_bytes: int
    actor_roles: tuple[str, ...] = ()
