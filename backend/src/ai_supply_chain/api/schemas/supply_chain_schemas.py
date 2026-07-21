from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field


class RecordProvenanceRequest(BaseModel):
    asset_id: UUID
    model_origin: str
    artifact_size_bytes: int
    registry_provider: str = ""
    registry_id: str = ""
    training_data_description: str = ""


class VerifyProvenanceRequest(BaseModel):
    retrieval_uri: str
    provider_reported_checksum: str | None = None
    signature_provider: str | None = None
    signature_location: str | None = None
    signing_key_fingerprint: str | None = None


class BuildMBOMRequest(BaseModel):
    components: list[dict[str, str]] = Field(default_factory=list)


class RunDiscoveryScanRequest(BaseModel):
    sources: list[str] = Field(default_factory=list)
    cloud_accounts: list[str] = Field(default_factory=list)


class SetThresholdRequest(BaseModel):
    size_threshold_bytes: int
