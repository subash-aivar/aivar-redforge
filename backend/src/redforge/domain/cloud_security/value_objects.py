"""Value objects and closed enums for M26 Cloud Security foundation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, unique
from typing import Self
from uuid import UUID, uuid4


@unique
class CloudProviderType(StrEnum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"


@unique
class CloudProviderStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


@unique
class CloudAccountType(StrEnum):
    ROOT = "ROOT"
    MEMBER = "MEMBER"
    STANDALONE = "STANDALONE"


@unique
class SyncStatus(StrEnum):
    PENDING = "PENDING"
    SYNCING = "SYNCING"
    SYNCED = "SYNCED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class CloudProviderId:
    value: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("CloudProviderId.value must be UUID")

    @classmethod
    def generate(cls) -> Self:
        return cls(uuid4())

    @classmethod
    def from_string(cls, raw: str) -> Self:
        return cls(UUID(raw))

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CloudAccountId:
    value: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("CloudAccountId.value must be UUID")

    @classmethod
    def generate(cls) -> Self:
        return cls(uuid4())

    @classmethod
    def from_string(cls, raw: str) -> Self:
        return cls(UUID(raw))

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class OrganizationId:
    """Conformist identity from M2 — platform organization ULID string."""

    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("OrganizationId must be non-empty")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class CredentialRef:
    """Opaque pointer into credential_vault. Never contains secret material."""

    reference_id: str

    def __post_init__(self) -> None:
        if not self.reference_id or not self.reference_id.strip():
            raise ValueError("CredentialRef.reference_id is required")
        if len(self.reference_id) > 256:
            raise ValueError("CredentialRef.reference_id max 256 chars")


@dataclass(frozen=True, slots=True)
class DiscoveryConfig:
    """Provider discovery / sync configuration."""

    polling_interval_seconds: int = 3600
    region_filter: tuple[str, ...] = ()
    service_filter: tuple[str, ...] = ()
    tags_filter: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if self.polling_interval_seconds < 60:
            raise ValueError("polling_interval_seconds must be >= 60")
        if self.polling_interval_seconds > 86400 * 7:
            raise ValueError("polling_interval_seconds must be <= 7 days")
        if len(self.region_filter) > 200:
            raise ValueError("region_filter max 200 entries")
        if len(self.service_filter) > 200:
            raise ValueError("service_filter max 200 entries")
        if len(self.tags_filter) > 100:
            raise ValueError("tags_filter max 100 entries")

    def to_dict(self) -> dict[str, object]:
        return {
            "polling_interval_seconds": self.polling_interval_seconds,
            "region_filter": list(self.region_filter),
            "service_filter": list(self.service_filter),
            "tags_filter": [[k, v] for k, v in self.tags_filter],
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Self:
        tags_raw = data.get("tags_filter", [])
        tags: list[tuple[str, str]] = []
        if isinstance(tags_raw, list):
            for item in tags_raw:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    tags.append((str(item[0]), str(item[1])))
        region_raw = data.get("region_filter") or []
        service_raw = data.get("service_filter") or []
        poll_raw = data.get("polling_interval_seconds", 3600)
        return cls(
            polling_interval_seconds=int(poll_raw) if isinstance(poll_raw, (int, str)) else 3600,
            region_filter=tuple(str(x) for x in region_raw) if isinstance(region_raw, list) else (),
            service_filter=tuple(str(x) for x in service_raw)
            if isinstance(service_raw, list)
            else (),
            tags_filter=tuple(tags),
        )


@dataclass(frozen=True, slots=True)
class AccountSyncState:
    status: SyncStatus
    last_sync_started_at: datetime | None = None
    last_sync_completed_at: datetime | None = None
    last_error: str | None = None

    def __post_init__(self) -> None:
        if self.status is SyncStatus.FAILED and not self.last_error:
            raise ValueError("FAILED sync state requires last_error")
        if self.last_error is not None and len(self.last_error) > 4000:
            raise ValueError("last_error max 4000 chars")

    @classmethod
    def pending(cls) -> Self:
        return cls(status=SyncStatus.PENDING)

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "last_sync_started_at": (
                self.last_sync_started_at.isoformat() if self.last_sync_started_at else None
            ),
            "last_sync_completed_at": (
                self.last_sync_completed_at.isoformat() if self.last_sync_completed_at else None
            ),
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Self:
        started = data.get("last_sync_started_at")
        completed = data.get("last_sync_completed_at")
        return cls(
            status=SyncStatus(str(data["status"])),
            last_sync_started_at=(
                datetime.fromisoformat(str(started)) if started is not None else None
            ),
            last_sync_completed_at=(
                datetime.fromisoformat(str(completed)) if completed is not None else None
            ),
            last_error=str(data["last_error"]) if data.get("last_error") is not None else None,
        )


@dataclass(frozen=True, slots=True)
class CloudAccountMetadata:
    """Provider-agnostic account metadata envelope (never secrets)."""

    attributes: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if len(self.attributes) > 100:
            raise ValueError("CloudAccountMetadata max 100 attributes")
        for key, value in self.attributes:
            if not key or len(key) > 128:
                raise ValueError("metadata key invalid")
            if len(value) > 2048:
                raise ValueError("metadata value max 2048 chars")

    def to_dict(self) -> dict[str, str]:
        return dict(self.attributes)

    @classmethod
    def from_dict(cls, data: dict[str, str] | None) -> Self:
        if not data:
            return cls()
        return cls(attributes=tuple((str(k), str(v)) for k, v in data.items()))


# Closed enum required by CloudProviderAdapter protocol (Phase 1 interface only).
@unique
class CloudAssetType(StrEnum):
    EC2_INSTANCE = "EC2_INSTANCE"
    S3_BUCKET = "S3_BUCKET"
    RDS_INSTANCE = "RDS_INSTANCE"
    LAMBDA_FUNCTION = "LAMBDA_FUNCTION"
    VPC = "VPC"
    SUBNET = "SUBNET"
    SECURITY_GROUP = "SECURITY_GROUP"
    LOAD_BALANCER = "LOAD_BALANCER"
    EKS_CLUSTER = "EKS_CLUSTER"
    ECS_CLUSTER = "ECS_CLUSTER"
    ECR_REPOSITORY = "ECR_REPOSITORY"
    IAM_ROLE = "IAM_ROLE"
    IAM_USER = "IAM_USER"
    IAM_POLICY = "IAM_POLICY"
    KMS_KEY = "KMS_KEY"
    SECRETS_MANAGER_SECRET = "SECRETS_MANAGER_SECRET"
    ROUTE53_ZONE = "ROUTE53_ZONE"
    CLOUDFRONT_DISTRIBUTION = "CLOUDFRONT_DISTRIBUTION"
    AZURE_VM = "AZURE_VM"
    AZURE_STORAGE_ACCOUNT = "AZURE_STORAGE_ACCOUNT"
    AZURE_SQL_DATABASE = "AZURE_SQL_DATABASE"
    AZURE_VNET = "AZURE_VNET"
    AZURE_NSG = "AZURE_NSG"
    AZURE_AKS_CLUSTER = "AZURE_AKS_CLUSTER"
    AZURE_FUNCTION_APP = "AZURE_FUNCTION_APP"
    AZURE_KEYVAULT = "AZURE_KEYVAULT"
    AZURE_OPENAI_SERVICE = "AZURE_OPENAI_SERVICE"
    GCP_COMPUTE_INSTANCE = "GCP_COMPUTE_INSTANCE"
    GCP_STORAGE_BUCKET = "GCP_STORAGE_BUCKET"
    GCP_CLOUD_SQL = "GCP_CLOUD_SQL"
    GCP_VPC_NETWORK = "GCP_VPC_NETWORK"
    GCP_GKE_CLUSTER = "GCP_GKE_CLUSTER"
    GCP_CLOUD_FUNCTION = "GCP_CLOUD_FUNCTION"
    GCP_SECRET_MANAGER = "GCP_SECRET_MANAGER"
    GCP_VERTEX_AI_ENDPOINT = "GCP_VERTEX_AI_ENDPOINT"
    SAGEMAKER_ENDPOINT = "SAGEMAKER_ENDPOINT"
    BEDROCK_MODEL = "BEDROCK_MODEL"
    UNKNOWN = "UNKNOWN"
