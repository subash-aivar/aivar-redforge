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


@unique
class CloudAssetRelationshipType(StrEnum):
    """Directed relationship kinds stored on CloudAsset."""

    CONTAINED_IN = "CONTAINED_IN"
    ATTACHED_TO = "ATTACHED_TO"
    ENCRYPTED_BY = "ENCRYPTED_BY"
    USES_IDENTITY = "USES_IDENTITY"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"


@unique
class NetworkExposure(StrEnum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    VPN_ONLY = "VPN_ONLY"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class CloudAssetId:
    value: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("CloudAssetId.value must be UUID")

    @classmethod
    def generate(cls) -> Self:
        return cls(uuid4())

    @classmethod
    def from_string(cls, raw: str) -> Self:
        return cls(UUID(raw))

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """Opaque provider-specific metadata (never secrets)."""

    attributes: dict[str, object]

    def __post_init__(self) -> None:
        if len(self.attributes) > 500:
            raise ValueError("ProviderMetadata max 500 attributes")

    def to_dict(self) -> dict[str, object]:
        return dict(self.attributes)

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> Self:
        return cls(attributes=dict(data or {}))

    @classmethod
    def empty(cls) -> Self:
        return cls(attributes={})


@dataclass(frozen=True, slots=True)
class NormalizedConfig:
    """Provider-agnostic configuration shared across ≥2 providers (ADR-M26-001)."""

    schema_version: str
    resource_class: str
    state: str | None = None
    network_exposure: NetworkExposure = NetworkExposure.UNKNOWN
    encryption_at_rest: bool | None = None
    public_endpoints: tuple[str, ...] = ()
    vpc_id: str | None = None
    subnet_ids: tuple[str, ...] = ()
    security_group_ids: tuple[str, ...] = ()
    kms_key_id: str | None = None
    iam_role_arn: str | None = None
    attributes: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.schema_version:
            raise ValueError("NormalizedConfig.schema_version required")
        if not self.resource_class or len(self.resource_class) > 64:
            raise ValueError("NormalizedConfig.resource_class invalid")
        if len(self.public_endpoints) > 50:
            raise ValueError("public_endpoints max 50")
        if len(self.subnet_ids) > 100 or len(self.security_group_ids) > 100:
            raise ValueError("network id lists exceed max")
        if len(self.attributes) > 100:
            raise ValueError("NormalizedConfig.attributes max 100")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "resource_class": self.resource_class,
            "state": self.state,
            "network_exposure": self.network_exposure.value,
            "encryption_at_rest": self.encryption_at_rest,
            "public_endpoints": list(self.public_endpoints),
            "vpc_id": self.vpc_id,
            "subnet_ids": list(self.subnet_ids),
            "security_group_ids": list(self.security_group_ids),
            "kms_key_id": self.kms_key_id,
            "iam_role_arn": self.iam_role_arn,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Self:
        attrs_raw = data.get("attributes") or {}
        attrs: list[tuple[str, str]] = []
        if isinstance(attrs_raw, dict):
            attrs = [(str(k), str(v)) for k, v in attrs_raw.items()]
        exposure_raw = data.get("network_exposure", NetworkExposure.UNKNOWN.value)
        endpoints_raw = data.get("public_endpoints")
        subnet_raw = data.get("subnet_ids")
        sg_raw = data.get("security_group_ids")
        endpoints = (
            tuple(str(x) for x in endpoints_raw) if isinstance(endpoints_raw, list) else ()
        )
        subnets = tuple(str(x) for x in subnet_raw) if isinstance(subnet_raw, list) else ()
        sgs = tuple(str(x) for x in sg_raw) if isinstance(sg_raw, list) else ()
        return cls(
            schema_version=str(data.get("schema_version", "1")),
            resource_class=str(data.get("resource_class", "unknown")),
            state=str(data["state"]) if data.get("state") is not None else None,
            network_exposure=NetworkExposure(str(exposure_raw)),
            encryption_at_rest=(
                bool(data["encryption_at_rest"])
                if data.get("encryption_at_rest") is not None
                else None
            ),
            public_endpoints=endpoints,
            vpc_id=str(data["vpc_id"]) if data.get("vpc_id") is not None else None,
            subnet_ids=subnets,
            security_group_ids=sgs,
            kms_key_id=str(data["kms_key_id"]) if data.get("kms_key_id") is not None else None,
            iam_role_arn=(
                str(data["iam_role_arn"]) if data.get("iam_role_arn") is not None else None
            ),
            attributes=tuple(attrs),
        )


@dataclass(frozen=True, slots=True)
class CloudPostureState:
    """Posture snapshot on CloudAsset (CSPM evaluation deferred to later phases)."""

    config_hash: str
    last_changed_at: datetime | None = None
    drift_detected: bool = False

    def __post_init__(self) -> None:
        if not self.config_hash or len(self.config_hash) > 128:
            raise ValueError("CloudPostureState.config_hash invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "config_hash": self.config_hash,
            "last_changed_at": (
                self.last_changed_at.isoformat() if self.last_changed_at is not None else None
            ),
            "drift_detected": self.drift_detected,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Self:
        changed = data.get("last_changed_at")
        return cls(
            config_hash=str(data["config_hash"]),
            last_changed_at=(
                datetime.fromisoformat(str(changed)) if changed is not None else None
            ),
            drift_detected=bool(data.get("drift_detected", False)),
        )

    @classmethod
    def initial(cls, config_hash: str, *, now: datetime | None = None) -> Self:
        return cls(config_hash=config_hash, last_changed_at=now, drift_detected=False)


# Phase 2 discovery asset types per provider (closed subsets of CloudAssetType).
AWS_DISCOVERY_ASSET_TYPES: tuple[CloudAssetType, ...] = (
    CloudAssetType.EC2_INSTANCE,
    CloudAssetType.S3_BUCKET,
    CloudAssetType.RDS_INSTANCE,
    CloudAssetType.VPC,
    CloudAssetType.SECURITY_GROUP,
    CloudAssetType.LAMBDA_FUNCTION,
    CloudAssetType.EKS_CLUSTER,
    CloudAssetType.ECR_REPOSITORY,
    CloudAssetType.ROUTE53_ZONE,
    CloudAssetType.CLOUDFRONT_DISTRIBUTION,
    CloudAssetType.KMS_KEY,
    CloudAssetType.SECRETS_MANAGER_SECRET,
)

AZURE_DISCOVERY_ASSET_TYPES: tuple[CloudAssetType, ...] = (
    CloudAssetType.AZURE_VM,
    CloudAssetType.AZURE_VNET,
    CloudAssetType.AZURE_NSG,
    CloudAssetType.AZURE_STORAGE_ACCOUNT,
    CloudAssetType.AZURE_SQL_DATABASE,
    CloudAssetType.AZURE_AKS_CLUSTER,
    CloudAssetType.AZURE_KEYVAULT,
    CloudAssetType.AZURE_FUNCTION_APP,
)

GCP_DISCOVERY_ASSET_TYPES: tuple[CloudAssetType, ...] = (
    CloudAssetType.GCP_COMPUTE_INSTANCE,
    CloudAssetType.GCP_VPC_NETWORK,
    CloudAssetType.GCP_STORAGE_BUCKET,
    CloudAssetType.GCP_CLOUD_SQL,
    CloudAssetType.GCP_GKE_CLUSTER,
    CloudAssetType.GCP_SECRET_MANAGER,
    CloudAssetType.GCP_CLOUD_FUNCTION,
)

DISCOVERY_ASSET_TYPES_BY_PROVIDER: dict[CloudProviderType, tuple[CloudAssetType, ...]] = {
    CloudProviderType.AWS: AWS_DISCOVERY_ASSET_TYPES,
    CloudProviderType.AZURE: AZURE_DISCOVERY_ASSET_TYPES,
    CloudProviderType.GCP: GCP_DISCOVERY_ASSET_TYPES,
}


@unique
class IAMPrincipalType(StrEnum):
    USER = "USER"
    ROLE = "ROLE"
    SERVICE_PRINCIPAL = "SERVICE_PRINCIPAL"
    GROUP = "GROUP"
    MANAGED_IDENTITY = "MANAGED_IDENTITY"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    POLICY = "POLICY"


@unique
class PrivilegeLevel(StrEnum):
    """Privilege classification placeholder — scoring deferred past Phase 3."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    ADMIN = "ADMIN"


@unique
class PolicyAttachmentType(StrEnum):
    MANAGED = "MANAGED"
    INLINE = "INLINE"
    ROLE_ASSIGNMENT = "ROLE_ASSIGNMENT"
    IAM_BINDING = "IAM_BINDING"
    CUSTOM_ROLE = "CUSTOM_ROLE"
    PREDEFINED_ROLE = "PREDEFINED_ROLE"


@dataclass(frozen=True, slots=True)
class CloudIAMPrincipalId:
    value: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("CloudIAMPrincipalId.value must be UUID")

    @classmethod
    def generate(cls) -> Self:
        return cls(uuid4())

    @classmethod
    def from_string(cls, raw: str) -> Self:
        return cls(UUID(raw))

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class EffectivePermissions:
    """Computed permission set — never persisted (ADR-M26-003).

    Phase 3 ships the value object only; calculation is deferred.
    """

    actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    computed_at: datetime | None = None

    def __post_init__(self) -> None:
        if len(self.actions) > 10_000 or len(self.resources) > 10_000:
            raise ValueError("EffectivePermissions lists exceed max size")

    @classmethod
    def unknown(cls) -> Self:
        return cls()

    def to_dict(self) -> dict[str, object]:
        return {
            "actions": list(self.actions),
            "resources": list(self.resources),
            "computed_at": self.computed_at.isoformat() if self.computed_at else None,
        }
