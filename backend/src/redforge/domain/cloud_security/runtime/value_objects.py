"""Value objects for M26 Phase 6 Runtime Visibility."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum, unique
from typing import Self
from uuid import UUID, uuid4


@unique
class RuntimeEventType(StrEnum):
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    FILE_ACTIVITY = "FILE_ACTIVITY"
    CONTAINER_EXECUTION = "CONTAINER_EXECUTION"
    IDENTITY_SESSION = "IDENTITY_SESSION"
    API_ACTIVITY = "API_ACTIVITY"
    UNKNOWN = "UNKNOWN"


@unique
class RuntimeSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@unique
class RuntimeProtocol(StrEnum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    UNKNOWN = "UNKNOWN"


@unique
class RuntimeDirection(StrEnum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    LATERAL = "LATERAL"
    UNKNOWN = "UNKNOWN"


@unique
class RuntimeSource(StrEnum):
    CLOUDTRAIL = "CLOUDTRAIL"
    AZURE_ACTIVITY = "AZURE_ACTIVITY"
    GCP_AUDIT = "GCP_AUDIT"
    KUBERNETES_AUDIT = "KUBERNETES_AUDIT"
    GENERIC = "GENERIC"


@unique
class EventOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class CloudRuntimeEventId:
    value: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise TypeError("CloudRuntimeEventId.value must be UUID")

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> Self:
        return cls(uuid4())

    @classmethod
    def from_str(cls, raw: str) -> Self:
        return cls(UUID(raw))


@dataclass(frozen=True, slots=True)
class RuntimeIdentity:
    principal_id: str = ""
    principal_type: str = ""
    principal_name: str = ""
    account_id: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "principal_name": self.principal_name,
            "account_id": self.account_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> Self:
        if not data:
            return cls()
        return cls(
            principal_id=str(data.get("principal_id", "")),
            principal_type=str(data.get("principal_type", "")),
            principal_name=str(data.get("principal_name", "")),
            account_id=str(data.get("account_id", "")),
        )


@dataclass(frozen=True, slots=True)
class RuntimeHost:
    hostname: str = ""
    host_id: str = ""
    private_ip: str = ""
    public_ip: str = ""
    region: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "hostname": self.hostname,
            "host_id": self.host_id,
            "private_ip": self.private_ip,
            "public_ip": self.public_ip,
            "region": self.region,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> Self:
        if not data:
            return cls()
        return cls(
            hostname=str(data.get("hostname", "")),
            host_id=str(data.get("host_id", "")),
            private_ip=str(data.get("private_ip", "")),
            public_ip=str(data.get("public_ip", "")),
            region=str(data.get("region", "")),
        )


@dataclass(frozen=True, slots=True)
class RuntimeContainer:
    container_id: str = ""
    image: str = ""
    namespace: str = ""
    pod_name: str = ""
    workload_name: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "container_id": self.container_id,
            "image": self.image,
            "namespace": self.namespace,
            "pod_name": self.pod_name,
            "workload_name": self.workload_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> Self:
        if not data:
            return cls()
        return cls(
            container_id=str(data.get("container_id", "")),
            image=str(data.get("image", "")),
            namespace=str(data.get("namespace", "")),
            pod_name=str(data.get("pod_name", "")),
            workload_name=str(data.get("workload_name", "")),
        )


@dataclass(frozen=True, slots=True)
class RuntimeTimestamp:
    event_time: datetime
    ingested_at: datetime

    def to_dict(self) -> dict[str, object]:
        return {
            "event_time": self.event_time.isoformat(),
            "ingested_at": self.ingested_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class RuntimeCorrelationRefs:
    """Soft references to existing platform aggregates — inventory only, no detections."""

    cloud_asset_id: UUID | None = None
    cloud_iam_principal_id: UUID | None = None
    kubernetes_workload_id: UUID | None = None
    cloud_account_id: UUID | None = None
    organization_id: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "cloud_asset_id": str(self.cloud_asset_id) if self.cloud_asset_id else None,
            "cloud_iam_principal_id": (
                str(self.cloud_iam_principal_id) if self.cloud_iam_principal_id else None
            ),
            "kubernetes_workload_id": (
                str(self.kubernetes_workload_id) if self.kubernetes_workload_id else None
            ),
            "cloud_account_id": str(self.cloud_account_id) if self.cloud_account_id else None,
            "organization_id": self.organization_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> Self:
        if not data:
            return cls()

        def _uuid(key: str) -> UUID | None:
            raw = data.get(key)
            if raw is None or raw == "":
                return None
            return UUID(str(raw))

        return cls(
            cloud_asset_id=_uuid("cloud_asset_id"),
            cloud_iam_principal_id=_uuid("cloud_iam_principal_id"),
            kubernetes_workload_id=_uuid("kubernetes_workload_id"),
            cloud_account_id=_uuid("cloud_account_id"),
            organization_id=str(data.get("organization_id", "")),
        )
