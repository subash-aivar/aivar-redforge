"""Value objects for M26 Phase 5 Kubernetes Security."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, unique
from typing import Self
from uuid import UUID, uuid4


@unique
class K8sClusterType(StrEnum):
    EKS = "EKS"
    AKS = "AKS"
    GKE = "GKE"
    SELF_MANAGED = "SELF_MANAGED"


@unique
class WorkloadKind(StrEnum):
    DEPLOYMENT = "DEPLOYMENT"
    STATEFULSET = "STATEFULSET"
    DAEMONSET = "DAEMONSET"
    REPLICASET = "REPLICASET"
    JOB = "JOB"
    CRONJOB = "CRONJOB"
    POD = "POD"


@unique
class PodSecurityLevel(StrEnum):
    PRIVILEGED = "PRIVILEGED"
    BASELINE = "BASELINE"
    RESTRICTED = "RESTRICTED"
    UNKNOWN = "UNKNOWN"


@unique
class WorkloadExposure(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CLUSTER_LOCAL = "CLUSTER_LOCAL"
    UNKNOWN = "UNKNOWN"


@unique
class K8sNetworkExposure(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    NAMESPACE_LOCAL = "NAMESPACE_LOCAL"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


@unique
class AdmissionMode(StrEnum):
    ENFORCE = "ENFORCE"
    AUDIT = "AUDIT"
    WARN = "WARN"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"


@unique
class RBACPrincipalKind(StrEnum):
    USER = "USER"
    GROUP = "GROUP"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"


@dataclass(frozen=True, slots=True)
class ClusterId:
    value: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise ValueError("ClusterId must be UUID")

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> Self:
        return cls(uuid4())

    @classmethod
    def from_str(cls, raw: str) -> Self:
        return cls(UUID(raw))


@dataclass(frozen=True, slots=True)
class NamespaceId:
    value: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise ValueError("NamespaceId must be UUID")

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> Self:
        return cls(uuid4())

    @classmethod
    def from_str(cls, raw: str) -> Self:
        return cls(UUID(raw))


@dataclass(frozen=True, slots=True)
class WorkloadId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> Self:
        return cls(uuid4())

    @classmethod
    def from_str(cls, raw: str) -> Self:
        return cls(UUID(raw))


@dataclass(frozen=True, slots=True)
class ContainerImage:
    repository: str
    tag: str
    digest: str = ""

    def __post_init__(self) -> None:
        if not self.repository or len(self.repository) > 512:
            raise ValueError("ContainerImage.repository invalid")
        if len(self.tag) > 256:
            raise ValueError("ContainerImage.tag too long")
        if len(self.digest) > 128:
            raise ValueError("ContainerImage.digest too long")

    @property
    def uses_latest_tag(self) -> bool:
        return self.tag.lower() in {"", "latest"} and not self.digest

    def reference(self) -> str:
        if self.digest:
            return f"{self.repository}@{self.digest}"
        return f"{self.repository}:{self.tag or 'latest'}"

    def to_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "tag": self.tag,
            "digest": self.digest,
            "uses_latest_tag": self.uses_latest_tag,
        }

    @classmethod
    def parse(cls, image: str) -> Self:
        raw = (image or "").strip()
        if not raw:
            raise ValueError("ContainerImage empty")
        digest = ""
        repo_tag = raw
        if "@" in raw:
            repo_tag, digest = raw.split("@", 1)
        if ":" in repo_tag and "/" in repo_tag.rsplit(":", 1)[0]:
            repository, tag = repo_tag.rsplit(":", 1)
        elif ":" in repo_tag and repo_tag.count(":") == 1 and "/" not in repo_tag:
            repository, tag = repo_tag.split(":", 1)
        else:
            # host:port/path without tag
            if repo_tag.count(":") == 1 and "/" in repo_tag:
                repository, tag = repo_tag, "latest"
            else:
                repository, tag = repo_tag, "latest"
        return cls(repository=repository, tag=tag, digest=digest)


@dataclass(frozen=True, slots=True)
class ResourceRequests:
    cpu: str = ""
    memory: str = ""
    ephemeral_storage: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "cpu": self.cpu,
            "memory": self.memory,
            "ephemeral_storage": self.ephemeral_storage,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> Self:
        if not data:
            return cls()
        return cls(
            cpu=str(data.get("cpu", "")),
            memory=str(data.get("memory", "")),
            ephemeral_storage=str(data.get("ephemeral_storage", "")),
        )


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    cpu: str = ""
    memory: str = ""
    ephemeral_storage: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "cpu": self.cpu,
            "memory": self.memory,
            "ephemeral_storage": self.ephemeral_storage,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> Self:
        if not data:
            return cls()
        return cls(
            cpu=str(data.get("cpu", "")),
            memory=str(data.get("memory", "")),
            ephemeral_storage=str(data.get("ephemeral_storage", "")),
        )


@dataclass(frozen=True, slots=True)
class K8sSecurityScore:
    """Computed posture score 0-100 (higher is better). Not a risk-engine score."""

    value: int
    findings_open: int = 0
    workloads_evaluated: int = 0
    coverage_ratio: float = 0.0

    def __post_init__(self) -> None:
        if self.value < 0 or self.value > 100:
            raise ValueError("K8sSecurityScore.value must be 0..100")

    def to_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "findings_open": self.findings_open,
            "workloads_evaluated": self.workloads_evaluated,
            "coverage_ratio": self.coverage_ratio,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> Self:
        if not data:
            return cls(value=0)
        return cls(
            value=int(str(data.get("value", 0) or 0)),
            findings_open=int(str(data.get("findings_open", 0) or 0)),
            workloads_evaluated=int(str(data.get("workloads_evaluated", 0) or 0)),
            coverage_ratio=float(str(data.get("coverage_ratio", 0.0) or 0.0)),
        )

    @classmethod
    def compute(
        cls,
        *,
        workloads_evaluated: int,
        violation_count: int,
        critical_count: int = 0,
        high_count: int = 0,
    ) -> Self:
        if workloads_evaluated <= 0:
            return cls(value=100, findings_open=0, workloads_evaluated=0, coverage_ratio=0.0)
        penalty = violation_count * 4 + critical_count * 8 + high_count * 3
        score = max(0, min(100, 100 - penalty))
        coverage = 1.0 if workloads_evaluated > 0 else 0.0
        return cls(
            value=score,
            findings_open=violation_count,
            workloads_evaluated=workloads_evaluated,
            coverage_ratio=coverage,
        )
