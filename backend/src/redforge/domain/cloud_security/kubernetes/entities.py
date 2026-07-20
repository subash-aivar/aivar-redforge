"""Entities for Kubernetes security domain."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from redforge.domain.cloud_security.kubernetes.value_objects import (
    ContainerImage,
    ResourceLimits,
    ResourceRequests,
)


@dataclass(frozen=True, slots=True)
class VolumeMount:
    name: str
    mount_path: str
    read_only: bool = False
    host_path: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "mount_path": self.mount_path,
            "read_only": self.read_only,
            "host_path": self.host_path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> VolumeMount:
        return cls(
            name=str(data.get("name", "")),
            mount_path=str(data.get("mount_path", "")),
            read_only=bool(data.get("read_only", False)),
            host_path=str(data.get("host_path", "")),
        )


@dataclass(frozen=True, slots=True)
class PodContainer:
    name: str
    image: ContainerImage
    privileged: bool = False
    allow_privilege_escalation: bool = True
    read_only_root_filesystem: bool = False
    run_as_non_root: bool = False
    run_as_user: int | None = None
    capabilities_add: tuple[str, ...] = ()
    capabilities_drop: tuple[str, ...] = ()
    image_pull_policy: str = "IfNotPresent"
    requests: ResourceRequests = field(default_factory=ResourceRequests)
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    volume_mounts: tuple[VolumeMount, ...] = ()
    env_from_secret: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "image": self.image.to_dict(),
            "privileged": self.privileged,
            "allow_privilege_escalation": self.allow_privilege_escalation,
            "read_only_root_filesystem": self.read_only_root_filesystem,
            "run_as_non_root": self.run_as_non_root,
            "run_as_user": self.run_as_user,
            "capabilities_add": list(self.capabilities_add),
            "capabilities_drop": list(self.capabilities_drop),
            "image_pull_policy": self.image_pull_policy,
            "requests": self.requests.to_dict(),
            "limits": self.limits.to_dict(),
            "volume_mounts": [v.to_dict() for v in self.volume_mounts],
            "env_from_secret": self.env_from_secret,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> PodContainer:
        image_raw = data.get("image")
        if isinstance(image_raw, dict):
            image = ContainerImage(
                repository=str(image_raw.get("repository", "")),
                tag=str(image_raw.get("tag", "latest")),
                digest=str(image_raw.get("digest", "")),
            )
        else:
            image = ContainerImage.parse(str(image_raw or "unknown:latest"))
        mounts_raw = data.get("volume_mounts") or []
        mounts: list[VolumeMount] = []
        if isinstance(mounts_raw, list):
            for item in mounts_raw:
                if isinstance(item, dict):
                    mounts.append(VolumeMount.from_dict(item))
        caps_add = data.get("capabilities_add") or []
        caps_drop = data.get("capabilities_drop") or []
        return cls(
            name=str(data.get("name", "")),
            image=image,
            privileged=bool(data.get("privileged", False)),
            allow_privilege_escalation=bool(data.get("allow_privilege_escalation", True)),
            read_only_root_filesystem=bool(data.get("read_only_root_filesystem", False)),
            run_as_non_root=bool(data.get("run_as_non_root", False)),
            run_as_user=(
                int(str(data["run_as_user"])) if data.get("run_as_user") is not None else None
            ),
            capabilities_add=tuple(str(x) for x in caps_add)
            if isinstance(caps_add, (list, tuple))
            else (),
            capabilities_drop=tuple(str(x) for x in caps_drop)
            if isinstance(caps_drop, (list, tuple))
            else (),
            image_pull_policy=str(data.get("image_pull_policy", "IfNotPresent")),
            requests=ResourceRequests.from_dict(
                _maybe_str_dict(data.get("requests"))
            ),
            limits=ResourceLimits.from_dict(
                _maybe_str_dict(data.get("limits"))
            ),
            volume_mounts=tuple(mounts),
            env_from_secret=bool(data.get("env_from_secret", False)),
        )


def _maybe_str_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    return {str(k): v for k, v in value.items()}


@dataclass(frozen=True, slots=True)
class ServiceAccountReference:
    name: str
    namespace: str
    uid: str = ""

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "namespace": self.namespace, "uid": self.uid}

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> ServiceAccountReference:
        if not data:
            return cls(name="default", namespace="default")
        return cls(
            name=str(data.get("name", "default")),
            namespace=str(data.get("namespace", "default")),
            uid=str(data.get("uid", "")),
        )


@dataclass(frozen=True, slots=True)
class RBACBinding:
    binding_name: str
    binding_kind: str
    role_ref_kind: str
    role_ref_name: str
    subjects: tuple[dict[str, str], ...]
    namespace: str = ""
    verbs: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    api_groups: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "binding_name": self.binding_name,
            "binding_kind": self.binding_kind,
            "role_ref_kind": self.role_ref_kind,
            "role_ref_name": self.role_ref_name,
            "subjects": [dict(s) for s in self.subjects],
            "namespace": self.namespace,
            "verbs": list(self.verbs),
            "resources": list(self.resources),
            "api_groups": list(self.api_groups),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> RBACBinding:
        subjects_raw = data.get("subjects") or []
        subjects: list[dict[str, str]] = []
        if isinstance(subjects_raw, list):
            for item in subjects_raw:
                if isinstance(item, dict):
                    subjects.append({str(k): str(v) for k, v in item.items()})
        verbs_raw = data.get("verbs") or []
        resources_raw = data.get("resources") or []
        api_groups_raw = data.get("api_groups") or []
        return cls(
            binding_name=str(data.get("binding_name", "")),
            binding_kind=str(data.get("binding_kind", "")),
            role_ref_kind=str(data.get("role_ref_kind", "")),
            role_ref_name=str(data.get("role_ref_name", "")),
            subjects=tuple(subjects),
            namespace=str(data.get("namespace", "")),
            verbs=tuple(str(x) for x in verbs_raw)
            if isinstance(verbs_raw, (list, tuple))
            else (),
            resources=tuple(str(x) for x in resources_raw)
            if isinstance(resources_raw, (list, tuple))
            else (),
            api_groups=tuple(str(x) for x in api_groups_raw)
            if isinstance(api_groups_raw, (list, tuple))
            else (),
        )


@dataclass(frozen=True, slots=True)
class NetworkRule:
    direction: str
    peers: tuple[str, ...]
    ports: tuple[str, ...]
    allow: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "direction": self.direction,
            "peers": list(self.peers),
            "ports": list(self.ports),
            "allow": self.allow,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> NetworkRule:
        peers_raw = data.get("peers") or []
        ports_raw = data.get("ports") or []
        return cls(
            direction=str(data.get("direction", "ingress")),
            peers=tuple(str(x) for x in peers_raw)
            if isinstance(peers_raw, (list, tuple))
            else (),
            ports=tuple(str(x) for x in ports_raw)
            if isinstance(ports_raw, (list, tuple))
            else (),
            allow=bool(data.get("allow", True)),
        )


@dataclass(frozen=True, slots=True)
class AdmissionViolation:
    rule_id: str
    message: str
    resource_kind: str
    resource_name: str
    namespace: str = ""
    severity: str = "MEDIUM"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "resource_kind": self.resource_kind,
            "resource_name": self.resource_name,
            "namespace": self.namespace,
            "severity": self.severity,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> AdmissionViolation:
        return cls(
            rule_id=str(data.get("rule_id", "")),
            message=str(data.get("message", "")),
            resource_kind=str(data.get("resource_kind", "")),
            resource_name=str(data.get("resource_name", "")),
            namespace=str(data.get("namespace", "")),
            severity=str(data.get("severity", "MEDIUM")),
        )
