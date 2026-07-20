"""Domain events for Kubernetes security discovery and evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class KubernetesDomainEvent:
    occurred_at: datetime
    organization_id: str
    cluster_id: UUID


@dataclass(frozen=True, slots=True)
class ClusterDiscovered(KubernetesDomainEvent):
    cluster_name: str
    cluster_type: str
    cloud_asset_id: UUID | None


@dataclass(frozen=True, slots=True)
class NamespaceDiscovered(KubernetesDomainEvent):
    namespace: str
    namespace_id: UUID


@dataclass(frozen=True, slots=True)
class WorkloadDiscovered(KubernetesDomainEvent):
    workload_id: UUID
    namespace: str
    name: str
    kind: str


@dataclass(frozen=True, slots=True)
class NodeDiscovered(KubernetesDomainEvent):
    node_id: UUID
    node_name: str


@dataclass(frozen=True, slots=True)
class RBACDiscovered(KubernetesDomainEvent):
    principal_id: UUID
    principal_kind: str
    principal_name: str


@dataclass(frozen=True, slots=True)
class NetworkPolicyDiscovered(KubernetesDomainEvent):
    policy_id: UUID
    namespace: str
    name: str


@dataclass(frozen=True, slots=True)
class AdmissionPolicyEvaluated(KubernetesDomainEvent):
    policy_id: UUID
    mode: str
    violation_count: int


# Freeze-aligned aliases / posture events (inventory + CSPM integration; no attack paths).
K8sClusterDiscovered = ClusterDiscovered


@dataclass(frozen=True, slots=True)
class K8sWorkloadUpdated(KubernetesDomainEvent):
    workload_id: UUID
    namespace: str
    name: str


@dataclass(frozen=True, slots=True)
class K8sPodSecurityViolationDetected(KubernetesDomainEvent):
    workload_id: UUID
    policy_id: str
    severity: str
    message: str


@dataclass(frozen=True, slots=True)
class K8sNetworkPolicyGapDetected(KubernetesDomainEvent):
    namespace: str
    message: str
    details: dict[str, Any]
