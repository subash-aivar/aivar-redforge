"""Extra Phase 5 coverage for posture helpers and service DTOs."""

from __future__ import annotations

from uuid import uuid4

from redforge.application.cloud_security.kubernetes.dtos import (
    ComplianceSummaryDTO,
    EvaluationResultDTO,
    ViolationResultDTO,
)
from redforge.domain.cloud_security.kubernetes.cluster import KubernetesCluster
from redforge.domain.cloud_security.kubernetes.entities import PodContainer
from redforge.domain.cloud_security.kubernetes.node import KubernetesNode
from redforge.domain.cloud_security.kubernetes.value_objects import (
    ContainerImage,
    WorkloadKind,
)
from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId
from redforge.infrastructure.cloud_security.cspm.policy_loader import load_cspm_policies

ORG = OrganizationId("01HXORG0000000000000000001")
ACCOUNT = CloudAccountId(uuid4())


def test_workload_kind_enum_values() -> None:
    assert WorkloadKind.DEPLOYMENT.value == "DEPLOYMENT"
    assert WorkloadKind.STATEFULSET.value == "STATEFULSET"
    assert WorkloadKind.DAEMONSET.value == "DAEMONSET"
    assert WorkloadKind.CRONJOB.value == "CRONJOB"


def test_node_discover_event() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="EKS",
        name="n-cluster",
        version="1.29",
    )
    node = KubernetesNode.discover(
        cluster_id=cluster.id,
        organization_id=ORG,
        name="worker-1",
        roles=["worker"],
    )
    events = node.pop_events()
    assert len(events) == 1
    assert events[0].node_name == "worker-1"


def test_evaluation_result_dto_fields() -> None:
    dto = EvaluationResultDTO(
        cluster_id=str(uuid4()),
        workloads_evaluated=2,
        policies_evaluated=12,
        violations=[
            ViolationResultDTO(
                workload_id=str(uuid4()),
                policy_id="P",
                rule_id="R",
                severity="HIGH",
                title="t",
                message="m",
                passed=False,
            )
        ],
        security_score={"value": 80},
    )
    assert dto.workloads_evaluated == 2
    assert dto.violations[0].severity == "HIGH"


def test_compliance_summary_dto() -> None:
    dto = ComplianceSummaryDTO(
        cluster_id=str(uuid4()),
        security_score={"value": 90},
        workload_count=5,
        privileged_count=1,
        public_exposure_count=0,
        namespaces_without_network_policy=2,
        rbac_wildcard_count=1,
    )
    assert dto.rbac_wildcard_count == 1


def test_k8s_policies_apply_to_workload_asset_type() -> None:
    policies = [
        p
        for p in load_cspm_policies()
        if p.applies_to(provider_type="AWS", asset_type="K8S_WORKLOAD")
    ]
    assert len(policies) >= 12


def test_baseline_capabilities_infer_baseline_level() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="EKS",
        name="cap-cluster",
        version="1.29",
    )
    wl = KubernetesWorkload.discover(
        cluster_id=cluster.id,
        organization_id=ORG,
        namespace="default",
        name="cap",
        kind="POD",
        containers=[
            PodContainer(
                name="c",
                image=ContainerImage.parse("app:1"),
                capabilities_add=("NET_BIND_SERVICE",),
            )
        ],
    )
    assert wl.security_level.value == "BASELINE"


def test_empty_containers_unknown_security_level() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="EKS",
        name="empty-c",
        version="1.29",
    )
    wl = KubernetesWorkload.discover(
        cluster_id=cluster.id,
        organization_id=ORG,
        namespace="default",
        name="empty",
        kind="POD",
        containers=[],
    )
    assert wl.security_level.value == "UNKNOWN"
