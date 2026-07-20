"""Unit tests for Kubernetes domain aggregates and value objects."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from redforge.domain.cloud_security.kubernetes.admission_policy import KubernetesAdmissionPolicy
from redforge.domain.cloud_security.kubernetes.cluster import KubernetesCluster
from redforge.domain.cloud_security.kubernetes.entities import (
    AdmissionViolation,
    PodContainer,
    RBACBinding,
    ServiceAccountReference,
)
from redforge.domain.cloud_security.kubernetes.events import (
    AdmissionPolicyEvaluated,
    ClusterDiscovered,
    K8sPodSecurityViolationDetected,
    NamespaceDiscovered,
    NetworkPolicyDiscovered,
    RBACDiscovered,
    WorkloadDiscovered,
)
from redforge.domain.cloud_security.kubernetes.exceptions import InvalidKubernetesArgumentError
from redforge.domain.cloud_security.kubernetes.namespace import KubernetesNamespace
from redforge.domain.cloud_security.kubernetes.network_policy import KubernetesNetworkPolicy
from redforge.domain.cloud_security.kubernetes.rbac import KubernetesRBACPrincipal
from redforge.domain.cloud_security.kubernetes.value_objects import (
    ContainerImage,
    K8sClusterType,
    K8sSecurityScore,
    PodSecurityLevel,
    WorkloadExposure,
    WorkloadKind,
)
from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId

ORG = OrganizationId("01HXORG0000000000000000001")
ACCOUNT = CloudAccountId(uuid4())


def test_cluster_discover_emits_event() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type=K8sClusterType.EKS,
        name="prod",
        version="1.29.0",
    )
    events = cluster.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], ClusterDiscovered)
    assert events[0].cluster_name == "prod"
    assert cluster.security_score.value == 100


def test_cluster_discover_rejects_empty_name() -> None:
    with pytest.raises(InvalidKubernetesArgumentError):
        KubernetesCluster.discover(
            organization_id=ORG,
            cloud_account_id=ACCOUNT,
            cluster_type="EKS",
            name="  ",
            version="1.29",
        )


def test_cluster_mark_synced_bumps_version() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="AKS",
        name="aks-1",
        version="1.28",
    )
    before = cluster.row_version
    cluster.mark_synced()
    assert cluster.row_version == before + 1
    assert cluster.last_synced_at is not None


def test_cluster_update_security_score() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="GKE",
        name="gke-1",
        version="1.28",
    )
    score = K8sSecurityScore.compute(
        workloads_evaluated=10, violation_count=2, critical_count=1, high_count=1
    )
    cluster.update_security_score(score)
    assert cluster.security_score.findings_open == 2
    assert cluster.security_score.value < 100


@pytest.mark.parametrize(
    ("image", "latest"),
    [
        ("nginx:latest", True),
        ("nginx", True),
        ("nginx:1.25", False),
        ("nginx@sha256:abc", False),
        ("registry.io/app:v1", False),
        ("registry.io/app:latest", True),
    ],
)
def test_container_image_latest_tag(image: str, latest: bool) -> None:
    parsed = ContainerImage.parse(image)
    assert parsed.uses_latest_tag is latest


def test_container_image_reference() -> None:
    assert ContainerImage.parse("nginx:1.25").reference() == "nginx:1.25"
    assert "sha256" in ContainerImage.parse("nginx@sha256:deadbeef").reference()


def test_container_image_rejects_empty() -> None:
    with pytest.raises(ValueError):
        ContainerImage.parse("")


def test_security_score_bounds() -> None:
    with pytest.raises(ValueError):
        K8sSecurityScore(value=101)
    with pytest.raises(ValueError):
        K8sSecurityScore(value=-1)


def test_security_score_compute_empty() -> None:
    score = K8sSecurityScore.compute(workloads_evaluated=0, violation_count=0)
    assert score.value == 100
    assert score.coverage_ratio == 0.0


def test_security_score_compute_penalties() -> None:
    score = K8sSecurityScore.compute(
        workloads_evaluated=5, violation_count=3, critical_count=1, high_count=2
    )
    # 100 - (3*4 + 1*8 + 2*3) = 100 - 26 = 74
    assert score.value == 74


def test_security_score_round_trip_dict() -> None:
    score = K8sSecurityScore(value=88, findings_open=2, workloads_evaluated=5, coverage_ratio=1.0)
    restored = K8sSecurityScore.from_dict(score.to_dict())
    assert restored == score


def _privileged_container() -> PodContainer:
    return PodContainer(
        name="app",
        image=ContainerImage.parse("app:latest"),
        privileged=True,
        allow_privilege_escalation=True,
    )


def _restricted_container() -> PodContainer:
    return PodContainer(
        name="app",
        image=ContainerImage.parse("app:1.0"),
        privileged=False,
        allow_privilege_escalation=False,
        read_only_root_filesystem=True,
        run_as_non_root=True,
        image_pull_policy="Always",
    )


def test_workload_discover_privileged_level() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="EKS",
        name="c",
        version="1.29",
    )
    wl = KubernetesWorkload.discover(
        cluster_id=cluster.id,
        organization_id=ORG,
        namespace="default",
        name="web",
        kind=WorkloadKind.DEPLOYMENT,
        containers=[_privileged_container()],
        host_network=True,
    )
    assert wl.privileged is True
    assert wl.security_level == PodSecurityLevel.PRIVILEGED
    assert isinstance(wl.pop_events()[0], WorkloadDiscovered)


def test_workload_restricted_level() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="EKS",
        name="c2",
        version="1.29",
    )
    wl = KubernetesWorkload.discover(
        cluster_id=cluster.id,
        organization_id=ORG,
        namespace="secure",
        name="api",
        kind="DEPLOYMENT",
        containers=[_restricted_container()],
    )
    assert wl.security_level == PodSecurityLevel.RESTRICTED


def test_workload_posture_snapshot_shape() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="EKS",
        name="c3",
        version="1.29",
    )
    wl = KubernetesWorkload.discover(
        cluster_id=cluster.id,
        organization_id=ORG,
        namespace="default",
        name="web",
        kind=WorkloadKind.DEPLOYMENT,
        containers=[_privileged_container()],
        host_pid=True,
        host_ipc=True,
        exposure=WorkloadExposure.PUBLIC,
    )
    snap = wl.posture_snapshot()
    assert snap["asset_type"] == "K8S_WORKLOAD"
    assert snap["normalized_config"]["privileged"] is True
    assert snap["normalized_config"]["host_pid"] is True
    assert snap["normalized_config"]["host_ipc"] is True
    assert snap["normalized_config"]["network_exposure"] == "PUBLIC"
    assert snap["normalized_config"]["uses_latest_tag"] is True
    assert "image_pull_policy_always" in snap["normalized_config"]


def test_workload_rejects_empty_name() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="EKS",
        name="c4",
        version="1.29",
    )
    with pytest.raises(InvalidKubernetesArgumentError):
        KubernetesWorkload.discover(
            cluster_id=cluster.id,
            organization_id=ORG,
            namespace="default",
            name="",
            kind="POD",
        )


def test_namespace_discover_and_network_policy_flag() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="EKS",
        name="c5",
        version="1.29",
    )
    ns = KubernetesNamespace.discover(
        cluster_id=cluster.id,
        organization_id=ORG,
        name="payments",
        pod_security_level="restricted",
    )
    assert isinstance(ns.pop_events()[0], NamespaceDiscovered)
    assert ns.has_network_policy is False
    ns.mark_network_policy(True)
    assert ns.has_network_policy is True


def test_rbac_inventory_flags() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="EKS",
        name="c6",
        version="1.29",
    )
    principal = KubernetesRBACPrincipal.discover(
        cluster_id=cluster.id,
        organization_id=ORG,
        kind="SERVICE_ACCOUNT",
        name="deployer",
        namespace="default",
        cluster_roles=["cluster-admin"],
        bindings=[
            RBACBinding(
                binding_name="bind",
                binding_kind="ClusterRoleBinding",
                role_ref_kind="ClusterRole",
                role_ref_name="cluster-admin",
                subjects=({"kind": "ServiceAccount", "name": "deployer"},),
                verbs=("*",),
                resources=("*",),
            )
        ],
    )
    inv = principal.inventory_dict()
    assert inv["has_wildcard_verb"] is True
    assert inv["has_wildcard_resource"] is True
    assert inv["bound_cluster_admin"] is True
    assert isinstance(principal.pop_events()[0], RBACDiscovered)


def test_network_policy_discover() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="EKS",
        name="c7",
        version="1.29",
    )
    policy = KubernetesNetworkPolicy.discover(
        cluster_id=cluster.id,
        organization_id=ORG,
        namespace="default",
        name="deny-all",
        allows_cross_namespace=False,
    )
    assert isinstance(policy.pop_events()[0], NetworkPolicyDiscovered)


def test_admission_policy_evaluation_event() -> None:
    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="EKS",
        name="c8",
        version="1.29",
    )
    policy = KubernetesAdmissionPolicy.register(
        cluster_id=cluster.id,
        organization_id=ORG,
        name="pss",
        mode="ENFORCE",
        controller="PodSecurity",
    )
    policy.record_evaluation(
        violations=[
            AdmissionViolation(
                rule_id="no-privileged",
                message="privileged",
                resource_kind="Deployment",
                resource_name="web",
                namespace="default",
            )
        ]
    )
    events = policy.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], AdmissionPolicyEvaluated)
    assert events[0].violation_count == 1


def test_pod_security_violation_event_fields() -> None:
    event = K8sPodSecurityViolationDetected(
        occurred_at=datetime.now(UTC),
        organization_id=str(ORG),
        cluster_id=uuid4(),
        workload_id=uuid4(),
        policy_id="CSPM-K8S-PRIVILEGED-001",
        severity="CRITICAL",
        message="privileged",
    )
    assert event.policy_id.startswith("CSPM-K8S")


def test_service_account_default() -> None:
    sa = ServiceAccountReference.from_dict(None)
    assert sa.name == "default"
    assert sa.namespace == "default"
