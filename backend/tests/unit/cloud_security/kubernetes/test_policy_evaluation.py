"""Policy evaluation against packaged Kubernetes CSPM YAML policies."""

from __future__ import annotations

from uuid import uuid4

from redforge.domain.cloud_security.kubernetes.cluster import KubernetesCluster
from redforge.domain.cloud_security.kubernetes.entities import PodContainer
from redforge.domain.cloud_security.kubernetes.value_objects import ContainerImage
from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload
from redforge.domain.cloud_security.policy_engine.evaluator import PolicyEvaluationEngine
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId
from redforge.infrastructure.cloud_security.cspm.policy_loader import load_cspm_policies

ORG = OrganizationId("01HXORG0000000000000000001")
ACCOUNT = CloudAccountId(uuid4())


def _k8s_policies() -> list:
    return [
        p
        for p in load_cspm_policies()
        if "K8S_WORKLOAD" in p.asset_types or "*" in p.asset_types
    ]


def _cluster():
    return KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        cluster_type="EKS",
        name="policy-test",
        version="1.29",
    )


def _workload(**kwargs):
    cluster = _cluster()
    defaults = {
        "cluster_id": cluster.id,
        "organization_id": ORG,
        "namespace": "default",
        "name": "web",
        "kind": "DEPLOYMENT",
        "containers": [
            PodContainer(
                name="web",
                image=ContainerImage.parse("nginx:1.25"),
                privileged=False,
                allow_privilege_escalation=False,
                read_only_root_filesystem=True,
                run_as_non_root=True,
                image_pull_policy="Always",
            )
        ],
    }
    defaults.update(kwargs)
    return KubernetesWorkload.discover(**defaults)


def test_loader_includes_kubernetes_policies() -> None:
    policies = _k8s_policies()
    assert len(policies) >= 12
    ids = {str(p.id) for p in policies}
    assert "CSPM-K8S-PRIVILEGED-001" in ids
    assert "CSPM-K8S-LATEST-TAG-001" in ids


def test_privileged_policy_matches() -> None:
    engine = PolicyEvaluationEngine()
    policy = next(p for p in _k8s_policies() if str(p.id) == "CSPM-K8S-PRIVILEGED-001")
    bad = _workload(
        containers=[
            PodContainer(
                name="web",
                image=ContainerImage.parse("nginx:1.25"),
                privileged=True,
            )
        ]
    )
    good = _workload()
    assert engine.evaluate(policy.rule, bad.posture_snapshot()).matched is True
    assert engine.evaluate(policy.rule, good.posture_snapshot()).matched is False


def test_host_network_policy() -> None:
    engine = PolicyEvaluationEngine()
    policy = next(p for p in _k8s_policies() if str(p.id) == "CSPM-K8S-HOST-NETWORK-001")
    wl = _workload(host_network=True)
    assert engine.evaluate(policy.rule, wl.posture_snapshot()).matched is True


def test_host_pid_policy() -> None:
    engine = PolicyEvaluationEngine()
    policy = next(p for p in _k8s_policies() if str(p.id) == "CSPM-K8S-HOST-PID-001")
    wl = _workload(host_pid=True)
    assert engine.evaluate(policy.rule, wl.posture_snapshot()).matched is True


def test_host_ipc_policy() -> None:
    engine = PolicyEvaluationEngine()
    policy = next(p for p in _k8s_policies() if str(p.id) == "CSPM-K8S-HOST-IPC-001")
    wl = _workload(host_ipc=True)
    assert engine.evaluate(policy.rule, wl.posture_snapshot()).matched is True


def test_allow_privilege_escalation_policy() -> None:
    engine = PolicyEvaluationEngine()
    policy = next(p for p in _k8s_policies() if str(p.id) == "CSPM-K8S-ALLOW-PRIV-ESC-001")
    wl = _workload(
        containers=[
            PodContainer(
                name="web",
                image=ContainerImage.parse("nginx:1.25"),
                allow_privilege_escalation=True,
                read_only_root_filesystem=True,
                run_as_non_root=True,
                image_pull_policy="Always",
            )
        ]
    )
    assert engine.evaluate(policy.rule, wl.posture_snapshot()).matched is True


def test_readonly_root_filesystem_policy() -> None:
    engine = PolicyEvaluationEngine()
    policy = next(p for p in _k8s_policies() if str(p.id) == "CSPM-K8S-READONLY-ROOT-001")
    wl = _workload(
        containers=[
            PodContainer(
                name="web",
                image=ContainerImage.parse("nginx:1.25"),
                allow_privilege_escalation=False,
                read_only_root_filesystem=False,
                run_as_non_root=True,
                image_pull_policy="Always",
            )
        ]
    )
    assert engine.evaluate(policy.rule, wl.posture_snapshot()).matched is True


def test_run_as_non_root_policy() -> None:
    engine = PolicyEvaluationEngine()
    policy = next(p for p in _k8s_policies() if str(p.id) == "CSPM-K8S-RUN-AS-NON-ROOT-001")
    wl = _workload(
        containers=[
            PodContainer(
                name="web",
                image=ContainerImage.parse("nginx:1.25"),
                allow_privilege_escalation=False,
                read_only_root_filesystem=True,
                run_as_non_root=False,
                image_pull_policy="Always",
            )
        ]
    )
    assert engine.evaluate(policy.rule, wl.posture_snapshot()).matched is True


def test_capabilities_policy() -> None:
    engine = PolicyEvaluationEngine()
    policy = next(p for p in _k8s_policies() if str(p.id) == "CSPM-K8S-CAPABILITIES-001")
    wl = _workload(
        containers=[
            PodContainer(
                name="web",
                image=ContainerImage.parse("nginx:1.25"),
                allow_privilege_escalation=False,
                read_only_root_filesystem=True,
                run_as_non_root=True,
                capabilities_add=("NET_ADMIN",),
                image_pull_policy="Always",
            )
        ]
    )
    assert engine.evaluate(policy.rule, wl.posture_snapshot()).matched is True


def test_latest_tag_policy() -> None:
    engine = PolicyEvaluationEngine()
    policy = next(p for p in _k8s_policies() if str(p.id) == "CSPM-K8S-LATEST-TAG-001")
    wl = _workload(
        containers=[
            PodContainer(
                name="web",
                image=ContainerImage.parse("nginx:latest"),
                allow_privilege_escalation=False,
                read_only_root_filesystem=True,
                run_as_non_root=True,
                image_pull_policy="Always",
            )
        ]
    )
    assert engine.evaluate(policy.rule, wl.posture_snapshot()).matched is True


def test_image_pull_policy() -> None:
    engine = PolicyEvaluationEngine()
    policy = next(p for p in _k8s_policies() if str(p.id) == "CSPM-K8S-IMAGE-PULL-POLICY-001")
    wl = _workload(
        containers=[
            PodContainer(
                name="web",
                image=ContainerImage.parse("nginx:1.25"),
                allow_privilege_escalation=False,
                read_only_root_filesystem=True,
                run_as_non_root=True,
                image_pull_policy="IfNotPresent",
            )
        ]
    )
    assert engine.evaluate(policy.rule, wl.posture_snapshot()).matched is True


def test_public_exposure_policy() -> None:
    engine = PolicyEvaluationEngine()
    policy = next(p for p in _k8s_policies() if str(p.id) == "CSPM-K8S-PUBLIC-EXPOSURE-001")
    wl = _workload(exposure="PUBLIC")
    assert engine.evaluate(policy.rule, wl.posture_snapshot()).matched is True


def test_security_level_privileged_policy() -> None:
    engine = PolicyEvaluationEngine()
    policy = next(p for p in _k8s_policies() if str(p.id) == "CSPM-K8S-SECURITY-LEVEL-001")
    wl = _workload(host_network=True)
    assert wl.security_level.value == "PRIVILEGED"
    assert engine.evaluate(policy.rule, wl.posture_snapshot()).matched is True


def test_secure_workload_passes_most_policies() -> None:
    engine = PolicyEvaluationEngine()
    wl = _workload()
    snap = wl.posture_snapshot()
    # Privileged / host / latest / public should not match a secure baseline workload.
    for pid in (
        "CSPM-K8S-PRIVILEGED-001",
        "CSPM-K8S-HOST-NETWORK-001",
        "CSPM-K8S-LATEST-TAG-001",
        "CSPM-K8S-PUBLIC-EXPOSURE-001",
        "CSPM-K8S-SECURITY-LEVEL-001",
    ):
        policy = next(p for p in _k8s_policies() if str(p.id) == pid)
        assert engine.evaluate(policy.rule, snap).matched is False
