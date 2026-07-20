"""Normalization service unit tests."""

from __future__ import annotations

from uuid import uuid4

from redforge.application.cloud_security.kubernetes.normalization_service import (
    KubernetesNormalizationService,
)
from redforge.domain.cloud_security.kubernetes.value_objects import ClusterId, WorkloadKind
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId

ORG = OrganizationId("01HXORG0000000000000000001")
ACCOUNT = CloudAccountId(uuid4())


def test_normalize_cluster_info() -> None:
    svc = KubernetesNormalizationService()
    cluster = svc.normalize_cluster(
        {
            "name": "eks-prod",
            "version": "1.29.2",
            "cluster_type": "eks",
            "api_server_endpoint": "https://eks.example",
            "region": "us-east-1",
            "labels": {"env": "prod"},
        },
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
    )
    assert cluster.name == "eks-prod"
    assert cluster.cluster_type.value == "EKS"
    assert cluster.labels["env"] == "prod"


def test_normalize_namespace() -> None:
    svc = KubernetesNormalizationService()
    cid = ClusterId.new()
    result = svc.normalize_resources(
        [
            {
                "kind": "Namespace",
                "metadata": {
                    "name": "payments",
                    "labels": {"team": "pay"},
                    "annotations": {"pod-security.kubernetes.io/enforce": "restricted"},
                },
            }
        ],
        cluster_id=cid,
        organization_id=ORG,
    )
    assert len(result.namespaces) == 1
    assert result.namespaces[0].pod_security_level == "RESTRICTED"


def test_normalize_deployment_workload() -> None:
    svc = KubernetesNormalizationService()
    cid = ClusterId.new()
    result = svc.normalize_resources(
        [
            {
                "kind": "Deployment",
                "metadata": {"name": "web", "namespace": "default", "uid": "u1"},
                "spec": {
                    "replicas": 3,
                    "template": {
                        "spec": {
                            "serviceAccountName": "web-sa",
                            "hostNetwork": True,
                            "containers": [
                                {
                                    "name": "web",
                                    "image": "nginx:latest",
                                    "imagePullPolicy": "IfNotPresent",
                                    "securityContext": {
                                        "privileged": True,
                                        "allowPrivilegeEscalation": True,
                                        "capabilities": {"add": ["NET_ADMIN"]},
                                    },
                                }
                            ],
                        }
                    },
                },
            }
        ],
        cluster_id=cid,
        organization_id=ORG,
    )
    assert len(result.workloads) == 1
    wl = result.workloads[0]
    assert wl.kind == WorkloadKind.DEPLOYMENT
    assert wl.privileged is True
    assert wl.host_network is True
    assert wl.service_account.name == "web-sa"
    assert wl.containers[0].image.uses_latest_tag is True
    assert "NET_ADMIN" in wl.containers[0].capabilities_add


def test_normalize_statefulset_daemonset_job_cronjob_pod() -> None:
    svc = KubernetesNormalizationService()
    cid = ClusterId.new()
    kinds = [
        ("StatefulSet", WorkloadKind.STATEFULSET),
        ("DaemonSet", WorkloadKind.DAEMONSET),
        ("Job", WorkloadKind.JOB),
        ("Pod", WorkloadKind.POD),
    ]
    resources = []
    for kind, _ in kinds:
        if kind == "Pod":
            resources.append(
                {
                    "kind": kind,
                    "metadata": {"name": kind.lower(), "namespace": "ns"},
                    "spec": {"containers": [{"name": "c", "image": "busybox:1.36"}]},
                }
            )
        else:
            resources.append(
                {
                    "kind": kind,
                    "metadata": {"name": kind.lower(), "namespace": "ns"},
                    "spec": {
                        "template": {
                            "spec": {"containers": [{"name": "c", "image": "busybox:1.36"}]}
                        }
                    },
                }
            )
    resources.append(
        {
            "kind": "CronJob",
            "metadata": {"name": "cron", "namespace": "ns"},
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {"containers": [{"name": "c", "image": "busybox:1.36"}]}
                        }
                    }
                }
            },
        }
    )
    result = svc.normalize_resources(resources, cluster_id=cid, organization_id=ORG)
    assert len(result.workloads) == 5


def test_normalize_node() -> None:
    svc = KubernetesNormalizationService()
    cid = ClusterId.new()
    result = svc.normalize_resources(
        [
            {
                "kind": "Node",
                "metadata": {
                    "name": "ip-10-0-1-5",
                    "labels": {"node-role.kubernetes.io/control-plane": ""},
                },
                "spec": {"unschedulable": False, "taints": [{"key": "node-role", "effect": "NoSchedule"}]},
                "status": {
                    "nodeInfo": {
                        "kubeletVersion": "v1.29.0",
                        "osImage": "Amazon Linux 2",
                        "containerRuntimeVersion": "containerd://1.7",
                    }
                },
            }
        ],
        cluster_id=cid,
        organization_id=ORG,
    )
    assert len(result.nodes) == 1
    assert "control-plane" in result.nodes[0].roles


def test_normalize_public_service() -> None:
    svc = KubernetesNormalizationService()
    cid = ClusterId.new()
    result = svc.normalize_resources(
        [
            {
                "kind": "Service",
                "metadata": {"name": "web", "namespace": "default"},
                "spec": {
                    "type": "LoadBalancer",
                    "clusterIP": "10.0.0.10",
                    "ports": [{"port": 80, "protocol": "TCP"}],
                    "selector": {"app": "web"},
                },
                "status": {"loadBalancer": {"ingress": [{"hostname": "elb.amazonaws.com"}]}},
            },
            {
                "kind": "Deployment",
                "metadata": {"name": "web", "namespace": "default"},
                "spec": {
                    "template": {
                        "spec": {"containers": [{"name": "c", "image": "nginx:1.25"}]}
                    }
                },
            },
        ],
        cluster_id=cid,
        organization_id=ORG,
    )
    assert result.services[0].is_public is True
    assert result.workloads[0].exposure.value == "PUBLIC"


def test_normalize_network_policy_marks_namespace() -> None:
    svc = KubernetesNormalizationService()
    cid = ClusterId.new()
    result = svc.normalize_resources(
        [
            {"kind": "Namespace", "metadata": {"name": "default"}},
            {
                "kind": "NetworkPolicy",
                "metadata": {"name": "deny", "namespace": "default"},
                "spec": {
                    "podSelector": {"matchLabels": {"app": "web"}},
                    "policyTypes": ["Ingress"],
                    "ingress": [{"from": [{"namespaceSelector": {}}]}],
                },
            },
        ],
        cluster_id=cid,
        organization_id=ORG,
    )
    assert len(result.network_policies) == 1
    assert result.network_policies[0].allows_cross_namespace is True
    assert result.namespaces[0].has_network_policy is True


def test_normalize_rbac_bindings() -> None:
    svc = KubernetesNormalizationService()
    cid = ClusterId.new()
    result = svc.normalize_resources(
        [
            {
                "kind": "ServiceAccount",
                "metadata": {"name": "deployer", "namespace": "default"},
            },
            {
                "kind": "ClusterRole",
                "metadata": {"name": "cluster-admin"},
                "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}],
            },
            {
                "kind": "ClusterRoleBinding",
                "metadata": {"name": "deployer-admin"},
                "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                "subjects": [
                    {"kind": "ServiceAccount", "name": "deployer", "namespace": "default"}
                ],
            },
        ],
        cluster_id=cid,
        organization_id=ORG,
    )
    assert len(result.rbac_principals) >= 1
    deployer = next(p for p in result.rbac_principals if p.name == "deployer")
    assert "cluster-admin" in deployer.cluster_roles
    assert deployer.inventory_dict()["bound_cluster_admin"] is True


def test_normalize_metadata_only_resources() -> None:
    svc = KubernetesNormalizationService()
    cid = ClusterId.new()
    result = svc.normalize_resources(
        [
            {"kind": "ConfigMap", "metadata": {"name": "cfg", "namespace": "default"}},
            {"kind": "Secret", "metadata": {"name": "sec", "namespace": "default"}},
            {"kind": "PersistentVolume", "metadata": {"name": "pv1"}},
            {"kind": "PersistentVolumeClaim", "metadata": {"name": "pvc1", "namespace": "default"}},
            {"kind": "PodDisruptionBudget", "metadata": {"name": "pdb", "namespace": "default"}},
            {
                "kind": "HorizontalPodAutoscaler",
                "metadata": {"name": "hpa", "namespace": "default"},
            },
        ],
        cluster_id=cid,
        organization_id=ORG,
    )
    assert len(result.metadata_only) == 6


def test_normalize_admission_webhooks() -> None:
    svc = KubernetesNormalizationService()
    cid = ClusterId.new()
    result = svc.normalize_resources(
        [
            {
                "kind": "ValidatingWebhookConfiguration",
                "metadata": {"name": "pss"},
                "webhooks": [{"name": "validate.pods", "failurePolicy": "Fail"}],
            }
        ],
        cluster_id=cid,
        organization_id=ORG,
    )
    assert len(result.admission_policies) == 1
    assert result.admission_policies[0].controller == "ValidatingWebhookConfiguration"


def test_normalize_ingress_exposure_metadata() -> None:
    svc = KubernetesNormalizationService()
    cid = ClusterId.new()
    result = svc.normalize_resources(
        [
            {
                "kind": "Ingress",
                "metadata": {"name": "web", "namespace": "default"},
                "spec": {
                    "rules": [
                        {
                            "http": {
                                "paths": [
                                    {
                                        "backend": {
                                            "service": {"name": "web", "port": {"number": 80}}
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                },
            }
        ],
        cluster_id=cid,
        organization_id=ORG,
    )
    assert result.ingress_exposure["default/web"] == "PUBLIC"
