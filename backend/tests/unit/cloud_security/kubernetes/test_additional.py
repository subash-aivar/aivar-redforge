"""Additional Kubernetes domain / service unit coverage."""

from __future__ import annotations

from uuid import uuid4

import pytest

from redforge.domain.cloud_security.kubernetes.entities import (
    NetworkRule,
    PodContainer,
    VolumeMount,
)
from redforge.domain.cloud_security.kubernetes.service import KubernetesService
from redforge.domain.cloud_security.kubernetes.value_objects import (
    ClusterId,
    ContainerImage,
    K8sClusterType,
    K8sNetworkExposure,
    ResourceLimits,
    ResourceRequests,
)
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId

ORG = OrganizationId("01HXORG0000000000000000001")


def test_volume_mount_round_trip() -> None:
    mount = VolumeMount(name="data", mount_path="/data", read_only=True, host_path="/host")
    restored = VolumeMount.from_dict(mount.to_dict())
    assert restored == mount


def test_pod_container_round_trip() -> None:
    container = PodContainer(
        name="app",
        image=ContainerImage.parse("ghcr.io/org/app:1.2.3"),
        privileged=False,
        allow_privilege_escalation=False,
        read_only_root_filesystem=True,
        run_as_non_root=True,
        run_as_user=1000,
        capabilities_add=("NET_BIND_SERVICE",),
        capabilities_drop=("ALL",),
        image_pull_policy="Always",
        requests=ResourceRequests(cpu="100m", memory="128Mi"),
        limits=ResourceLimits(cpu="500m", memory="512Mi"),
        volume_mounts=(VolumeMount(name="tmp", mount_path="/tmp", read_only=False),),
        env_from_secret=True,
    )
    restored = PodContainer.from_dict(container.to_dict())
    assert restored.name == "app"
    assert restored.run_as_user == 1000
    assert restored.env_from_secret is True
    assert restored.image.repository == "ghcr.io/org/app"


def test_pod_container_from_string_image() -> None:
    container = PodContainer.from_dict({"name": "c", "image": "busybox:1.36"})
    assert container.image.tag == "1.36"


def test_network_rule_round_trip() -> None:
    rule = NetworkRule(direction="ingress", peers=("podSelector",), ports=("TCP/80",), allow=True)
    assert NetworkRule.from_dict(rule.to_dict()) == rule


def test_k8s_service_public_detection() -> None:
    cid = ClusterId.new()
    lb = KubernetesService.discover(
        cluster_id=cid,
        organization_id=ORG,
        namespace="default",
        name="lb",
        service_type="LoadBalancer",
        load_balancer_ingress=["a.example.com"],
    )
    assert lb.is_public is True
    assert lb.exposure == K8sNetworkExposure.PUBLIC

    cip = KubernetesService.discover(
        cluster_id=cid,
        organization_id=ORG,
        namespace="default",
        name="cip",
        service_type="ClusterIP",
    )
    assert cip.is_public is False
    assert cip.exposure == K8sNetworkExposure.INTERNAL

    nodeport = KubernetesService.discover(
        cluster_id=cid,
        organization_id=ORG,
        namespace="default",
        name="np",
        service_type="NodePort",
    )
    assert nodeport.is_public is True


def test_k8s_service_rejects_empty_name() -> None:
    from redforge.domain.cloud_security.kubernetes.exceptions import InvalidKubernetesArgumentError

    with pytest.raises(InvalidKubernetesArgumentError):
        KubernetesService.discover(
            cluster_id=ClusterId.new(),
            organization_id=ORG,
            namespace="default",
            name="",
        )


def test_cluster_type_enum_values() -> None:
    assert K8sClusterType.EKS.value == "EKS"
    assert K8sClusterType.AKS.value == "AKS"
    assert K8sClusterType.GKE.value == "GKE"
    assert K8sClusterType.SELF_MANAGED.value == "SELF_MANAGED"


def test_cluster_id_round_trip() -> None:
    cid = ClusterId.new()
    assert ClusterId.from_str(str(cid)).value == cid.value


def test_resource_requests_limits_from_empty() -> None:
    assert ResourceRequests.from_dict(None).cpu == ""
    assert ResourceLimits.from_dict({}).memory == ""


def test_container_image_host_port_path() -> None:
    img = ContainerImage.parse("localhost:5000/app")
    assert img.repository == "localhost:5000/app"
    assert img.tag == "latest"
    assert img.uses_latest_tag is True


def test_fake_inventory_seed_and_clear() -> None:
    import asyncio

    from redforge.infrastructure.cloud_security.kubernetes.fake_inventory import (
        FakeKubernetesInventory,
    )

    inv = FakeKubernetesInventory()
    inv.seed({"kind": "Pod", "metadata": {"name": "p", "namespace": "ns"}})
    assert len(asyncio.run(inv.list_resources())) == 1
    inv.clear()
    assert asyncio.run(inv.list_resources()) == []


def test_mappings_cluster_round_trip() -> None:
    from redforge.domain.cloud_security.kubernetes.cluster import KubernetesCluster
    from redforge.infrastructure.cloud_security.kubernetes.mappings import (
        cluster_from_model,
        cluster_to_model,
    )

    cluster = KubernetesCluster.discover(
        organization_id=ORG,
        cloud_account_id=CloudAccountId(uuid4()),
        cluster_type="GKE",
        name="gke-map",
        version="1.28",
        region="us-central1",
    )
    model = cluster_to_model(cluster)
    restored = cluster_from_model(model)
    assert restored.name == cluster.name
    assert restored.cluster_type == cluster.cluster_type
    assert restored.security_score.value == 100
