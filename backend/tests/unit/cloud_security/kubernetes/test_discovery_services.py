"""Discovery services with FakeKubernetesInventory and in-memory repos."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID, uuid4

import pytest

from redforge.application.cloud_security.kubernetes.admission_policy_evaluation_service import (
    AdmissionPolicyEvaluationService,
)
from redforge.application.cloud_security.kubernetes.cluster_discovery_service import (
    ClusterDiscoveryService,
)
from redforge.application.cloud_security.kubernetes.dtos import (
    DiscoverClusterCommand,
    EvaluateClusterCommand,
)
from redforge.application.cloud_security.kubernetes.inventory_projection_service import (
    InventoryProjectionService,
)
from redforge.application.cloud_security.kubernetes.network_policy_discovery_service import (
    NetworkPolicyDiscoveryService,
)
from redforge.application.cloud_security.kubernetes.posture_evaluation_service import (
    PostureEvaluationService,
)
from redforge.application.cloud_security.kubernetes.rbac_discovery_service import (
    RBACDiscoveryService,
)
from redforge.application.cloud_security.kubernetes.workload_discovery_service import (
    WorkloadDiscoveryService,
)
from redforge.domain.cloud_security.kubernetes.admission_policy import KubernetesAdmissionPolicy
from redforge.domain.cloud_security.kubernetes.cluster import KubernetesCluster
from redforge.domain.cloud_security.kubernetes.namespace import KubernetesNamespace
from redforge.domain.cloud_security.kubernetes.network_policy import KubernetesNetworkPolicy
from redforge.domain.cloud_security.kubernetes.node import KubernetesNode
from redforge.domain.cloud_security.kubernetes.rbac import KubernetesRBACPrincipal
from redforge.domain.cloud_security.kubernetes.service import KubernetesService
from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.cloud_security.kubernetes.fake_inventory import (
    FakeKubernetesInventory,
)

ORG = "01HXORG0000000000000000001"
ACCOUNT = uuid4()


class _MemRepo:
    def __init__(self) -> None:
        self.items: dict[UUID, Any] = {}

    async def save(self, entity: Any) -> None:
        self.items[entity.id.value] = entity

    async def save_batch(self, entities: list[Any]) -> None:
        for e in entities:
            await self.save(e)

    async def get_by_id(self, entity_id: UUID, *, organization_id: OrganizationId) -> Any | None:
        item = self.items.get(entity_id)
        if item is None:
            return None
        if str(item.organization_id) != str(organization_id):
            return None
        return item

    async def get_by_name(self, *, organization_id: OrganizationId, name: str) -> Any | None:
        for item in self.items.values():
            if str(item.organization_id) == str(organization_id) and getattr(item, "name", None) == name:
                return item
        return None

    async def list_by_organization(
        self, organization_id: OrganizationId, *, limit: int = 100, offset: int = 0
    ) -> list[Any]:
        items = [i for i in self.items.values() if str(i.organization_id) == str(organization_id)]
        return items[offset : offset + limit]

    async def list_by_cluster(
        self,
        cluster_id: UUID,
        *,
        organization_id: OrganizationId,
        namespace: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[Any]:
        items = [
            i
            for i in self.items.values()
            if getattr(i, "cluster_id", None) is not None
            and i.cluster_id.value == cluster_id
            and str(i.organization_id) == str(organization_id)
            and (namespace is None or getattr(i, "namespace", None) == namespace)
        ]
        return items[offset : offset + limit]


class _FakeSession:
    pass


@asynccontextmanager
async def _session_factory():
    yield _FakeSession()


class _UowPatch:
    """Patch SessionUnitOfWork to use a no-op session context for unit tests."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Uow:
            def __init__(self, _factory: Any) -> None:
                self.session = _FakeSession()

            async def __aenter__(self) -> _Uow:
                return self

            async def __aexit__(self, *args: object) -> None:
                return None

            async def commit(self) -> None:
                return None

        monkeypatch.setattr(
            "redforge.application.cloud_security.kubernetes.cluster_discovery_service.SessionUnitOfWork",
            _Uow,
        )
        monkeypatch.setattr(
            "redforge.application.cloud_security.kubernetes.workload_discovery_service.SessionUnitOfWork",
            _Uow,
        )
        monkeypatch.setattr(
            "redforge.application.cloud_security.kubernetes.rbac_discovery_service.SessionUnitOfWork",
            _Uow,
        )
        monkeypatch.setattr(
            "redforge.application.cloud_security.kubernetes.network_policy_discovery_service.SessionUnitOfWork",
            _Uow,
        )
        monkeypatch.setattr(
            "redforge.application.cloud_security.kubernetes.inventory_projection_service.SessionUnitOfWork",
            _Uow,
        )
        monkeypatch.setattr(
            "redforge.application.cloud_security.kubernetes.posture_evaluation_service.SessionUnitOfWork",
            _Uow,
        )
        monkeypatch.setattr(
            "redforge.application.cloud_security.kubernetes.admission_policy_evaluation_service.SessionUnitOfWork",
            _Uow,
        )


def _seed_inventory() -> FakeKubernetesInventory:
    inv = FakeKubernetesInventory(
        cluster_info={
            "name": "dev-eks",
            "version": "1.29.0",
            "cluster_type": "EKS",
            "api_server_endpoint": "https://127.0.0.1",
            "region": "us-east-1",
        }
    )
    inv.seed_many(
        [
            {"kind": "Namespace", "metadata": {"name": "default"}},
            {
                "kind": "Deployment",
                "metadata": {"name": "web", "namespace": "default"},
                "spec": {
                    "replicas": 2,
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "web",
                                    "image": "nginx:latest",
                                    "securityContext": {"privileged": True},
                                }
                            ]
                        }
                    },
                },
            },
            {
                "kind": "Service",
                "metadata": {"name": "web", "namespace": "default"},
                "spec": {"type": "LoadBalancer", "ports": [{"port": 80}]},
            },
            {
                "kind": "NetworkPolicy",
                "metadata": {"name": "deny", "namespace": "default"},
                "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
            },
            {
                "kind": "ServiceAccount",
                "metadata": {"name": "default", "namespace": "default"},
            },
            {
                "kind": "ClusterRole",
                "metadata": {"name": "view"},
                "rules": [{"verbs": ["get"], "resources": ["pods"]}],
            },
            {
                "kind": "ClusterRoleBinding",
                "metadata": {"name": "view-binding"},
                "roleRef": {"kind": "ClusterRole", "name": "view"},
                "subjects": [
                    {"kind": "ServiceAccount", "name": "default", "namespace": "default"}
                ],
            },
            {
                "kind": "Node",
                "metadata": {"name": "node-1"},
                "status": {"nodeInfo": {"kubeletVersion": "v1.29.0"}},
            },
        ]
    )
    return inv


@pytest.fixture
def repos() -> dict[str, _MemRepo]:
    return {
        "cluster": _MemRepo(),
        "workload": _MemRepo(),
        "namespace": _MemRepo(),
        "node": _MemRepo(),
        "service": _MemRepo(),
        "rbac": _MemRepo(),
        "network": _MemRepo(),
        "admission": _MemRepo(),
    }


@pytest.mark.asyncio
async def test_cluster_discovery(monkeypatch: pytest.MonkeyPatch, repos: dict[str, _MemRepo]) -> None:
    _UowPatch(monkeypatch)
    inv = _seed_inventory()
    svc = ClusterDiscoveryService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        inventory=inv,
    )
    dto = await svc.discover(
        DiscoverClusterCommand(
            organization_id=ORG,
            cloud_account_id=ACCOUNT,
            sync_inventory=False,
        )
    )
    assert dto.name == "dev-eks"
    assert len(repos["cluster"].items) == 1
    listed = await svc.list_clusters(ORG)
    assert len(listed) == 1
    got = await svc.get(ORG, dto.cluster_id)
    assert got.cluster_id == dto.cluster_id


@pytest.mark.asyncio
async def test_workload_discovery(monkeypatch: pytest.MonkeyPatch, repos: dict[str, _MemRepo]) -> None:
    _UowPatch(monkeypatch)
    inv = _seed_inventory()
    cluster_svc = ClusterDiscoveryService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        inventory=inv,
    )
    cluster = await cluster_svc.discover(
        DiscoverClusterCommand(organization_id=ORG, cloud_account_id=ACCOUNT, sync_inventory=False)
    )
    wl_svc = WorkloadDiscoveryService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        workload_repo_factory=lambda _s: repos["workload"],
        inventory=inv,
    )
    workloads = await wl_svc.discover(
        organization_id=ORG, cluster_id=UUID(cluster.cluster_id)
    )
    assert len(workloads) == 1
    assert workloads[0].privileged is True
    listed = await wl_svc.list_workloads(
        organization_id=ORG, cluster_id=UUID(cluster.cluster_id)
    )
    assert len(listed) == 1
    got = await wl_svc.get_workload(
        organization_id=ORG,
        cluster_id=UUID(cluster.cluster_id),
        workload_id=UUID(workloads[0].workload_id),
    )
    assert got.name == "web"


@pytest.mark.asyncio
async def test_rbac_discovery(monkeypatch: pytest.MonkeyPatch, repos: dict[str, _MemRepo]) -> None:
    _UowPatch(monkeypatch)
    inv = _seed_inventory()
    cluster = await ClusterDiscoveryService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        inventory=inv,
    ).discover(DiscoverClusterCommand(organization_id=ORG, cloud_account_id=ACCOUNT, sync_inventory=False))
    svc = RBACDiscoveryService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        rbac_repo_factory=lambda _s: repos["rbac"],
        inventory=inv,
    )
    principals = await svc.discover(
        organization_id=ORG, cluster_id=UUID(cluster.cluster_id)
    )
    assert len(principals) >= 1
    listed = await svc.list_rbac(organization_id=ORG, cluster_id=UUID(cluster.cluster_id))
    assert len(listed) >= 1


@pytest.mark.asyncio
async def test_network_policy_discovery(
    monkeypatch: pytest.MonkeyPatch, repos: dict[str, _MemRepo]
) -> None:
    _UowPatch(monkeypatch)
    inv = _seed_inventory()
    cluster = await ClusterDiscoveryService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        inventory=inv,
    ).discover(DiscoverClusterCommand(organization_id=ORG, cloud_account_id=ACCOUNT, sync_inventory=False))
    svc = NetworkPolicyDiscoveryService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        network_policy_repo_factory=lambda _s: repos["network"],
        inventory=inv,
    )
    policies = await svc.discover(
        organization_id=ORG, cluster_id=UUID(cluster.cluster_id)
    )
    assert len(policies) == 1
    listed = await svc.list_policies(organization_id=ORG, cluster_id=UUID(cluster.cluster_id))
    assert listed[0].name == "deny"


@pytest.mark.asyncio
async def test_inventory_projection_full_sync(
    monkeypatch: pytest.MonkeyPatch, repos: dict[str, _MemRepo]
) -> None:
    _UowPatch(monkeypatch)
    inv = _seed_inventory()
    cluster = await ClusterDiscoveryService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        inventory=inv,
    ).discover(DiscoverClusterCommand(organization_id=ORG, cloud_account_id=ACCOUNT, sync_inventory=False))
    svc = InventoryProjectionService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        namespace_repo_factory=lambda _s: repos["namespace"],
        workload_repo_factory=lambda _s: repos["workload"],
        node_repo_factory=lambda _s: repos["node"],
        service_repo_factory=lambda _s: repos["service"],
        rbac_repo_factory=lambda _s: repos["rbac"],
        network_policy_repo_factory=lambda _s: repos["network"],
        admission_repo_factory=lambda _s: repos["admission"],
        inventory=inv,
    )
    summary = await svc.sync(organization_id=ORG, cluster_id=UUID(cluster.cluster_id))
    assert summary["workloads"] == 1
    assert summary["namespaces"] == 1
    assert summary["services"] == 1
    assert summary["nodes"] == 1
    assert summary["network_policies"] == 1


@pytest.mark.asyncio
async def test_posture_evaluation(
    monkeypatch: pytest.MonkeyPatch, repos: dict[str, _MemRepo]
) -> None:
    _UowPatch(monkeypatch)
    inv = _seed_inventory()
    cluster = await ClusterDiscoveryService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        inventory=inv,
    ).discover(DiscoverClusterCommand(organization_id=ORG, cloud_account_id=ACCOUNT, sync_inventory=False))
    await WorkloadDiscoveryService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        workload_repo_factory=lambda _s: repos["workload"],
        inventory=inv,
    ).discover(organization_id=ORG, cluster_id=UUID(cluster.cluster_id))
    posture = PostureEvaluationService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        workload_repo_factory=lambda _s: repos["workload"],
        namespace_repo_factory=lambda _s: repos["namespace"],
        rbac_repo_factory=lambda _s: repos["rbac"],
    )
    result = await posture.evaluate(
        EvaluateClusterCommand(organization_id=ORG, cluster_id=UUID(cluster.cluster_id))
    )
    assert result.workloads_evaluated == 1
    assert result.policies_evaluated >= 12
    assert len(result.violations) >= 1
    events = posture.pop_events()
    assert len(events) >= 1
    summary = await posture.compliance_summary(
        organization_id=ORG, cluster_id=UUID(cluster.cluster_id)
    )
    assert summary.workload_count == 1
    assert summary.privileged_count == 1


@pytest.mark.asyncio
async def test_admission_evaluation(
    monkeypatch: pytest.MonkeyPatch, repos: dict[str, _MemRepo]
) -> None:
    _UowPatch(monkeypatch)
    inv = _seed_inventory()
    cluster = await ClusterDiscoveryService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        inventory=inv,
    ).discover(DiscoverClusterCommand(organization_id=ORG, cloud_account_id=ACCOUNT, sync_inventory=False))
    await WorkloadDiscoveryService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        workload_repo_factory=lambda _s: repos["workload"],
        inventory=inv,
    ).discover(organization_id=ORG, cluster_id=UUID(cluster.cluster_id))
    svc = AdmissionPolicyEvaluationService(
        _session_factory,
        cluster_repo_factory=lambda _s: repos["cluster"],
        admission_repo_factory=lambda _s: repos["admission"],
        workload_repo_factory=lambda _s: repos["workload"],
    )
    results = await svc.evaluate(organization_id=ORG, cluster_id=UUID(cluster.cluster_id))
    assert len(results) == 1
    assert results[0]["violation_count"] >= 1
    assert results[0]["events"]


def test_fake_inventory_filters_by_kind_and_namespace() -> None:
    inv = _seed_inventory()

    async def _run() -> None:
        all_res = await inv.list_resources()
        assert len(all_res) >= 5
        deps = await inv.list_resources(kinds=["Deployment"])
        assert all(r["kind"] == "Deployment" for r in deps)
        scoped = await inv.list_resources(kinds=["Deployment"], namespace="default")
        assert len(scoped) == 1
        info = await inv.get_cluster_info()
        assert info["name"] == "dev-eks"

    import asyncio

    asyncio.run(_run())


def test_mem_repo_type_coverage() -> None:
    # Ensure domain types used by repos remain importable for discovery tests.
    assert KubernetesCluster is not None
    assert KubernetesWorkload is not None
    assert KubernetesNamespace is not None
    assert KubernetesNode is not None
    assert KubernetesService is not None
    assert KubernetesRBACPrincipal is not None
    assert KubernetesNetworkPolicy is not None
    assert KubernetesAdmissionPolicy is not None
