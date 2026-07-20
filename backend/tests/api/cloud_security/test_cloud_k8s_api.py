"""API tests for M26 Phase 5 Kubernetes Security endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from redforge.api.security import TenantContext, get_tenant_context
from redforge.api.v1.cloud_k8s import router as cloud_k8s_router
from redforge.application.cloud_security.kubernetes.dtos import (
    ClusterDTO,
    ComplianceSummaryDTO,
    EvaluationResultDTO,
    NamespaceDTO,
    NetworkPolicyDTO,
    RBACPrincipalDTO,
    ViolationResultDTO,
    WorkloadDTO,
)
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware

ORG = "01HXORG0000000000000000001"
ACCOUNT = uuid4()
CLUSTER = uuid4()
WORKLOAD = uuid4()
NOW = datetime.now(UTC)


def _cluster_dto() -> ClusterDTO:
    return ClusterDTO(
        cluster_id=str(CLUSTER),
        organization_id=ORG,
        cloud_account_id=str(ACCOUNT),
        cloud_asset_id=None,
        cluster_type="EKS",
        name="dev-eks",
        version="1.29.0",
        api_server_endpoint="https://127.0.0.1",
        region="us-east-1",
        security_score={"value": 80, "findings_open": 2, "workloads_evaluated": 1, "coverage_ratio": 1.0},
        labels={},
        pod_security_standards={},
        discovered_at=NOW,
        last_synced_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )


class _FakeK8sService:
    def __init__(self) -> None:
        self.cluster = _cluster_dto()

    async def discover_cluster(self, command: Any) -> ClusterDTO:
        return self.cluster

    async def list_clusters(self, organization_id: str, *, limit: int = 100, offset: int = 0) -> list[ClusterDTO]:
        return [self.cluster]

    async def get_cluster(self, organization_id: str, cluster_id: Any) -> ClusterDTO:
        return self.cluster

    async def list_namespaces(self, organization_id: str, cluster_id: Any) -> list[NamespaceDTO]:
        return [
            NamespaceDTO(
                namespace_id=str(uuid4()),
                cluster_id=str(CLUSTER),
                name="default",
                pod_security_level="BASELINE",
                has_network_policy=True,
                labels={},
            )
        ]

    async def list_workloads(
        self,
        organization_id: str,
        cluster_id: Any,
        *,
        namespace: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[WorkloadDTO]:
        return [
            WorkloadDTO(
                workload_id=str(WORKLOAD),
                cluster_id=str(CLUSTER),
                namespace="default",
                name="web",
                kind="DEPLOYMENT",
                privileged=True,
                host_network=False,
                host_pid=False,
                host_ipc=False,
                security_level="PRIVILEGED",
                exposure="PUBLIC",
                replicas=2,
                containers=[],
                service_account={"name": "default", "namespace": "default"},
                posture_snapshot={"asset_type": "K8S_WORKLOAD"},
            )
        ]

    async def get_workload(
        self, organization_id: str, cluster_id: Any, workload_id: Any
    ) -> WorkloadDTO:
        return (await self.list_workloads(organization_id, cluster_id))[0]

    async def list_rbac(self, organization_id: str, cluster_id: Any) -> list[RBACPrincipalDTO]:
        return [
            RBACPrincipalDTO(
                principal_id=str(uuid4()),
                cluster_id=str(CLUSTER),
                kind="SERVICE_ACCOUNT",
                name="default",
                namespace="default",
                inventory={"has_wildcard_verb": False},
            )
        ]

    async def list_network_policies(
        self, organization_id: str, cluster_id: Any
    ) -> list[NetworkPolicyDTO]:
        return [
            NetworkPolicyDTO(
                policy_id=str(uuid4()),
                cluster_id=str(CLUSTER),
                namespace="default",
                name="deny",
                policy_types=["Ingress"],
                allows_cross_namespace=False,
                pod_selector={},
            )
        ]

    async def evaluate_cluster(self, command: Any) -> EvaluationResultDTO:
        return EvaluationResultDTO(
            cluster_id=str(CLUSTER),
            workloads_evaluated=1,
            policies_evaluated=12,
            violations=[
                ViolationResultDTO(
                    workload_id=str(WORKLOAD),
                    policy_id="CSPM-K8S-PRIVILEGED-001",
                    rule_id="K8S_PRIVILEGED_CONTAINER",
                    severity="CRITICAL",
                    title="Privileged",
                    message="privileged",
                    passed=False,
                )
            ],
            security_score={"value": 70},
        )

    async def compliance_summary(
        self, organization_id: str, cluster_id: Any
    ) -> ComplianceSummaryDTO:
        return ComplianceSummaryDTO(
            cluster_id=str(CLUSTER),
            security_score={"value": 70},
            workload_count=1,
            privileged_count=1,
            public_exposure_count=1,
            namespaces_without_network_policy=0,
            rbac_wildcard_count=0,
        )


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    application.add_middleware(ErrorHandlerMiddleware)
    application.include_router(cloud_k8s_router, prefix="/api/v1")
    fake = _FakeK8sService()

    async def _tenant() -> TenantContext:
        return TenantContext(
            user_id="01HXUSER000000000000000001",
            email="owner@example.com",
            organization_id=ORG,
            role=MembershipRole.OWNER,
            permissions=frozenset(ROLE_PERMISSIONS[MembershipRole.OWNER]),
        )

    class _OrgStub:
        async def get_by_id(self, organization_id: str) -> object:
            class _Org:
                status = "active"

            return _Org()

    from redforge.api.dependencies import (
        get_kubernetes_security_service,
        get_organization_service,
    )

    application.dependency_overrides[get_tenant_context] = _tenant
    application.dependency_overrides[get_kubernetes_security_service] = lambda: fake
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return application


@pytest.fixture
async def client(app: FastAPI):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_discover_cluster(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/cloud-foundation/k8s/clusters/discover",
        json={"cloud_account_id": str(ACCOUNT), "sync_inventory": False},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "dev-eks"
    assert body["cluster_type"] == "EKS"


@pytest.mark.asyncio
async def test_list_clusters(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/cloud-foundation/k8s/clusters")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


@pytest.mark.asyncio
async def test_get_cluster(client: AsyncClient) -> None:
    resp = await client.get(f"/api/v1/cloud-foundation/k8s/clusters/{CLUSTER}")
    assert resp.status_code == 200
    assert resp.json()["cluster_id"] == str(CLUSTER)


@pytest.mark.asyncio
async def test_list_namespaces(client: AsyncClient) -> None:
    resp = await client.get(f"/api/v1/cloud-foundation/k8s/clusters/{CLUSTER}/namespaces")
    assert resp.status_code == 200
    assert resp.json()[0]["name"] == "default"


@pytest.mark.asyncio
async def test_list_workloads(client: AsyncClient) -> None:
    resp = await client.get(f"/api/v1/cloud-foundation/k8s/clusters/{CLUSTER}/workloads")
    assert resp.status_code == 200
    assert resp.json()[0]["privileged"] is True


@pytest.mark.asyncio
async def test_get_workload(client: AsyncClient) -> None:
    resp = await client.get(
        f"/api/v1/cloud-foundation/k8s/clusters/{CLUSTER}/workloads/{WORKLOAD}"
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "web"


@pytest.mark.asyncio
async def test_list_rbac(client: AsyncClient) -> None:
    resp = await client.get(f"/api/v1/cloud-foundation/k8s/clusters/{CLUSTER}/rbac")
    assert resp.status_code == 200
    assert resp.json()[0]["kind"] == "SERVICE_ACCOUNT"


@pytest.mark.asyncio
async def test_list_network_policies(client: AsyncClient) -> None:
    resp = await client.get(
        f"/api/v1/cloud-foundation/k8s/clusters/{CLUSTER}/network-policies"
    )
    assert resp.status_code == 200
    assert resp.json()[0]["name"] == "deny"


@pytest.mark.asyncio
async def test_evaluate_cluster(client: AsyncClient) -> None:
    resp = await client.post(f"/api/v1/cloud-foundation/k8s/clusters/{CLUSTER}/evaluate")
    assert resp.status_code == 200
    body = resp.json()
    assert body["workloads_evaluated"] == 1
    assert len(body["violations"]) == 1


@pytest.mark.asyncio
async def test_compliance_summary(client: AsyncClient) -> None:
    resp = await client.get(
        f"/api/v1/cloud-foundation/k8s/clusters/{CLUSTER}/compliance-summary"
    )
    assert resp.status_code == 200
    assert resp.json()["privileged_count"] == 1
