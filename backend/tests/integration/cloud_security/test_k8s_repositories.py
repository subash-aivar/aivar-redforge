"""PostgreSQL integration tests for Kubernetes security repositories."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from ulid import ULID

from redforge.domain.cloud_security.kubernetes.admission_policy import KubernetesAdmissionPolicy
from redforge.domain.cloud_security.kubernetes.cluster import KubernetesCluster
from redforge.domain.cloud_security.kubernetes.entities import (
    AdmissionViolation,
    PodContainer,
)
from redforge.domain.cloud_security.kubernetes.namespace import KubernetesNamespace
from redforge.domain.cloud_security.kubernetes.network_policy import KubernetesNetworkPolicy
from redforge.domain.cloud_security.kubernetes.node import KubernetesNode
from redforge.domain.cloud_security.kubernetes.rbac import KubernetesRBACPrincipal
from redforge.domain.cloud_security.kubernetes.service import KubernetesService
from redforge.domain.cloud_security.kubernetes.value_objects import ContainerImage
from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId
from redforge.infrastructure.cloud_security.kubernetes.repositories import (
    PgKubernetesAdmissionPolicyRepository,
    PgKubernetesClusterRepository,
    PgKubernetesNamespaceRepository,
    PgKubernetesNetworkPolicyRepository,
    PgKubernetesNodeRepository,
    PgKubernetesRBACRepository,
    PgKubernetesServiceRepository,
    PgKubernetesWorkloadRepository,
)

pytestmark = pytest.mark.integration

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


@pytest.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    if not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("TEST_DATABASE_URL not set")
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_k8s_repositories_round_trip(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    org = OrganizationId(str(ULID()))
    account_id = CloudAccountId(uuid4())
    async with session_factory() as session, session.begin():
        clusters = PgKubernetesClusterRepository(session)
        namespaces = PgKubernetesNamespaceRepository(session)
        workloads = PgKubernetesWorkloadRepository(session)
        nodes = PgKubernetesNodeRepository(session)
        services = PgKubernetesServiceRepository(session)
        rbac = PgKubernetesRBACRepository(session)
        network = PgKubernetesNetworkPolicyRepository(session)
        admission = PgKubernetesAdmissionPolicyRepository(session)

        cluster = KubernetesCluster.discover(
            organization_id=org,
            cloud_account_id=account_id,
            cluster_type="EKS",
            name=f"cluster-{uuid4().hex[:8]}",
            version="1.29.0",
            region="us-east-1",
        )
        await clusters.save(cluster)

        loaded = await clusters.get_by_id(cluster.id.value, organization_id=org)
        assert loaded is not None
        assert loaded.name == cluster.name

        by_name = await clusters.get_by_name(organization_id=org, name=cluster.name)
        assert by_name is not None

        listed = await clusters.list_by_organization(org)
        assert any(c.id.value == cluster.id.value for c in listed)

        ns = KubernetesNamespace.discover(
            cluster_id=cluster.id, organization_id=org, name="default"
        )
        await namespaces.save(ns)
        assert len(await namespaces.list_by_cluster(cluster.id.value, organization_id=org)) == 1

        wl = KubernetesWorkload.discover(
            cluster_id=cluster.id,
            organization_id=org,
            namespace="default",
            name="web",
            kind="DEPLOYMENT",
            containers=[
                PodContainer(
                    name="web",
                    image=ContainerImage.parse("nginx:1.25"),
                    privileged=True,
                )
            ],
        )
        await workloads.save(wl)
        got_wl = await workloads.get_by_id(wl.id.value, organization_id=org)
        assert got_wl is not None
        assert got_wl.privileged is True
        assert len(await workloads.list_by_cluster(cluster.id.value, organization_id=org)) == 1

        node = KubernetesNode.discover(
            cluster_id=cluster.id, organization_id=org, name="node-1", kubelet_version="v1.29.0"
        )
        await nodes.save(node)
        assert len(await nodes.list_by_cluster(cluster.id.value, organization_id=org)) == 1

        svc = KubernetesService.discover(
            cluster_id=cluster.id,
            organization_id=org,
            namespace="default",
            name="web",
            service_type="LoadBalancer",
        )
        await services.save(svc)
        assert (await services.list_by_cluster(cluster.id.value, organization_id=org))[0].is_public

        principal = KubernetesRBACPrincipal.discover(
            cluster_id=cluster.id,
            organization_id=org,
            kind="SERVICE_ACCOUNT",
            name="default",
            namespace="default",
        )
        await rbac.save(principal)
        assert len(await rbac.list_by_cluster(cluster.id.value, organization_id=org)) == 1

        np = KubernetesNetworkPolicy.discover(
            cluster_id=cluster.id,
            organization_id=org,
            namespace="default",
            name="deny-all",
        )
        await network.save(np)
        assert len(await network.list_by_cluster(cluster.id.value, organization_id=org)) == 1

        adm = KubernetesAdmissionPolicy.register(
            cluster_id=cluster.id,
            organization_id=org,
            name="pss",
            mode="AUDIT",
            controller="PodSecurity",
        )
        adm.record_evaluation(
            violations=[
                AdmissionViolation(
                    rule_id="x",
                    message="m",
                    resource_kind="Deployment",
                    resource_name="web",
                )
            ]
        )
        await admission.save(adm)
        loaded_adm = await admission.list_by_cluster(cluster.id.value, organization_id=org)
        assert len(loaded_adm) == 1
        assert loaded_adm[0].violations[0].rule_id == "x"

        # Update cluster security score and re-save
        from redforge.domain.cloud_security.kubernetes.value_objects import K8sSecurityScore

        cluster.update_security_score(
            K8sSecurityScore.compute(workloads_evaluated=1, violation_count=1, critical_count=1)
        )
        await clusters.save(cluster)
        reloaded = await clusters.get_by_id(cluster.id.value, organization_id=org)
        assert reloaded is not None
        assert reloaded.security_score.findings_open == 1


@pytest.mark.asyncio
async def test_k8s_workload_batch_save(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    org = OrganizationId(str(ULID()))
    account_id = CloudAccountId(uuid4())
    async with session_factory() as session, session.begin():
        clusters = PgKubernetesClusterRepository(session)
        workloads = PgKubernetesWorkloadRepository(session)
        cluster = KubernetesCluster.discover(
            organization_id=org,
            cloud_account_id=account_id,
            cluster_type="AKS",
            name=f"aks-{uuid4().hex[:8]}",
            version="1.28",
        )
        await clusters.save(cluster)
        batch = [
            KubernetesWorkload.discover(
                cluster_id=cluster.id,
                organization_id=org,
                namespace="ns",
                name=f"app-{i}",
                kind="DEPLOYMENT",
                containers=[
                    PodContainer(name="c", image=ContainerImage.parse(f"app:{i}"))
                ],
            )
            for i in range(3)
        ]
        await workloads.save_batch(batch)
        listed = await workloads.list_by_cluster(cluster.id.value, organization_id=org)
        assert len(listed) == 3
