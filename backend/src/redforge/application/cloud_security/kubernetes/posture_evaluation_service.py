"""Evaluate Kubernetes workload posture via shared CSPM PolicyEvaluationEngine."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from redforge.application.cloud_security.kubernetes.dtos import (
    ComplianceSummaryDTO,
    EvaluateClusterCommand,
    EvaluationResultDTO,
    ViolationResultDTO,
)
from redforge.domain.cloud_security.cspm.policy import CSPMPolicy
from redforge.domain.cloud_security.kubernetes.events import K8sPodSecurityViolationDetected
from redforge.domain.cloud_security.kubernetes.exceptions import KubernetesClusterNotFoundError
from redforge.domain.cloud_security.kubernetes.value_objects import K8sSecurityScore
from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload
from redforge.domain.cloud_security.policy_engine.evaluator import PolicyEvaluationEngine
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.cloud_security.cspm.policy_loader import load_cspm_policies
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]
    RepoFactory = Callable[[AsyncSession], object]


class PostureEvaluationService:
    """Builds workload snapshots, loads k8s CSPM policies, runs PolicyEvaluationEngine."""

    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        cluster_repo_factory: RepoFactory,
        workload_repo_factory: RepoFactory,
        namespace_repo_factory: RepoFactory | None = None,
        rbac_repo_factory: RepoFactory | None = None,
        service_repo_factory: RepoFactory | None = None,
        engine: PolicyEvaluationEngine | None = None,
        graph_acl: object | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._cluster_repo_factory = cluster_repo_factory
        self._workload_repo_factory = workload_repo_factory
        self._namespace_repo_factory = namespace_repo_factory
        self._rbac_repo_factory = rbac_repo_factory
        self._service_repo_factory = service_repo_factory
        self._engine = engine or PolicyEvaluationEngine()
        self._graph_acl = graph_acl
        self._policy_cache: list[CSPMPolicy] | None = None
        self._pending_events: list[K8sPodSecurityViolationDetected] = []

    def invalidate_policy_cache(self) -> None:
        self._policy_cache = None

    def _k8s_policies(self) -> list[CSPMPolicy]:
        if self._policy_cache is None:
            all_policies = load_cspm_policies()
            self._policy_cache = [
                p
                for p in all_policies
                if p.applies_to(provider_type="*", asset_type="K8S_WORKLOAD")
                or "K8S_WORKLOAD" in p.asset_types
                or "*" in p.asset_types
            ]
        return self._policy_cache

    async def evaluate(self, command: EvaluateClusterCommand) -> EvaluationResultDTO:
        org = OrganizationId(command.organization_id)
        self._pending_events.clear()
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            cluster_repo = self._cluster_repo_factory(uow.session)
            cluster = await cluster_repo.get_by_id(  # type: ignore[attr-defined]
                command.cluster_id, organization_id=org
            )
            if cluster is None:
                raise KubernetesClusterNotFoundError(str(command.cluster_id))
            workload_repo = self._workload_repo_factory(uow.session)
            workloads: list[KubernetesWorkload] = await workload_repo.list_by_cluster(  # type: ignore[attr-defined]
                command.cluster_id, organization_id=org
            )
            policies = [
                p
                for p in self._k8s_policies()
                if p.applies_to(
                    provider_type=command.provider_type,
                    asset_type="K8S_WORKLOAD",
                )
            ]

            violations: list[ViolationResultDTO] = []
            critical = 0
            high = 0
            for wl in workloads:
                snapshot = wl.posture_snapshot()
                for policy in policies:
                    outcome = self._engine.evaluate(policy.rule, snapshot)
                    passed = not outcome.matched
                    if not passed:
                        msg = outcome.message or policy.title
                        violations.append(
                            ViolationResultDTO(
                                workload_id=str(wl.id),
                                policy_id=str(policy.id),
                                rule_id=str(policy.rule_id),
                                severity=policy.severity.value,
                                title=policy.title,
                                message=msg,
                                passed=False,
                            )
                        )
                        if policy.severity.value == "CRITICAL":
                            critical += 1
                        elif policy.severity.value == "HIGH":
                            high += 1
                        from datetime import UTC, datetime

                        self._pending_events.append(
                            K8sPodSecurityViolationDetected(
                                occurred_at=datetime.now(UTC),
                                organization_id=str(org),
                                cluster_id=command.cluster_id,
                                workload_id=wl.id.value,
                                policy_id=str(policy.id),
                                severity=policy.severity.value,
                                message=msg,
                            )
                        )

            score = K8sSecurityScore.compute(
                workloads_evaluated=len(workloads),
                violation_count=len(violations),
                critical_count=critical,
                high_count=high,
            )
            cluster.update_security_score(score)
            await cluster_repo.save(cluster)  # type: ignore[attr-defined]
            await uow.commit()

        return EvaluationResultDTO(
            cluster_id=str(command.cluster_id),
            workloads_evaluated=len(workloads),
            policies_evaluated=len(policies),
            violations=violations,
            security_score=score.to_dict(),
        )

    def pop_events(self) -> list[K8sPodSecurityViolationDetected]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    async def compliance_summary(
        self, *, organization_id: str, cluster_id: UUID
    ) -> ComplianceSummaryDTO:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            cluster_repo = self._cluster_repo_factory(uow.session)
            cluster = await cluster_repo.get_by_id(cluster_id, organization_id=org)  # type: ignore[attr-defined]
            if cluster is None:
                raise KubernetesClusterNotFoundError(str(cluster_id))
            workloads = await self._workload_repo_factory(uow.session).list_by_cluster(  # type: ignore[attr-defined]
                cluster_id, organization_id=org
            )
            namespaces = []
            if self._namespace_repo_factory is not None:
                namespaces = await self._namespace_repo_factory(uow.session).list_by_cluster(  # type: ignore[attr-defined]
                    cluster_id, organization_id=org
                )
            rbac = []
            if self._rbac_repo_factory is not None:
                rbac = await self._rbac_repo_factory(uow.session).list_by_cluster(  # type: ignore[attr-defined]
                    cluster_id, organization_id=org
                )

        privileged_count = sum(1 for w in workloads if w.privileged)
        public_count = sum(1 for w in workloads if w.exposure.value == "PUBLIC")
        ns_without_np = sum(1 for n in namespaces if not n.has_network_policy)
        rbac_wild = sum(
            1
            for p in rbac
            if p.inventory_dict().get("has_wildcard_verb")
            or p.inventory_dict().get("has_wildcard_resource")
        )
        return ComplianceSummaryDTO(
            cluster_id=str(cluster_id),
            security_score=cluster.security_score.to_dict(),
            workload_count=len(workloads),
            privileged_count=privileged_count,
            public_exposure_count=public_count,
            namespaces_without_network_policy=ns_without_np,
            rbac_wildcard_count=rbac_wild,
        )
