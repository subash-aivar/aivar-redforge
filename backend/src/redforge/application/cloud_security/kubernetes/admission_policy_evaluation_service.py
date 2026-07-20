"""Evaluate admission controller policies against workloads (inventory events)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from redforge.domain.cloud_security.kubernetes.admission_policy import KubernetesAdmissionPolicy
from redforge.domain.cloud_security.kubernetes.entities import AdmissionViolation
from redforge.domain.cloud_security.kubernetes.exceptions import KubernetesClusterNotFoundError
from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]
    RepoFactory = Callable[[AsyncSession], object]


class AdmissionPolicyEvaluationService:
    """Applies registered admission policy rules to workloads and records violations."""

    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        cluster_repo_factory: RepoFactory,
        admission_repo_factory: RepoFactory,
        workload_repo_factory: RepoFactory,
    ) -> None:
        self._session_factory = session_factory
        self._cluster_repo_factory = cluster_repo_factory
        self._admission_repo_factory = admission_repo_factory
        self._workload_repo_factory = workload_repo_factory

    async def evaluate(self, *, organization_id: str, cluster_id: UUID) -> list[dict[str, Any]]:
        org = OrganizationId(organization_id)
        results: list[dict[str, Any]] = []
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            cluster_repo = self._cluster_repo_factory(uow.session)
            cluster = await cluster_repo.get_by_id(cluster_id, organization_id=org)  # type: ignore[attr-defined]
            if cluster is None:
                raise KubernetesClusterNotFoundError(str(cluster_id))
            admission_repo = self._admission_repo_factory(uow.session)
            workload_repo = self._workload_repo_factory(uow.session)
            policies: list[KubernetesAdmissionPolicy] = await admission_repo.list_by_cluster(  # type: ignore[attr-defined]
                cluster_id, organization_id=org
            )
            workloads: list[KubernetesWorkload] = await workload_repo.list_by_cluster(  # type: ignore[attr-defined]
                cluster_id, organization_id=org
            )
            if not policies:
                # Register a default PSS-style admission policy if none exist.
                policy = KubernetesAdmissionPolicy.register(
                    cluster_id=cluster.id,
                    organization_id=org,
                    name="pod-security-baseline",
                    mode="AUDIT",
                    controller="PodSecurity",
                    rules=[{"id": "no-privileged", "check": "privileged"}],
                )
                policies = [policy]

            for policy in policies:
                violations = self._evaluate_policy(policy, workloads)
                policy.record_evaluation(violations=violations)
                await admission_repo.save(policy)  # type: ignore[attr-defined]
                results.append(
                    {
                        "policy_id": str(policy.id),
                        "name": policy.name,
                        "mode": policy.mode.value,
                        "violation_count": len(violations),
                        "violations": [v.to_dict() for v in violations],
                        "events": [
                            {
                                "type": type(e).__name__,
                                "violation_count": getattr(e, "violation_count", None),
                            }
                            for e in policy.pop_events()
                        ],
                    }
                )
            await uow.commit()
        return results

    def _evaluate_policy(
        self,
        policy: KubernetesAdmissionPolicy,
        workloads: list[KubernetesWorkload],
    ) -> list[AdmissionViolation]:
        violations: list[AdmissionViolation] = []
        for wl in workloads:
            if wl.privileged:
                violations.append(
                    AdmissionViolation(
                        rule_id="no-privileged",
                        message=f"Workload {wl.namespace}/{wl.name} runs privileged containers",
                        resource_kind=wl.kind.value,
                        resource_name=wl.name,
                        namespace=wl.namespace,
                        severity="HIGH",
                    )
                )
            if wl.host_network:
                violations.append(
                    AdmissionViolation(
                        rule_id="no-host-network",
                        message=f"Workload {wl.namespace}/{wl.name} uses hostNetwork",
                        resource_kind=wl.kind.value,
                        resource_name=wl.name,
                        namespace=wl.namespace,
                        severity="HIGH",
                    )
                )
            if any(c.image.uses_latest_tag for c in wl.containers):
                violations.append(
                    AdmissionViolation(
                        rule_id="no-latest-tag",
                        message=f"Workload {wl.namespace}/{wl.name} uses :latest image tag",
                        resource_kind=wl.kind.value,
                        resource_name=wl.name,
                        namespace=wl.namespace,
                        severity="MEDIUM",
                    )
                )
        # Attach policy context in message only; rule ids stay stable.
        _ = policy.name
        return violations
