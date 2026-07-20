"""Kubernetes security domain exceptions."""

from __future__ import annotations

from redforge.core.exceptions import ConflictError, NotFoundError, ValidationError


class InvalidKubernetesArgumentError(ValidationError):
    def __init__(self, field: str, message: str) -> None:
        self.field = field
        super().__init__(message=f"{field}: {message}", details={field: message})


class KubernetesClusterNotFoundError(NotFoundError):
    def __init__(self, cluster_id: str) -> None:
        super().__init__(resource="KubernetesCluster", identifier=cluster_id)
        self.cluster_id = cluster_id


class KubernetesWorkloadNotFoundError(NotFoundError):
    def __init__(self, workload_id: str) -> None:
        super().__init__(resource="KubernetesWorkload", identifier=workload_id)
        self.workload_id = workload_id


class KubernetesRBACNotFoundError(NotFoundError):
    def __init__(self, principal_id: str) -> None:
        super().__init__(resource="KubernetesRBACPrincipal", identifier=principal_id)
        self.principal_id = principal_id


class KubernetesConcurrencyError(ConflictError):
    def __init__(self, resource: str, identifier: str) -> None:
        super().__init__(
            message=f"Optimistic concurrency conflict on {resource}={identifier}",
        )
