"""In-memory FakeKubernetesInventory for tests and local development."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


class FakeKubernetesInventory:
    """Stores raw dict resources; never exposes kubernetes SDK objects."""

    def __init__(
        self,
        *,
        cluster_info: dict[str, Any] | None = None,
        resources: list[dict[str, Any]] | None = None,
    ) -> None:
        self._cluster_info = dict(
            cluster_info
            or {
                "name": "dev-cluster",
                "version": "1.29.0",
                "api_server_endpoint": "https://127.0.0.1:6443",
                "region": "us-east-1",
                "cluster_type": "EKS",
                "labels": {},
                "pod_security_standards": {},
            }
        )
        self._resources: list[dict[str, Any]] = [dict(r) for r in (resources or [])]

    def seed(self, resource: dict[str, Any]) -> None:
        self._resources.append(dict(resource))

    def seed_many(self, resources: list[dict[str, Any]]) -> None:
        for resource in resources:
            self.seed(resource)

    def clear(self) -> None:
        self._resources.clear()

    async def get_cluster_info(self) -> dict[str, Any]:
        return deepcopy(self._cluster_info)

    async def list_resources(
        self,
        *,
        kinds: list[str] | None = None,
        namespace: str | None = None,
    ) -> list[dict[str, Any]]:
        kind_filter = {k.lower() for k in kinds} if kinds else None
        results: list[dict[str, Any]] = []
        for resource in self._resources:
            kind = str(resource.get("kind", "")).lower()
            if kind_filter is not None and kind not in kind_filter:
                continue
            meta = resource.get("metadata") if isinstance(resource.get("metadata"), dict) else {}
            ns = str(meta.get("namespace", "")) if isinstance(meta, dict) else ""
            if namespace is not None and ns != namespace:
                continue
            results.append(deepcopy(resource))
        return results
