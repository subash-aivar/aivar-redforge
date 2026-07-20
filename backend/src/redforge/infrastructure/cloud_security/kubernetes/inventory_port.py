"""Inventory port — raw dict resources only (never kubernetes client types)."""

from __future__ import annotations

from typing import Any, Protocol


class KubernetesInventoryPort(Protocol):
    """Fetches cluster inventory as plain dicts suitable for normalization."""

    async def list_resources(
        self,
        *,
        kinds: list[str] | None = None,
        namespace: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return raw inventory dicts with at least ``kind`` and ``metadata`` keys."""
        ...

    async def get_cluster_info(self) -> dict[str, Any]:
        """Return cluster-level metadata (name, version, endpoint, labels, …)."""
        ...
