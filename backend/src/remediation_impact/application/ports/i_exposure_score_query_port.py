"""ACL port — pull current asset scores from exposure BC (no domain leakage)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from remediation_impact.domain.value_objects.identifiers import TenantId


class IExposureScoreQueryPort(ABC):
    @abstractmethod
    async def get_asset_scores(self, tenant_id: TenantId) -> dict[str, float]: ...

    @abstractmethod
    async def get_score_input_version(self, tenant_id: TenantId) -> int: ...
