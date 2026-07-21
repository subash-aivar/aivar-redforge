from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exposure.domain.aggregates.amplifier_weight_configuration import (
        AmplifierWeightConfiguration,
    )
    from exposure.domain.value_objects.identifiers import TenantId


class IAmplifierWeightConfigurationRepository(ABC):
    @abstractmethod
    async def save(self, tenant_id: TenantId, config: AmplifierWeightConfiguration) -> None: ...

    @abstractmethod
    async def find_current(self, tenant_id: TenantId) -> AmplifierWeightConfiguration | None: ...

    @abstractmethod
    async def find_by_version(
        self, tenant_id: TenantId, version: int
    ) -> AmplifierWeightConfiguration | None: ...

    @abstractmethod
    async def find_all_versions(
        self, tenant_id: TenantId
    ) -> list[AmplifierWeightConfiguration]: ...
