"""Frozen repository interfaces for playbook BC."""

from __future__ import annotations

from abc import ABC, abstractmethod

from playbook.domain.aggregates.automation_policy import AutomationPolicy
from playbook.domain.aggregates.playbook import Playbook
from playbook.domain.aggregates.playbook_test_result import PlaybookTestResult
from playbook.domain.aggregates.playbook_version import PlaybookVersion
from playbook.domain.value_objects.enums import TriggerSourceContext
from playbook.domain.value_objects.identifiers import (
    PlaybookId,
    PlaybookVersionId,
    TenantId,
)


class IPlaybookRepository(ABC):
    @abstractmethod
    async def save(self, playbook: Playbook, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def get(self, playbook_id: PlaybookId, tenant_id: TenantId) -> Playbook | None: ...

    @abstractmethod
    async def find_approved_for_trigger(
        self, tenant_id: TenantId, source_context: TriggerSourceContext
    ) -> list[Playbook]: ...

    @abstractmethod
    async def list(
        self, tenant_id: TenantId, *, status_filter: str | None, page: int, page_size: int
    ) -> list[Playbook]: ...


class IPlaybookVersionRepository(ABC):
    @abstractmethod
    async def save(self, version: PlaybookVersion, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def get(
        self, playbook_id: PlaybookId, version_number: int, tenant_id: TenantId
    ) -> PlaybookVersion | None: ...

    @abstractmethod
    async def get_latest(
        self, playbook_id: PlaybookId, tenant_id: TenantId
    ) -> PlaybookVersion | None: ...


class IPlaybookTestResultRepository(ABC):
    @abstractmethod
    async def append(self, result: PlaybookTestResult, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def find_latest_for_version(
        self, playbook_id: PlaybookId, version_id: PlaybookVersionId, tenant_id: TenantId
    ) -> PlaybookTestResult | None: ...


class IAutomationPolicyRepository(ABC):
    @abstractmethod
    async def get_or_create_default(self, tenant_id: TenantId) -> AutomationPolicy: ...

    @abstractmethod
    async def save(self, policy: AutomationPolicy, tenant_id: TenantId) -> None: ...
