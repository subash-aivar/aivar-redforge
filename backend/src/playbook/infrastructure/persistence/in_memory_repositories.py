"""In-memory repositories with tenant isolation."""

from __future__ import annotations

from playbook.domain.aggregates.automation_policy import AutomationPolicy
from playbook.domain.aggregates.playbook import Playbook
from playbook.domain.aggregates.playbook_test_result import PlaybookTestResult
from playbook.domain.aggregates.playbook_version import PlaybookVersion
from playbook.domain.repositories.i_playbook_repositories import (
    IAutomationPolicyRepository,
    IPlaybookRepository,
    IPlaybookTestResultRepository,
    IPlaybookVersionRepository,
)
from playbook.domain.value_objects.enums import PlaybookStatus, TriggerSourceContext
from playbook.domain.value_objects.identifiers import (
    PlaybookId,
    PlaybookVersionId,
    TenantId,
)


class InMemoryPlaybookRepository(IPlaybookRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, Playbook]] = {}

    async def save(self, playbook: Playbook, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(playbook.playbook_id)] = playbook

    async def get(self, playbook_id: PlaybookId, tenant_id: TenantId) -> Playbook | None:
        return self._items.get(str(tenant_id), {}).get(str(playbook_id))

    async def find_approved_for_trigger(
        self, tenant_id: TenantId, source_context: TriggerSourceContext
    ) -> list[Playbook]:
        del source_context
        return [
            p
            for p in self._items.get(str(tenant_id), {}).values()
            if p.status == PlaybookStatus.APPROVED
        ]

    async def list(
        self, tenant_id: TenantId, *, status_filter: str | None, page: int, page_size: int
    ) -> list[Playbook]:
        rows = list(self._items.get(str(tenant_id), {}).values())
        if status_filter:
            rows = [r for r in rows if r.status.value == status_filter]
        start = (page - 1) * page_size
        return rows[start : start + page_size]


class InMemoryPlaybookVersionRepository(IPlaybookVersionRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, PlaybookVersion]] = {}

    def _key(self, playbook_id: PlaybookId, version_number: int) -> str:
        return f"{playbook_id}:{version_number}"

    async def save(self, version: PlaybookVersion, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[
            self._key(version.playbook_id, version.version_number)
        ] = version

    async def get(
        self, playbook_id: PlaybookId, version_number: int, tenant_id: TenantId
    ) -> PlaybookVersion | None:
        return self._items.get(str(tenant_id), {}).get(self._key(playbook_id, version_number))

    async def get_latest(
        self, playbook_id: PlaybookId, tenant_id: TenantId
    ) -> PlaybookVersion | None:
        rows = [
            v
            for k, v in self._items.get(str(tenant_id), {}).items()
            if k.startswith(f"{playbook_id}:")
        ]
        if not rows:
            return None
        return max(rows, key=lambda v: v.version_number)


class InMemoryPlaybookTestResultRepository(IPlaybookTestResultRepository):
    def __init__(self) -> None:
        self._items: dict[str, list[PlaybookTestResult]] = {}

    async def append(self, result: PlaybookTestResult, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), []).append(result)

    async def find_latest_for_version(
        self, playbook_id: PlaybookId, version_id: PlaybookVersionId, tenant_id: TenantId
    ) -> PlaybookTestResult | None:
        rows = [
            r
            for r in self._items.get(str(tenant_id), [])
            if r.playbook_id.value == playbook_id.value and r.version_id.value == version_id.value
        ]
        if not rows:
            return None
        return max(rows, key=lambda r: r.executed_at)


class InMemoryAutomationPolicyRepository(IAutomationPolicyRepository):
    def __init__(self) -> None:
        self._items: dict[str, AutomationPolicy] = {}

    async def get_or_create_default(self, tenant_id: TenantId) -> AutomationPolicy:
        key = str(tenant_id)
        if key not in self._items:
            self._items[key] = AutomationPolicy.default(tenant_id)
        return self._items[key]

    async def save(self, policy: AutomationPolicy, tenant_id: TenantId) -> None:
        self._items[str(tenant_id)] = policy
