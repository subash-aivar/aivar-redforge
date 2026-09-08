"""In-memory fakes for tool_intel application-layer tests. No ORM, no
real I/O — pure Python collections."""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from tool_intel.application.ports.i_event_publisher import IEventPublisher
from tool_intel.application.ports.i_tool_repository import IToolRepository
from tool_intel.application.ports.i_unit_of_work import IUnitOfWork

if TYPE_CHECKING:
    from tool_intel.domain.aggregates.tool import Tool
    from tool_intel.domain.events.base import BaseDomainEvent
    from tool_intel.domain.value_objects.enums import (
        ToolCapability,
        ToolCategory,
        ToolLifecycleStatus,
        ToolPlatform,
    )
    from tool_intel.domain.value_objects.identifiers import TenantId, ToolId


def _tenant_key(tenant_id: TenantId | None) -> str:
    return "" if tenant_id is None else str(tenant_id)


class InMemoryToolRepository(IToolRepository):
    def __init__(self) -> None:
        self._by_id: dict[str, Tool] = {}

    async def save(self, tool: Tool) -> None:
        self._by_id[str(tool.tool_id)] = tool

    async def get(self, tenant_id: TenantId | None, tool_id: ToolId) -> Tool | None:
        tool = self._by_id.get(str(tool_id))
        if tool is None or _tenant_key(tool.tenant_id) != _tenant_key(tenant_id):
            return None
        return tool

    async def get_any(self, tool_id: ToolId) -> Tool | None:
        return self._by_id.get(str(tool_id))

    async def get_by_canonical_name(
        self, tenant_id: TenantId | None, canonical_name: str
    ) -> Tool | None:
        for tool in self._by_id.values():
            if (
                _tenant_key(tool.tenant_id) == _tenant_key(tenant_id)
                and tool.canonical_name == canonical_name
            ):
                return tool
        return None

    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: ToolLifecycleStatus | None = None,
        category: ToolCategory | None = None,
        platform: ToolPlatform | None = None,
        capability: ToolCapability | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Tool]:
        results = [
            t for t in self._by_id.values() if _tenant_key(t.tenant_id) == _tenant_key(tenant_id)
        ]
        if lifecycle_status is not None:
            results = [t for t in results if t.lifecycle_status is lifecycle_status]
        if category is not None:
            results = [t for t in results if t.category is category]
        if platform is not None:
            results = [t for t in results if platform in t.platforms]
        if capability is not None:
            results = [t for t in results if capability in t.capabilities]
        results = sorted(results, key=lambda t: t.created_at, reverse=True)
        return results[offset : offset + limit]


class FakeUnitOfWork(IUnitOfWork):
    def __init__(self, repo: InMemoryToolRepository, *, fail_commit: bool = False) -> None:
        self.tools = repo
        self._fail_commit = fail_commit
        self.committed = False
        self.rolled_back = False

    async def commit(self) -> None:
        if self._fail_commit:
            raise RuntimeError("simulated commit failure")
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        if exc_type is not None:
            await self.rollback()


class RecordingEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.published_batches: list[list[BaseDomainEvent]] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.published_batches.append(list(events))

    @property
    def all_published(self) -> list[BaseDomainEvent]:
        return [event for batch in self.published_batches for event in batch]
