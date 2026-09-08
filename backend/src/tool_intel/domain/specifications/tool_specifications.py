"""Predicate specifications over `Tool`. Pure, in-memory predicates
only — no query building, no persistence concerns (mirrors
`campaign_intel.domain.specifications.campaign_specifications`)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from tool_intel.domain.value_objects.enums import ToolLifecycleStatus

if TYPE_CHECKING:
    from tool_intel.domain.aggregates.tool import Tool


class ToolSpecification(Protocol):
    def is_satisfied_by(self, tool: Tool) -> bool: ...


class IsGlobalToolSpecification:
    def is_satisfied_by(self, tool: Tool) -> bool:
        return tool.tenant_id is None


class IsTenantToolSpecification:
    def is_satisfied_by(self, tool: Tool) -> bool:
        return tool.tenant_id is not None


class ActiveToolSpecification:
    """RECORD-lifecycle predicate — says nothing about whether the tool
    is still used in the wild."""

    def is_satisfied_by(self, tool: Tool) -> bool:
        return tool.lifecycle_status is ToolLifecycleStatus.ACTIVE


class DeprecatedOrRevokedToolSpecification:
    _TERMINAL = frozenset({ToolLifecycleStatus.DEPRECATED, ToolLifecycleStatus.REVOKED})

    def is_satisfied_by(self, tool: Tool) -> bool:
        return tool.lifecycle_status in self._TERMINAL


class SupersededToolSpecification:
    def is_satisfied_by(self, tool: Tool) -> bool:
        return tool.lifecycle_status is ToolLifecycleStatus.SUPERSEDED
