"""ToolIdentityPolicy — no duplicate `canonical_name` within a scope
(`tenant_id`, or global when `tenant_id is None`). The domain-layer half
of the two-layer defense; see `ToolApplicationService` for the
repository-existence-check half, mirroring `campaign_intel`'s dedup
discipline exactly."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tool_intel.domain.exceptions.domain_exceptions import DuplicateToolError

if TYPE_CHECKING:
    from tool_intel.domain.aggregates.tool import Tool


class ToolIdentityPolicy:
    @staticmethod
    def assert_no_duplicate(existing: list[Tool], canonical_name: str) -> None:
        for tool in existing:
            if tool.canonical_name == canonical_name:
                raise DuplicateToolError(canonical_name)
