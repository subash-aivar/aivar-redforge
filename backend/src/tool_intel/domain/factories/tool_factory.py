"""ToolFactory — the single supported construction path for `Tool`
aggregates.

Stays pure/sync: it performs no I/O and calls no port. Scope-level
uniqueness of `canonical_name` must already have been checked by the
application service (repository existence check) BEFORE this factory is
invoked — mirroring `campaign_intel`'s exact factory-stays-pure
discipline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tool_intel.domain.aggregates.tool import Tool
from tool_intel.domain.value_objects.enums import ToolCategory, ToolConfidence
from tool_intel.domain.value_objects.identifiers import ToolId

if TYPE_CHECKING:
    from datetime import datetime

    from tool_intel.domain.value_objects.enums import ToolCapability, ToolPlatform
    from tool_intel.domain.value_objects.identifiers import TenantId
    from tool_intel.domain.value_objects.taxonomy import ToolAlias, ToolFamily


class ToolFactory:
    def observe(
        self,
        tenant_id: TenantId | None,
        canonical_name: str,
        now: datetime,
        category: ToolCategory = ToolCategory.OTHER,
        family: ToolFamily | None = None,
        aliases: tuple[ToolAlias, ...] = (),
        platforms: tuple[ToolPlatform, ...] = (),
        capabilities: tuple[ToolCapability, ...] = (),
        confidence: ToolConfidence = ToolConfidence.MEDIUM,
    ) -> Tool:
        return Tool.observe(
            tool_id=ToolId.generate(),
            tenant_id=tenant_id,
            canonical_name=canonical_name,
            now=now,
            category=category,
            family=family,
            aliases=aliases,
            platforms=platforms,
            capabilities=capabilities,
            confidence=confidence,
        )
