from __future__ import annotations

import random
from datetime import UTC, datetime

from tool_intel.domain.aggregates.tool import Tool
from tool_intel.domain.value_objects.enums import ToolCategory, ToolConfidence
from tool_intel.domain.value_objects.evidence import SourceAttribution
from tool_intel.domain.value_objects.identifiers import TenantId, ToolId


def make_tenant_id() -> TenantId:
    return TenantId.generate()


def random_name(prefix: str = "tool") -> str:
    """Already in normalized form (lowercase, no separator runs) so a
    raw-string repository lookup matches what the aggregate stores —
    normalization would otherwise collapse `-`/`_` to a space."""
    return f"{prefix}{random.randint(1, 10**12)}"


def make_attribution(source_system: str = "redforge-analyst") -> SourceAttribution:
    return SourceAttribution(
        source_system=source_system,
        reference=f"ref-{random.randint(1, 10**9)}",
        observed_at=datetime(2026, 8, 6, tzinfo=UTC),
        confidence=ToolConfidence.HIGH,
    )


def make_tool(
    *,
    tenant_id: TenantId | None = None,
    canonical_name: str | None = None,
    category: ToolCategory = ToolCategory.OTHER,
) -> Tool:
    now = datetime(2026, 8, 6, tzinfo=UTC)
    return Tool.observe(
        tool_id=ToolId.generate(),
        tenant_id=tenant_id,
        canonical_name=canonical_name or random_name(),
        now=now,
        category=category,
    )
