"""Aggregate -> DTO mappers for tool_intel."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tool_intel.application.dtos.tool_dtos import (
    SourceAttributionDTO,
    ToolDetailDTO,
    ToolSummaryDTO,
    VersionRecordDTO,
)

if TYPE_CHECKING:
    from tool_intel.domain.aggregates.tool import Tool
    from tool_intel.domain.value_objects.evidence import SourceAttribution


def _attribution_dto(attribution: SourceAttribution) -> SourceAttributionDTO:
    return SourceAttributionDTO(
        source_system=attribution.source_system,
        reference=attribution.reference,
        observed_at=attribution.observed_at.isoformat(),
        confidence=attribution.confidence.value,
        notes=attribution.notes,
    )


def to_summary_dto(tool: Tool) -> ToolSummaryDTO:
    return ToolSummaryDTO(
        tool_id=str(tool.tool_id),
        tenant_id=str(tool.tenant_id) if tool.tenant_id is not None else None,
        canonical_name=tool.canonical_name,
        category=tool.category.value,
        lifecycle_status=tool.lifecycle_status.value,
        family=tool.family.family_name if tool.family is not None else None,
        confidence=tool.confidence.value,
        created_at=tool.created_at.isoformat(),
        updated_at=tool.updated_at.isoformat(),
        alias_count=len(tool.aliases),
        platform_count=len(tool.platforms),
        capability_count=len(tool.capabilities),
    )


def to_detail_dto(tool: Tool) -> ToolDetailDTO:
    return ToolDetailDTO(
        tool_id=str(tool.tool_id),
        tenant_id=str(tool.tenant_id) if tool.tenant_id is not None else None,
        canonical_name=tool.canonical_name,
        category=tool.category.value,
        lifecycle_status=tool.lifecycle_status.value,
        family=tool.family.family_name if tool.family is not None else None,
        confidence=tool.confidence.value,
        superseded_by=str(tool.superseded_by) if tool.superseded_by is not None else None,
        created_at=tool.created_at.isoformat(),
        updated_at=tool.updated_at.isoformat(),
        aliases=tuple(a.value for a in tool.aliases),
        platforms=tuple(p.value for p in tool.platforms),
        capabilities=tuple(c.value for c in tool.capabilities),
        evidence_citations=tuple(e.value for e in tool.evidence_citations),
        source_attributions=tuple(_attribution_dto(a) for a in tool.source_attributions),
        version_history=tuple(
            VersionRecordDTO(
                version=v.version,
                changed_at=v.changed_at.isoformat(),
                change_summary=v.change_summary,
                source=v.source,
            )
            for v in tool.version_history
        ),
    )
