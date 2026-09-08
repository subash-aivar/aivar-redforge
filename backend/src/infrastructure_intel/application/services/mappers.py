"""Aggregate -> DTO mappers for infrastructure_intel."""

from __future__ import annotations

from typing import TYPE_CHECKING

from infrastructure_intel.application.dtos.infrastructure_dtos import (
    InfrastructureDetailDTO,
    InfrastructureSummaryDTO,
    NetworkOwnershipDTO,
    SourceAttributionDTO,
    VersionRecordDTO,
)

if TYPE_CHECKING:
    from infrastructure_intel.domain.aggregates.infrastructure import Infrastructure
    from infrastructure_intel.domain.value_objects.evidence import SourceAttribution


def _attribution_dto(attribution: SourceAttribution) -> SourceAttributionDTO:
    return SourceAttributionDTO(
        source_system=attribution.source_system,
        reference=attribution.reference,
        observed_at=attribution.observed_at.isoformat(),
        confidence=attribution.confidence.value,
        notes=attribution.notes,
    )


def to_summary_dto(record: Infrastructure) -> InfrastructureSummaryDTO:
    return InfrastructureSummaryDTO(
        infrastructure_id=str(record.infrastructure_id),
        tenant_id=str(record.tenant_id) if record.tenant_id is not None else None,
        infrastructure_type=record.infrastructure_type.value,
        normalized_identifier=record.normalized_identifier,
        lifecycle_status=record.lifecycle_status.value,
        hosting_provider=(
            record.hosting_provider.provider_name if record.hosting_provider is not None else None
        ),
        cloud_provider=(
            record.cloud_provider.provider.value if record.cloud_provider is not None else None
        ),
        confidence=record.confidence.value,
        created_at=record.created_at.isoformat(),
        updated_at=record.updated_at.isoformat(),
        region_count=len(record.regions),
        evidence_citation_count=len(record.evidence_citations),
        source_attribution_count=len(record.source_attributions),
    )


def to_detail_dto(record: Infrastructure) -> InfrastructureDetailDTO:
    ownership = record.network_ownership
    return InfrastructureDetailDTO(
        infrastructure_id=str(record.infrastructure_id),
        tenant_id=str(record.tenant_id) if record.tenant_id is not None else None,
        infrastructure_type=record.infrastructure_type.value,
        normalized_identifier=record.normalized_identifier,
        lifecycle_status=record.lifecycle_status.value,
        hosting_provider=(
            record.hosting_provider.provider_name if record.hosting_provider is not None else None
        ),
        cloud_provider=(
            record.cloud_provider.provider.value if record.cloud_provider is not None else None
        ),
        network_ownership=(
            NetworkOwnershipDTO(
                registrant_organization=ownership.registrant_organization,
                abuse_contact=ownership.abuse_contact,
                notes=ownership.notes,
            )
            if ownership is not None
            else None
        ),
        confidence=record.confidence.value,
        superseded_by=(str(record.superseded_by) if record.superseded_by is not None else None),
        created_at=record.created_at.isoformat(),
        updated_at=record.updated_at.isoformat(),
        regions=tuple(r.region_code for r in record.regions),
        evidence_citations=tuple(e.value for e in record.evidence_citations),
        source_attributions=tuple(_attribution_dto(a) for a in record.source_attributions),
        version_history=tuple(
            VersionRecordDTO(
                version=v.version,
                changed_at=v.changed_at.isoformat(),
                change_summary=v.change_summary,
                source=v.source,
            )
            for v in record.version_history
        ),
    )
