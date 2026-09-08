"""Aggregate -> DTO mappers for ioc_intelligence (M51.2 Phase A2),
mirroring `threat_actor_intel.application.services.mappers`'s
convention. Every field is a plain primitive — the IOC domain object
never crosses into a DTO."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ioc_intelligence.application.dtos.ioc_dtos import (
    EpistemicStateDTO,
    EvidenceCitationDTO,
    IocDetailDTO,
    IocSummaryDTO,
    LifecycleStateDTO,
    SourceAttributionDTO,
)

if TYPE_CHECKING:
    from ioc_intelligence.domain.aggregates.ioc import IOC


def _tenant_id_str(tenant_id: object) -> str | None:
    return None if tenant_id is None else str(tenant_id)


def to_summary_dto(ioc: IOC) -> IocSummaryDTO:
    return IocSummaryDTO(
        ioc_id=str(ioc.ioc_id),
        tenant_id=_tenant_id_str(ioc.tenant_id),
        ioc_type=ioc.ioc_type.value,
        canonical_key=str(ioc.canonical_key),
        lifecycle=LifecycleStateDTO(ioc.lifecycle.value),
        epistemic_state=EpistemicStateDTO(ioc.epistemic_state.value),
        created_at=ioc.created_at.isoformat(),
        updated_at=ioc.updated_at.isoformat(),
        valid_until=(
            ioc.validity_window.valid_until.isoformat() if ioc.validity_window.valid_until else None
        ),
        source_count=len(ioc.source_attributions),
        evidence_count=len(ioc.evidence_citations),
    )


def to_detail_dto(ioc: IOC) -> IocDetailDTO:
    return IocDetailDTO(
        ioc_id=str(ioc.ioc_id),
        tenant_id=_tenant_id_str(ioc.tenant_id),
        ioc_type=ioc.ioc_type.value,
        canonical_key=str(ioc.canonical_key),
        lifecycle=LifecycleStateDTO(ioc.lifecycle.value),
        epistemic_state=EpistemicStateDTO(ioc.epistemic_state.value),
        valid_from=ioc.validity_window.valid_from.isoformat(),
        valid_until=(
            ioc.validity_window.valid_until.isoformat() if ioc.validity_window.valid_until else None
        ),
        created_at=ioc.created_at.isoformat(),
        updated_at=ioc.updated_at.isoformat(),
        source_attributions=tuple(
            SourceAttributionDTO(
                source_system=a.source_system,
                external_id=a.external_id,
                content_hash=a.content_hash,
                observed_at=a.observed_at.isoformat(),
                weight_applied=a.weight_applied,
                confidence=a.confidence.value,
            )
            for a in ioc.source_attributions
        ),
        evidence_citations=tuple(EvidenceCitationDTO(str(c)) for c in ioc.evidence_citations),
    )
