from __future__ import annotations

import random
from datetime import UTC, datetime

from infrastructure_intel.domain.aggregates.infrastructure import Infrastructure
from infrastructure_intel.domain.value_objects.enums import (
    InfrastructureConfidence,
    InfrastructureType,
)
from infrastructure_intel.domain.value_objects.evidence import SourceAttribution
from infrastructure_intel.domain.value_objects.identifiers import (
    InfrastructureId,
    TenantId,
)


def make_tenant_id() -> TenantId:
    return TenantId.generate()


def random_asn() -> str:
    """Already in canonical `AS<number>` form so a raw-string repository
    lookup matches what the aggregate stores."""
    return f"AS{random.randint(1, 4_000_000_000)}"


def random_domain() -> str:
    """Already normalized (lowercase, trimmed)."""
    return f"evil{random.randint(1, 10**12)}.example.com"


def make_attribution(source_system: str = "redforge-analyst") -> SourceAttribution:
    return SourceAttribution(
        source_system=source_system,
        reference=f"ref-{random.randint(1, 10**9)}",
        observed_at=datetime(2026, 8, 6, tzinfo=UTC),
        confidence=InfrastructureConfidence.HIGH,
    )


def make_infrastructure(
    *,
    tenant_id: TenantId | None = None,
    infrastructure_type: InfrastructureType = InfrastructureType.ASN,
    normalized_identifier: str | None = None,
    confidence: InfrastructureConfidence = InfrastructureConfidence.MEDIUM,
) -> Infrastructure:
    now = datetime(2026, 8, 6, tzinfo=UTC)
    if normalized_identifier is None:
        normalized_identifier = (
            random_asn() if infrastructure_type is InfrastructureType.ASN else random_domain()
        )
    return Infrastructure.observe(
        infrastructure_id=InfrastructureId.generate(),
        tenant_id=tenant_id,
        infrastructure_type=infrastructure_type,
        normalized_identifier=normalized_identifier,
        now=now,
        confidence=confidence,
    )
