from __future__ import annotations

from datetime import UTC, datetime

import pytest

from infrastructure_intel.domain.value_objects.enums import InfrastructureConfidence
from infrastructure_intel.domain.value_objects.evidence import SourceAttribution
from infrastructure_intel.domain.value_objects.identifiers import TenantId

NOW = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)


@pytest.fixture
def now() -> datetime:
    return NOW


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()


@pytest.fixture
def evidence() -> SourceAttribution:
    return SourceAttribution(
        source_system="redforge-analyst",
        reference="report-42",
        observed_at=NOW,
        confidence=InfrastructureConfidence.HIGH,
    )
