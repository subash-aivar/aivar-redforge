from __future__ import annotations

from redforge.shared.identifiers import EntityId
from risk_engine.domain.value_objects.identifiers import CorrelationSetId, RiskProfileId, TenantId


def test_tenant_id_is_shared_entity_id() -> None:
    assert TenantId is EntityId


def test_risk_profile_id_generate_and_str() -> None:
    a = RiskProfileId.generate()
    b = RiskProfileId.generate()
    assert a != b
    assert str(a) == str(a.value)


def test_correlation_set_id_generate_and_str() -> None:
    a = CorrelationSetId.generate()
    b = CorrelationSetId.generate()
    assert a != b
    assert str(a) == str(a.value)
