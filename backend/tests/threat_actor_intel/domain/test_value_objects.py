from __future__ import annotations

import pytest

from threat_actor_intel.domain.exceptions.domain_exceptions import (
    EmptyAliasError,
    EmptyIdentifierError,
    EmptyThreatActorNameError,
)
from threat_actor_intel.domain.value_objects.identifiers import ThreatActorId
from threat_actor_intel.domain.value_objects.identity import Alias, ThreatActorName
from threat_actor_intel.domain.value_objects.references import (
    AttackTechniqueReference,
    FusedIndicatorReference,
)


class TestThreatActorName:
    def test_valid_name(self) -> None:
        assert str(ThreatActorName("APT29")) == "APT29"

    def test_empty_name_raises(self) -> None:
        with pytest.raises(EmptyThreatActorNameError):
            ThreatActorName("   ")


class TestAlias:
    def test_valid_alias(self) -> None:
        assert str(Alias("Cozy Bear")) == "Cozy Bear"

    def test_empty_alias_raises(self) -> None:
        with pytest.raises(EmptyAliasError):
            Alias("")

    def test_normalized_is_casefolded_and_stripped(self) -> None:
        assert Alias("  Cozy Bear  ").normalized() == "cozy bear"


class TestReferences:
    def test_attack_technique_reference(self) -> None:
        assert AttackTechniqueReference("T1566").technique_id == "T1566"

    def test_empty_technique_id_raises(self) -> None:
        with pytest.raises(EmptyIdentifierError):
            AttackTechniqueReference("")

    def test_fused_indicator_reference(self) -> None:
        assert FusedIndicatorReference("ind-1").indicator_id == "ind-1"

    def test_empty_indicator_id_raises(self) -> None:
        with pytest.raises(EmptyIdentifierError):
            FusedIndicatorReference("  ")


class TestThreatActorId:
    def test_generate_produces_distinct_ids(self) -> None:
        assert ThreatActorId.generate() != ThreatActorId.generate()

    def test_nil_uuid_rejected(self) -> None:
        import uuid

        with pytest.raises(ValueError, match="nil UUID"):
            ThreatActorId(uuid.UUID(int=0))
