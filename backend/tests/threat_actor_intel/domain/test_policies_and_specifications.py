from __future__ import annotations

from datetime import UTC, datetime

import pytest

from threat_actor_intel.domain.aggregates.threat_actor import ThreatActor
from threat_actor_intel.domain.exceptions.domain_exceptions import (
    InvalidActivityStatusTransition,
)
from threat_actor_intel.domain.policies.activity_lifecycle_policy import ActivityLifecyclePolicy
from threat_actor_intel.domain.policies.attribution_confidence_policy import (
    AttributionConfidencePolicy,
)
from threat_actor_intel.domain.specifications.threat_actor_specifications import (
    HasAliasSpecification,
    HasHighAttributionConfidenceSpecification,
    IsActiveThreatActorSpecification,
    IsAssociatedWithIndicatorSpecification,
    IsAssociatedWithTechniqueSpecification,
)
from threat_actor_intel.domain.value_objects.enums import (
    ActivityStatus,
    AttributionConfidence,
    MotivationType,
    SophisticationLevel,
    ThreatActorOrigin,
)
from threat_actor_intel.domain.value_objects.identifiers import TenantId, ThreatActorId
from threat_actor_intel.domain.value_objects.identity import Alias, ThreatActorName
from threat_actor_intel.domain.value_objects.references import AttackTechniqueReference


def _now() -> datetime:
    return datetime.now(UTC)


def _register() -> ThreatActor:
    return ThreatActor.register(
        threat_actor_id=ThreatActorId.generate(),
        tenant_id=TenantId.generate(),
        name=ThreatActorName("APT29"),
        origin=ThreatActorOrigin.NATION_STATE,
        motivations=frozenset({MotivationType.ESPIONAGE}),
        sophistication=SophisticationLevel.NOVICE,
        now=_now(),
    )


class TestActivityLifecyclePolicy:
    def test_active_to_dormant_is_legal(self) -> None:
        ActivityLifecyclePolicy.assert_legal_transition(
            ActivityStatus.ACTIVE, ActivityStatus.DORMANT
        )

    def test_disbanded_to_anything_is_illegal(self) -> None:
        with pytest.raises(InvalidActivityStatusTransition):
            ActivityLifecyclePolicy.assert_legal_transition(
                ActivityStatus.DISBANDED, ActivityStatus.ACTIVE
            )

    def test_active_to_active_is_illegal(self) -> None:
        with pytest.raises(InvalidActivityStatusTransition):
            ActivityLifecyclePolicy.assert_legal_transition(
                ActivityStatus.ACTIVE, ActivityStatus.ACTIVE
            )


class TestAttributionConfidencePolicy:
    def test_zero_evidence_is_low(self) -> None:
        result = AttributionConfidencePolicy.derive(
            technique_count=0, indicator_count=0, sophistication=SophisticationLevel.NOVICE
        )
        assert result == AttributionConfidence.LOW

    def test_one_technique_is_medium(self) -> None:
        result = AttributionConfidencePolicy.derive(
            technique_count=1, indicator_count=0, sophistication=SophisticationLevel.NOVICE
        )
        assert result == AttributionConfidence.MEDIUM

    def test_three_techniques_at_expert_is_high(self) -> None:
        result = AttributionConfidencePolicy.derive(
            technique_count=3, indicator_count=0, sophistication=SophisticationLevel.EXPERT
        )
        assert result == AttributionConfidence.HIGH

    def test_three_techniques_at_novice_is_only_medium(self) -> None:
        result = AttributionConfidencePolicy.derive(
            technique_count=3, indicator_count=0, sophistication=SophisticationLevel.NOVICE
        )
        assert result == AttributionConfidence.MEDIUM


class TestSpecifications:
    def test_is_active_specification(self) -> None:
        actor = _register()
        assert IsActiveThreatActorSpecification().is_satisfied_by(actor) is True
        actor.mark_dormant(actor.tenant_id, _now())
        assert IsActiveThreatActorSpecification().is_satisfied_by(actor) is False

    def test_high_attribution_confidence_specification(self) -> None:
        actor = ThreatActor.register(
            threat_actor_id=ThreatActorId.generate(),
            tenant_id=TenantId.generate(),
            name=ThreatActorName("APT29"),
            origin=ThreatActorOrigin.NATION_STATE,
            motivations=frozenset({MotivationType.ESPIONAGE}),
            sophistication=SophisticationLevel.EXPERT,
            now=_now(),
        )
        assert HasHighAttributionConfidenceSpecification().is_satisfied_by(actor) is False
        for tid in ("T1", "T2", "T3"):
            actor.associate_technique(actor.tenant_id, AttackTechniqueReference(tid), _now())
        assert HasHighAttributionConfidenceSpecification().is_satisfied_by(actor) is True

    def test_is_associated_with_technique_specification(self) -> None:
        actor = _register()
        actor.associate_technique(actor.tenant_id, AttackTechniqueReference("T1566"), _now())
        assert IsAssociatedWithTechniqueSpecification("T1566").is_satisfied_by(actor) is True
        assert IsAssociatedWithTechniqueSpecification("T9999").is_satisfied_by(actor) is False

    def test_is_associated_with_indicator_specification(self) -> None:
        actor = _register()
        assert IsAssociatedWithIndicatorSpecification("ind-1").is_satisfied_by(actor) is False

    def test_has_alias_specification_is_case_insensitive(self) -> None:
        actor = _register()
        actor.add_alias(actor.tenant_id, Alias("Cozy Bear"), _now())
        assert HasAliasSpecification("cozy bear").is_satisfied_by(actor) is True
        assert HasAliasSpecification("Fancy Bear").is_satisfied_by(actor) is False
