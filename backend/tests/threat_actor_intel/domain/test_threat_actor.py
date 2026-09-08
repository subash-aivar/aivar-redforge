from __future__ import annotations

from datetime import UTC, datetime

import pytest

from threat_actor_intel.domain.aggregates.threat_actor import ThreatActor
from threat_actor_intel.domain.exceptions.domain_exceptions import (
    DuplicateAliasError,
    DuplicateIndicatorAssociationError,
    DuplicateTechniqueAssociationError,
    EmptyMotivationSetError,
    InvalidActivityStatusTransition,
    TenantMismatch,
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
from threat_actor_intel.domain.value_objects.references import (
    AttackTechniqueReference,
    FusedIndicatorReference,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _register(
    tenant_id: TenantId | None = None,
    motivations: frozenset[MotivationType] | None = None,
    sophistication: SophisticationLevel = SophisticationLevel.NOVICE,
) -> ThreatActor:
    return ThreatActor.register(
        threat_actor_id=ThreatActorId.generate(),
        tenant_id=tenant_id or TenantId.generate(),
        name=ThreatActorName("APT29"),
        origin=ThreatActorOrigin.NATION_STATE,
        motivations=motivations or frozenset({MotivationType.ESPIONAGE}),
        sophistication=sophistication,
        now=_now(),
    )


class TestRegister:
    def test_register_sets_initial_state(self) -> None:
        actor = _register()
        assert actor.status == ActivityStatus.ACTIVE
        assert actor.attribution_confidence == AttributionConfidence.LOW
        assert actor.aliases == ()
        assert actor.technique_refs == ()
        assert actor.indicator_refs == ()

    def test_register_emits_threat_actor_registered_event(self) -> None:
        actor = _register()
        events = actor.pop_events()
        assert len(events) == 1
        assert type(events[0]).__name__ == "ThreatActorRegistered"

    def test_register_rejects_empty_motivations(self) -> None:
        with pytest.raises(EmptyMotivationSetError):
            ThreatActor.register(
                threat_actor_id=ThreatActorId.generate(),
                tenant_id=TenantId.generate(),
                name=ThreatActorName("APT29"),
                origin=ThreatActorOrigin.NATION_STATE,
                motivations=frozenset(),
                sophistication=SophisticationLevel.NOVICE,
                now=_now(),
            )

    def test_pop_events_clears_pending_events(self) -> None:
        actor = _register()
        actor.pop_events()
        assert actor.pop_events() == []


class TestAlias:
    def test_add_alias(self) -> None:
        actor = _register()
        actor.pop_events()
        actor.add_alias(actor.tenant_id, Alias("Cozy Bear"), _now())
        assert len(actor.aliases) == 1
        assert str(actor.aliases[0]) == "Cozy Bear"
        events = actor.pop_events()
        assert len(events) == 1
        assert type(events[0]).__name__ == "ThreatActorAliasAdded"

    def test_duplicate_alias_case_insensitive_raises(self) -> None:
        actor = _register()
        actor.add_alias(actor.tenant_id, Alias("Cozy Bear"), _now())
        with pytest.raises(DuplicateAliasError):
            actor.add_alias(actor.tenant_id, Alias("cozy bear"), _now())

    def test_add_alias_wrong_tenant_raises(self) -> None:
        actor = _register()
        with pytest.raises(TenantMismatch):
            actor.add_alias(TenantId.generate(), Alias("Cozy Bear"), _now())


class TestTechniqueAssociation:
    def test_associate_technique(self) -> None:
        actor = _register()
        actor.associate_technique(actor.tenant_id, AttackTechniqueReference("T1566"), _now())
        assert len(actor.technique_refs) == 1
        assert actor.technique_refs[0].technique_id == "T1566"

    def test_duplicate_technique_raises(self) -> None:
        actor = _register()
        actor.associate_technique(actor.tenant_id, AttackTechniqueReference("T1566"), _now())
        with pytest.raises(DuplicateTechniqueAssociationError):
            actor.associate_technique(actor.tenant_id, AttackTechniqueReference("T1566"), _now())

    def test_associate_technique_wrong_tenant_raises(self) -> None:
        actor = _register()
        with pytest.raises(TenantMismatch):
            actor.associate_technique(
                TenantId.generate(), AttackTechniqueReference("T1566"), _now()
            )

    def test_three_techniques_with_expert_sophistication_raises_confidence_to_high(self) -> None:
        actor = _register(sophistication=SophisticationLevel.EXPERT)
        now = _now()
        actor.associate_technique(actor.tenant_id, AttackTechniqueReference("T1566"), now)
        actor.associate_technique(actor.tenant_id, AttackTechniqueReference("T1071"), now)
        assert actor.attribution_confidence == AttributionConfidence.MEDIUM
        actor.associate_technique(actor.tenant_id, AttackTechniqueReference("T1055"), now)
        assert actor.attribution_confidence == AttributionConfidence.HIGH

    def test_one_technique_at_novice_sophistication_is_medium_not_high(self) -> None:
        actor = _register(sophistication=SophisticationLevel.NOVICE)
        actor.associate_technique(actor.tenant_id, AttackTechniqueReference("T1566"), _now())
        assert actor.attribution_confidence == AttributionConfidence.MEDIUM


class TestIndicatorAssociation:
    def test_associate_indicator(self) -> None:
        actor = _register()
        actor.associate_indicator(actor.tenant_id, FusedIndicatorReference("ind-1"), _now())
        assert len(actor.indicator_refs) == 1
        assert actor.attribution_confidence == AttributionConfidence.MEDIUM

    def test_duplicate_indicator_raises(self) -> None:
        actor = _register()
        actor.associate_indicator(actor.tenant_id, FusedIndicatorReference("ind-1"), _now())
        with pytest.raises(DuplicateIndicatorAssociationError):
            actor.associate_indicator(actor.tenant_id, FusedIndicatorReference("ind-1"), _now())


class TestMotivationAndSophisticationUpdates:
    def test_update_motivations(self) -> None:
        actor = _register()
        actor.update_motivations(actor.tenant_id, frozenset({MotivationType.FINANCIAL}), _now())
        assert actor.motivations == frozenset({MotivationType.FINANCIAL})

    def test_update_motivations_rejects_empty(self) -> None:
        actor = _register()
        with pytest.raises(EmptyMotivationSetError):
            actor.update_motivations(actor.tenant_id, frozenset(), _now())

    def test_update_sophistication_recomputes_confidence(self) -> None:
        actor = _register(sophistication=SophisticationLevel.NOVICE)
        actor.associate_technique(actor.tenant_id, AttackTechniqueReference("T1"), _now())
        actor.associate_technique(actor.tenant_id, AttackTechniqueReference("T2"), _now())
        actor.associate_technique(actor.tenant_id, AttackTechniqueReference("T3"), _now())
        assert actor.attribution_confidence == AttributionConfidence.MEDIUM
        actor.update_sophistication(actor.tenant_id, SophisticationLevel.INNOVATOR, _now())
        assert actor.attribution_confidence == AttributionConfidence.HIGH


class TestActivityLifecycle:
    def test_mark_dormant_then_reactivate(self) -> None:
        actor = _register()
        actor.mark_dormant(actor.tenant_id, _now())
        assert actor.status == ActivityStatus.DORMANT
        actor.reactivate(actor.tenant_id, _now())
        assert actor.status == ActivityStatus.ACTIVE

    def test_disband_from_active(self) -> None:
        actor = _register()
        actor.disband(actor.tenant_id, _now())
        assert actor.status == ActivityStatus.DISBANDED

    def test_disband_from_dormant(self) -> None:
        actor = _register()
        actor.mark_dormant(actor.tenant_id, _now())
        actor.disband(actor.tenant_id, _now())
        assert actor.status == ActivityStatus.DISBANDED

    def test_disbanded_is_terminal(self) -> None:
        actor = _register()
        actor.disband(actor.tenant_id, _now())
        with pytest.raises(InvalidActivityStatusTransition):
            actor.reactivate(actor.tenant_id, _now())
        with pytest.raises(InvalidActivityStatusTransition):
            actor.mark_dormant(actor.tenant_id, _now())

    def test_cannot_reactivate_already_active(self) -> None:
        actor = _register()
        with pytest.raises(InvalidActivityStatusTransition):
            actor.reactivate(actor.tenant_id, _now())

    def test_status_change_wrong_tenant_raises(self) -> None:
        actor = _register()
        with pytest.raises(TenantMismatch):
            actor.mark_dormant(TenantId.generate(), _now())


class TestGlobalReferenceRecords:
    """ADR-M51.1-02: `tenant_id=None` represents a genuine global
    reference record — never a fake/reserved system tenant."""

    def test_register_global_actor_with_none_tenant(self) -> None:
        actor = ThreatActor.register(
            threat_actor_id=ThreatActorId.generate(),
            tenant_id=None,
            name=ThreatActorName("APT29"),
            origin=ThreatActorOrigin.NATION_STATE,
            motivations=frozenset({MotivationType.ESPIONAGE}),
            sophistication=SophisticationLevel.NOVICE,
            now=_now(),
        )
        assert actor.tenant_id is None

    def test_global_actor_registered_event_has_empty_tenant_id_not_string_none(self) -> None:
        actor = ThreatActor.register(
            threat_actor_id=ThreatActorId.generate(),
            tenant_id=None,
            name=ThreatActorName("APT29"),
            origin=ThreatActorOrigin.NATION_STATE,
            motivations=frozenset({MotivationType.ESPIONAGE}),
            sophistication=SophisticationLevel.NOVICE,
            now=_now(),
        )
        events = actor.pop_events()
        assert events[0].tenant_id == ""
        assert events[0].tenant_id != "None"

    def test_global_actor_mutation_requires_none_tenant_not_a_real_tenant(self) -> None:
        actor = ThreatActor.register(
            threat_actor_id=ThreatActorId.generate(),
            tenant_id=None,
            name=ThreatActorName("APT29"),
            origin=ThreatActorOrigin.NATION_STATE,
            motivations=frozenset({MotivationType.ESPIONAGE}),
            sophistication=SophisticationLevel.NOVICE,
            now=_now(),
        )
        with pytest.raises(TenantMismatch):
            actor.add_alias(TenantId.generate(), Alias("Cozy Bear"), _now())
        # Passing None (matching the global record's own tenant context)
        # succeeds — no fake sentinel tenant is ever required.
        actor.add_alias(None, Alias("Cozy Bear"), _now())
        assert len(actor.aliases) == 1

    def test_tenant_scoped_actor_rejects_none_tenant(self) -> None:
        actor = _register()
        with pytest.raises(TenantMismatch):
            actor.add_alias(None, Alias("Cozy Bear"), _now())

    def test_global_actor_full_lifecycle_unaffected_by_tenancy(self) -> None:
        actor = ThreatActor.register(
            threat_actor_id=ThreatActorId.generate(),
            tenant_id=None,
            name=ThreatActorName("APT29"),
            origin=ThreatActorOrigin.NATION_STATE,
            motivations=frozenset({MotivationType.ESPIONAGE}),
            sophistication=SophisticationLevel.EXPERT,
            now=_now(),
        )
        now = _now()
        actor.associate_technique(None, AttackTechniqueReference("T1566"), now)
        actor.associate_technique(None, AttackTechniqueReference("T1071"), now)
        actor.associate_technique(None, AttackTechniqueReference("T1055"), now)
        assert actor.attribution_confidence == AttributionConfidence.HIGH
        actor.mark_dormant(None, now)
        assert actor.status == ActivityStatus.DORMANT
