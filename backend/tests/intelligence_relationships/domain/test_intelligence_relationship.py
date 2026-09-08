from __future__ import annotations

import pytest

from intelligence_relationships.domain.events.relationship_events import (
    EpistemicStateTransitioned,
    EvidenceCitationAdded,
    IntelligenceRelationshipDeprecated,
    IntelligenceRelationshipObserved,
    IntelligenceRelationshipReactivated,
    IntelligenceRelationshipRevoked,
    IntelligenceRelationshipSuperseded,
    SourceAttributionAdded,
)
from intelligence_relationships.domain.exceptions.domain_exceptions import (
    IncompatibleRelationshipEndpointsError,
    InvalidEpistemicStateTransitionError,
    InvalidLifecycleTransitionError,
    TenantMismatchError,
)
from intelligence_relationships.domain.value_objects.enums import (
    EpistemicState,
    RelationshipConfidence,
    RelationshipDirection,
    RelationshipLifecycleStatus,
    RelationshipType,
)
from intelligence_relationships.domain.value_objects.evidence import EvidenceCitation
from intelligence_relationships.domain.value_objects.identifiers import (
    IntelligenceRelationshipId,
)
from tests.intelligence_relationships.domain.helpers import (
    NOW,
    campaign_ref,
    make_attribution,
    make_relationship,
    make_tenant_id,
    malware_ref,
)

# ── Observation ──────────────────────────────────────────────────────────


def test_observe_starts_active_at_observation_with_version_one() -> None:
    relationship = make_relationship()
    assert relationship.lifecycle_status is RelationshipLifecycleStatus.ACTIVE
    assert relationship.epistemic_state is EpistemicState.OBSERVATION
    assert len(relationship.version_history) == 1
    assert relationship.version_history[0].version == 1
    assert relationship.version_history[0].change_summary == "Observed"
    assert relationship.superseded_by is None
    assert relationship.row_version == 1


def test_observe_emits_observed_event_with_endpoint_payload() -> None:
    tenant_id = make_tenant_id()
    relationship = make_relationship(
        tenant_id=tenant_id,
        source_entity=malware_ref("m1"),
        target_entity=campaign_ref("c1"),
    )
    events = relationship.pop_events()
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, IntelligenceRelationshipObserved)
    assert event.aggregate_type == "IntelligenceRelationship"
    assert event.aggregate_id == str(relationship.relationship_id)
    assert event.tenant_id == str(tenant_id)
    assert event.source_entity == "malware:m1"
    assert event.target_entity == "campaign:c1"
    assert event.relationship_type == "malware_to_campaign"


def test_global_relationship_renders_empty_tenant_in_events() -> None:
    relationship = make_relationship(tenant_id=None)
    assert relationship.tenant_id is None
    assert relationship.pop_events()[0].tenant_id == ""


def test_observe_rejects_incompatible_endpoints() -> None:
    with pytest.raises(IncompatibleRelationshipEndpointsError):
        make_relationship(
            relationship_type=RelationshipType.IOC_TO_MALWARE,
            source_entity=campaign_ref("c1"),
            target_entity=malware_ref("m1"),
        )


def test_identity_key_is_stable_and_immutable_after_creation() -> None:
    relationship = make_relationship(
        source_entity=malware_ref("m1"), target_entity=campaign_ref("c1")
    )
    before = relationship.identity_key
    relationship.deprecate(relationship.tenant_id, make_attribution(), NOW)
    assert relationship.identity_key == before == "malware_to_campaign|malware:m1|campaign:c1"


def test_aggregate_has_no_identity_mutators() -> None:
    """Identity fields are set once by `observe` — the aggregate exposes
    no method that rewrites the type or either endpoint."""
    forbidden = {"set_relationship_type", "set_source_entity", "set_target_entity", "rename"}
    assert forbidden.isdisjoint(dir(make_relationship()))


def test_pop_events_drains_the_pending_list() -> None:
    relationship = make_relationship()
    assert relationship.pop_events()
    assert relationship.pop_events() == []


# ── Tenant isolation ─────────────────────────────────────────────────────


def test_every_mutator_rejects_a_mismatched_tenant() -> None:
    owner = make_tenant_id()
    intruder = make_tenant_id()
    relationship = make_relationship(tenant_id=owner)
    evidence = make_attribution()

    with pytest.raises(TenantMismatchError):
        relationship.add_evidence_citation(intruder, EvidenceCitation("x"), NOW)
    with pytest.raises(TenantMismatchError):
        relationship.add_source_attribution(intruder, evidence, NOW)
    with pytest.raises(TenantMismatchError):
        relationship.transition_epistemic_state(intruder, EpistemicState.EVIDENCE, evidence, NOW)
    with pytest.raises(TenantMismatchError):
        relationship.deprecate(intruder, evidence, NOW)
    with pytest.raises(TenantMismatchError):
        relationship.revoke(intruder, evidence, NOW)
    with pytest.raises(TenantMismatchError):
        relationship.supersede(intruder, IntelligenceRelationshipId.generate(), evidence, NOW)


def test_tenant_scoped_record_rejects_a_global_caller() -> None:
    relationship = make_relationship(tenant_id=make_tenant_id())
    with pytest.raises(TenantMismatchError):
        relationship.deprecate(None, make_attribution(), NOW)


def test_global_record_rejects_a_tenant_caller() -> None:
    relationship = make_relationship(tenant_id=None)
    with pytest.raises(TenantMismatchError):
        relationship.deprecate(make_tenant_id(), make_attribution(), NOW)


# ── Evidence enrichment ──────────────────────────────────────────────────


def test_add_evidence_citation_appends_records_version_and_emits() -> None:
    relationship = make_relationship()
    relationship.pop_events()
    relationship.add_evidence_citation(relationship.tenant_id, EvidenceCitation("report-1"), NOW)
    assert [c.value for c in relationship.evidence_citations] == ["report-1"]
    assert len(relationship.version_history) == 2
    assert relationship.version_history[1].version == 2
    events = relationship.pop_events()
    assert isinstance(events[0], EvidenceCitationAdded)
    assert events[0].citation == "report-1"


def test_add_source_attribution_appends_records_version_and_emits() -> None:
    relationship = make_relationship()
    relationship.pop_events()
    attribution = make_attribution("vendor-x")
    relationship.add_source_attribution(relationship.tenant_id, attribution, NOW)
    assert relationship.source_attributions == (attribution,)
    assert len(relationship.version_history) == 2
    events = relationship.pop_events()
    assert isinstance(events[0], SourceAttributionAdded)
    assert events[0].source_system == "vendor-x"
    assert events[0].confidence == RelationshipConfidence.HIGH.value


def test_evidence_accumulates_in_order() -> None:
    relationship = make_relationship()
    for i in range(3):
        relationship.add_evidence_citation(relationship.tenant_id, EvidenceCitation(f"c{i}"), NOW)
    assert [c.value for c in relationship.evidence_citations] == ["c0", "c1", "c2"]


# ── Epistemic axis ───────────────────────────────────────────────────────


def test_epistemic_transition_updates_state_versions_and_emits() -> None:
    relationship = make_relationship()
    relationship.pop_events()
    relationship.transition_epistemic_state(
        relationship.tenant_id, EpistemicState.EVIDENCE, make_attribution(), NOW
    )
    assert relationship.epistemic_state is EpistemicState.EVIDENCE
    assert (
        relationship.version_history[-1].change_summary == "Epistemic state observation -> evidence"
    )
    event = relationship.pop_events()[0]
    assert isinstance(event, EpistemicStateTransitioned)
    assert (event.from_state, event.to_state) == ("observation", "evidence")


def test_illegal_epistemic_transition_is_rejected_and_leaves_state_untouched() -> None:
    relationship = make_relationship()
    with pytest.raises(InvalidEpistemicStateTransitionError):
        relationship.transition_epistemic_state(
            relationship.tenant_id, EpistemicState.VALIDATED, make_attribution(), NOW
        )
    assert relationship.epistemic_state is EpistemicState.OBSERVATION
    assert len(relationship.version_history) == 1


def test_full_epistemic_walk_up_and_into_dispute_and_back() -> None:
    relationship = make_relationship()
    for state in (
        EpistemicState.EVIDENCE,
        EpistemicState.HYPOTHESIS,
        EpistemicState.CORROBORATED,
        EpistemicState.VALIDATED,
        EpistemicState.DISPUTED,
        EpistemicState.CORROBORATED,
    ):
        relationship.transition_epistemic_state(
            relationship.tenant_id, state, make_attribution(), NOW
        )
    assert relationship.epistemic_state is EpistemicState.CORROBORATED
    assert len(relationship.version_history) == 7


def test_terminal_epistemic_state_admits_no_further_transition() -> None:
    relationship = make_relationship()
    for state in (
        EpistemicState.EVIDENCE,
        EpistemicState.HYPOTHESIS,
        EpistemicState.REFUTED,
    ):
        relationship.transition_epistemic_state(
            relationship.tenant_id, state, make_attribution(), NOW
        )
    with pytest.raises(InvalidEpistemicStateTransitionError):
        relationship.transition_epistemic_state(
            relationship.tenant_id, EpistemicState.HYPOTHESIS, make_attribution(), NOW
        )


def test_epistemic_and_lifecycle_axes_are_independent() -> None:
    """A deprecated relationship's claim can still be re-evaluated, and
    an epistemically refuted claim is still lifecycle-ACTIVE until
    someone acts on it."""
    relationship = make_relationship()
    relationship.deprecate(relationship.tenant_id, make_attribution(), NOW)
    relationship.transition_epistemic_state(
        relationship.tenant_id, EpistemicState.EVIDENCE, make_attribution(), NOW
    )
    assert relationship.lifecycle_status is RelationshipLifecycleStatus.DEPRECATED
    assert relationship.epistemic_state is EpistemicState.EVIDENCE


# ── Lifecycle axis ───────────────────────────────────────────────────────


def test_deprecate_transitions_records_version_and_emits() -> None:
    relationship = make_relationship()
    relationship.pop_events()
    relationship.deprecate(relationship.tenant_id, make_attribution(), NOW)
    assert relationship.lifecycle_status is RelationshipLifecycleStatus.DEPRECATED
    assert relationship.version_history[-1].change_summary == "Deprecated"
    assert isinstance(relationship.pop_events()[0], IntelligenceRelationshipDeprecated)


def test_revoke_is_terminal() -> None:
    relationship = make_relationship()
    relationship.revoke(relationship.tenant_id, make_attribution(), NOW)
    assert relationship.lifecycle_status is RelationshipLifecycleStatus.REVOKED
    assert isinstance(relationship.pop_events()[-1], IntelligenceRelationshipRevoked)
    for mutate in ("deprecate", "reactivate"):
        with pytest.raises(InvalidLifecycleTransitionError):
            getattr(relationship, mutate)(relationship.tenant_id, make_attribution(), NOW)


def test_supersede_sets_pointer_and_emits() -> None:
    relationship = make_relationship()
    relationship.pop_events()
    successor = IntelligenceRelationshipId.generate()
    relationship.supersede(relationship.tenant_id, successor, make_attribution(), NOW)
    assert relationship.lifecycle_status is RelationshipLifecycleStatus.SUPERSEDED
    assert relationship.superseded_by == successor
    event = relationship.pop_events()[0]
    assert isinstance(event, IntelligenceRelationshipSuperseded)
    assert event.superseded_by == str(successor)


def test_superseded_can_only_be_revoked() -> None:
    relationship = make_relationship()
    relationship.supersede(
        relationship.tenant_id, IntelligenceRelationshipId.generate(), make_attribution(), NOW
    )
    with pytest.raises(InvalidLifecycleTransitionError):
        relationship.reactivate(relationship.tenant_id, make_attribution(), NOW)
    relationship.revoke(relationship.tenant_id, make_attribution(), NOW)
    assert relationship.lifecycle_status is RelationshipLifecycleStatus.REVOKED


def test_reactivate_from_deprecated_clears_superseded_by_and_emits() -> None:
    relationship = make_relationship()
    relationship.deprecate(relationship.tenant_id, make_attribution(), NOW)
    relationship.pop_events()
    relationship.reactivate(relationship.tenant_id, make_attribution(), NOW)
    assert relationship.lifecycle_status is RelationshipLifecycleStatus.ACTIVE
    assert relationship.superseded_by is None
    assert isinstance(relationship.pop_events()[0], IntelligenceRelationshipReactivated)


def test_reactivate_from_active_is_illegal() -> None:
    relationship = make_relationship()
    with pytest.raises(InvalidLifecycleTransitionError):
        relationship.reactivate(relationship.tenant_id, make_attribution(), NOW)


# ── Version history is append-only and monotonic ─────────────────────────


def test_every_mutator_appends_exactly_one_monotonic_version() -> None:
    relationship = make_relationship()
    relationship.add_evidence_citation(relationship.tenant_id, EvidenceCitation("c"), NOW)
    relationship.add_source_attribution(relationship.tenant_id, make_attribution(), NOW)
    relationship.transition_epistemic_state(
        relationship.tenant_id, EpistemicState.EVIDENCE, make_attribution(), NOW
    )
    relationship.deprecate(relationship.tenant_id, make_attribution(), NOW)
    relationship.reactivate(relationship.tenant_id, make_attribution(), NOW)
    relationship.revoke(relationship.tenant_id, make_attribution(), NOW)

    versions = [v.version for v in relationship.version_history]
    assert versions == [1, 2, 3, 4, 5, 6, 7]
    assert relationship.updated_at == NOW


def test_every_mutator_emits_exactly_one_event() -> None:
    relationship = make_relationship()
    relationship.pop_events()
    relationship.add_evidence_citation(relationship.tenant_id, EvidenceCitation("c"), NOW)
    relationship.deprecate(relationship.tenant_id, make_attribution(), NOW)
    relationship.revoke(relationship.tenant_id, make_attribution(), NOW)
    assert len(relationship.pop_events()) == 3


def test_direction_and_confidence_are_carried_through_construction() -> None:
    relationship = make_relationship(
        direction=RelationshipDirection.BIDIRECTIONAL,
        confidence=RelationshipConfidence.VERY_HIGH,
    )
    assert relationship.direction is RelationshipDirection.BIDIRECTIONAL
    assert relationship.confidence is RelationshipConfidence.VERY_HIGH
