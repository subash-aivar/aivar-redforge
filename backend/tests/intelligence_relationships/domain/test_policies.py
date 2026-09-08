from __future__ import annotations

import pytest

from intelligence_relationships.domain.exceptions.domain_exceptions import (
    DuplicateRelationshipError,
    IncompatibleRelationshipEndpointsError,
    InvalidEpistemicStateTransitionError,
    InvalidLifecycleTransitionError,
    SelfReferentialRelationshipError,
)
from intelligence_relationships.domain.policies.epistemic_transition_policy import (
    EpistemicTransitionPolicy,
)
from intelligence_relationships.domain.policies.identity_policy import (
    RelationshipIdentityPolicy,
    identity_key,
)
from intelligence_relationships.domain.policies.lifecycle_transition_policy import (
    LifecycleTransitionPolicy,
)
from intelligence_relationships.domain.policies.type_compatibility_policy import (
    RelationshipTypeCompatibilityPolicy,
)
from intelligence_relationships.domain.value_objects.entity_ref import EntityRef
from intelligence_relationships.domain.value_objects.enums import (
    EntityType,
    EpistemicState,
    RelationshipLifecycleStatus,
    RelationshipType,
)
from tests.intelligence_relationships.domain.helpers import (
    campaign_ref,
    make_relationship,
    malware_ref,
)

# ── LifecycleTransitionPolicy ────────────────────────────────────────────

ACTIVE = RelationshipLifecycleStatus.ACTIVE
DEPRECATED = RelationshipLifecycleStatus.DEPRECATED
REVOKED = RelationshipLifecycleStatus.REVOKED
SUPERSEDED = RelationshipLifecycleStatus.SUPERSEDED


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (ACTIVE, DEPRECATED),
        (ACTIVE, REVOKED),
        (ACTIVE, SUPERSEDED),
        (DEPRECATED, REVOKED),
        (DEPRECATED, ACTIVE),
        (SUPERSEDED, REVOKED),
    ],
)
def test_legal_lifecycle_transitions(
    current: RelationshipLifecycleStatus, target: RelationshipLifecycleStatus
) -> None:
    LifecycleTransitionPolicy.assert_legal_transition(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (ACTIVE, ACTIVE),
        (DEPRECATED, SUPERSEDED),
        (SUPERSEDED, ACTIVE),
        (SUPERSEDED, DEPRECATED),
        (REVOKED, ACTIVE),
        (REVOKED, DEPRECATED),
        (REVOKED, SUPERSEDED),
        (REVOKED, REVOKED),
    ],
)
def test_illegal_lifecycle_transitions(
    current: RelationshipLifecycleStatus, target: RelationshipLifecycleStatus
) -> None:
    with pytest.raises(InvalidLifecycleTransitionError):
        LifecycleTransitionPolicy.assert_legal_transition(current, target)


def test_revoked_is_terminal_in_the_lifecycle_graph() -> None:
    assert LifecycleTransitionPolicy.allowed_targets(REVOKED) == frozenset()


def test_lifecycle_table_covers_every_status() -> None:
    for status in RelationshipLifecycleStatus:
        assert isinstance(LifecycleTransitionPolicy.allowed_targets(status), frozenset)


# ── EpistemicTransitionPolicy ────────────────────────────────────────────

OBS = EpistemicState.OBSERVATION
EV = EpistemicState.EVIDENCE
HYP = EpistemicState.HYPOTHESIS
COR = EpistemicState.CORROBORATED
VAL = EpistemicState.VALIDATED
DIS = EpistemicState.DISPUTED
REF = EpistemicState.REFUTED
HIST = EpistemicState.HISTORICAL
RET = EpistemicState.RETIRED

_EXITS = (HIST, RET, REF)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (OBS, EV),
        (EV, HYP),
        (HYP, COR),
        (HYP, DIS),
        (COR, VAL),
        (COR, DIS),
        (VAL, DIS),
        (DIS, HYP),
        (DIS, COR),
        (DIS, VAL),
        *[(state, exit_) for state in (HYP, COR, VAL, DIS) for exit_ in _EXITS],
    ],
)
def test_legal_epistemic_transitions(current: EpistemicState, target: EpistemicState) -> None:
    EpistemicTransitionPolicy.assert_legal_transition(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (OBS, HYP),
        (OBS, VAL),
        (OBS, DIS),
        (OBS, REF),
        (EV, COR),
        (EV, DIS),
        (EV, REF),
        (HYP, EV),
        (COR, HYP),
        (VAL, COR),
        (DIS, EV),
        (DIS, OBS),
        *[(terminal, target) for terminal in _EXITS for target in (HYP, COR, VAL, DIS)],
    ],
)
def test_illegal_epistemic_transitions(current: EpistemicState, target: EpistemicState) -> None:
    with pytest.raises(InvalidEpistemicStateTransitionError):
        EpistemicTransitionPolicy.assert_legal_transition(current, target)


def test_disputed_is_re_enterable_not_a_dead_end() -> None:
    """The deliberate correction to a naive linear pipeline: a disputed
    claim can be re-argued back up the hierarchy."""
    for target in (HYP, COR, VAL):
        EpistemicTransitionPolicy.assert_legal_transition(DIS, target)


def test_terminal_states_are_exactly_historical_retired_refuted() -> None:
    for state in EpistemicState:
        assert EpistemicTransitionPolicy.is_terminal(state) is (state in _EXITS)
        if state in _EXITS:
            assert EpistemicTransitionPolicy.allowed_targets(state) == frozenset()


def test_early_states_cannot_exit_directly_to_terminal() -> None:
    """OBSERVATION and EVIDENCE are too weak to be *refuted* or retired —
    they must first become a HYPOTHESIS."""
    for state in (OBS, EV):
        for exit_ in _EXITS:
            with pytest.raises(InvalidEpistemicStateTransitionError):
                EpistemicTransitionPolicy.assert_legal_transition(state, exit_)


def test_epistemic_table_covers_every_state() -> None:
    for state in EpistemicState:
        assert isinstance(EpistemicTransitionPolicy.allowed_targets(state), frozenset)


# ── RelationshipTypeCompatibilityPolicy ──────────────────────────────────

_EXPECTED_PAIRS = {
    RelationshipType.IOC_TO_MALWARE: (EntityType.IOC, EntityType.MALWARE),
    RelationshipType.IOC_TO_TOOL: (EntityType.IOC, EntityType.TOOL),
    RelationshipType.IOC_TO_INFRASTRUCTURE: (EntityType.IOC, EntityType.INFRASTRUCTURE),
    RelationshipType.IOC_TO_THREAT_ACTOR: (EntityType.IOC, EntityType.THREAT_ACTOR),
    RelationshipType.IOC_TO_CAMPAIGN: (EntityType.IOC, EntityType.CAMPAIGN),
    RelationshipType.IOC_TO_ATTACK_PATTERN: (EntityType.IOC, EntityType.ATTACK_PATTERN),
    RelationshipType.MALWARE_TO_CAMPAIGN: (EntityType.MALWARE, EntityType.CAMPAIGN),
    RelationshipType.CAMPAIGN_TO_THREAT_ACTOR: (EntityType.CAMPAIGN, EntityType.THREAT_ACTOR),
    RelationshipType.TOOL_TO_THREAT_ACTOR: (EntityType.TOOL, EntityType.THREAT_ACTOR),
    RelationshipType.INFRASTRUCTURE_TO_CAMPAIGN: (EntityType.INFRASTRUCTURE, EntityType.CAMPAIGN),
    RelationshipType.THREAT_REPORT_TO_THREAT_ACTOR: (
        EntityType.THREAT_REPORT,
        EntityType.THREAT_ACTOR,
    ),
    RelationshipType.THREAT_REPORT_TO_CAMPAIGN: (EntityType.THREAT_REPORT, EntityType.CAMPAIGN),
    RelationshipType.THREAT_REPORT_TO_MALWARE: (EntityType.THREAT_REPORT, EntityType.MALWARE),
    RelationshipType.THREAT_REPORT_TO_TOOL: (EntityType.THREAT_REPORT, EntityType.TOOL),
    RelationshipType.THREAT_REPORT_TO_INFRASTRUCTURE: (
        EntityType.THREAT_REPORT,
        EntityType.INFRASTRUCTURE,
    ),
    RelationshipType.THREAT_REPORT_TO_ATTACK_PATTERN: (
        EntityType.THREAT_REPORT,
        EntityType.ATTACK_PATTERN,
    ),
    RelationshipType.THREAT_REPORT_TO_IOC: (EntityType.THREAT_REPORT, EntityType.IOC),
}


def test_every_relationship_type_has_exactly_one_required_pairing() -> None:
    for relationship_type in RelationshipType:
        assert (
            RelationshipTypeCompatibilityPolicy.required_endpoints(relationship_type)
            == _EXPECTED_PAIRS[relationship_type]
        )


@pytest.mark.parametrize("relationship_type", list(RelationshipType))
def test_matching_endpoints_are_accepted(relationship_type: RelationshipType) -> None:
    source_type, target_type = _EXPECTED_PAIRS[relationship_type]
    RelationshipTypeCompatibilityPolicy.assert_compatible(
        relationship_type,
        EntityRef(source_type, "source-1"),
        EntityRef(target_type, "target-1"),
    )


def test_swapped_endpoints_are_rejected() -> None:
    with pytest.raises(IncompatibleRelationshipEndpointsError) as exc:
        RelationshipTypeCompatibilityPolicy.assert_compatible(
            RelationshipType.MALWARE_TO_CAMPAIGN,
            campaign_ref("c1"),
            malware_ref("m1"),
        )
    assert exc.value.expected_source == "malware"
    assert exc.value.actual_source == "campaign"


def test_wrong_target_type_is_rejected() -> None:
    with pytest.raises(IncompatibleRelationshipEndpointsError):
        RelationshipTypeCompatibilityPolicy.assert_compatible(
            RelationshipType.IOC_TO_MALWARE,
            EntityRef(EntityType.IOC, "i1"),
            EntityRef(EntityType.CAMPAIGN, "c1"),
        )


def test_threat_report_is_always_the_source_in_every_pairing_that_admits_it() -> None:
    """M51.9 Phase H1 closed the vocabulary gap: THREAT_REPORT now
    appears as the source in exactly seven pairings (never as a
    target), one per other real/opaque entity type."""
    threat_report_pairs = [
        pair for pair in _EXPECTED_PAIRS.values() if EntityType.THREAT_REPORT in pair
    ]
    assert len(threat_report_pairs) == 7
    for source, target in threat_report_pairs:
        assert source is EntityType.THREAT_REPORT
        assert target is not EntityType.THREAT_REPORT
    targets = {target for _, target in threat_report_pairs}
    assert targets == {
        EntityType.THREAT_ACTOR,
        EntityType.CAMPAIGN,
        EntityType.MALWARE,
        EntityType.TOOL,
        EntityType.INFRASTRUCTURE,
        EntityType.ATTACK_PATTERN,
        EntityType.IOC,
    }


def test_threat_report_relationship_types_are_rejected_with_swapped_endpoints() -> None:
    """A THREAT_REPORT can never be the target of its own relationship
    type — e.g. IOC -> THREAT_REPORT is not the same as
    THREAT_REPORT_TO_IOC and must be rejected."""
    with pytest.raises(IncompatibleRelationshipEndpointsError):
        RelationshipTypeCompatibilityPolicy.assert_compatible(
            RelationshipType.THREAT_REPORT_TO_IOC,
            EntityRef(EntityType.IOC, "i1"),
            EntityRef(EntityType.THREAT_REPORT, "r1"),
        )


def test_no_relationship_type_joins_two_endpoints_of_the_same_kind() -> None:
    """Because every pairing joins two *different* entity types, an
    identical source/target pair can never be structurally compatible —
    the type check rejects it before the self-reference guard is
    reached. The guard below remains as defense-in-depth for any future
    same-type relationship kind."""
    for source_type, target_type in _EXPECTED_PAIRS.values():
        assert source_type is not target_type


def test_identical_endpoints_are_always_rejected() -> None:
    same = EntityRef(EntityType.IOC, "identical")
    with pytest.raises(IncompatibleRelationshipEndpointsError):
        RelationshipTypeCompatibilityPolicy.assert_compatible(
            RelationshipType.IOC_TO_MALWARE, same, same
        )


def test_self_reference_guard_rejects_a_structurally_compatible_identical_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Directly exercises the guard by temporarily declaring a
    same-type pairing, proving it fires once the type check passes."""
    import intelligence_relationships.domain.policies.type_compatibility_policy as mod

    monkeypatch.setitem(
        mod._REQUIRED_ENDPOINTS,
        RelationshipType.IOC_TO_MALWARE,
        (EntityType.IOC, EntityType.IOC),
    )
    same = EntityRef(EntityType.IOC, "identical")
    with pytest.raises(SelfReferentialRelationshipError):
        RelationshipTypeCompatibilityPolicy.assert_compatible(
            RelationshipType.IOC_TO_MALWARE, same, same
        )


# ── RelationshipIdentityPolicy ───────────────────────────────────────────


def test_identity_key_is_type_and_endpoint_qualified() -> None:
    key = identity_key(RelationshipType.MALWARE_TO_CAMPAIGN, malware_ref("m1"), campaign_ref("c1"))
    assert key == "malware_to_campaign|malware:m1|campaign:c1"


def test_duplicate_identity_is_rejected() -> None:
    source, target = malware_ref("m1"), campaign_ref("c1")
    existing = make_relationship(source_entity=source, target_entity=target)
    with pytest.raises(DuplicateRelationshipError):
        RelationshipIdentityPolicy.assert_no_duplicate(
            [existing], RelationshipType.MALWARE_TO_CAMPAIGN, source, target
        )


def test_different_endpoints_are_not_duplicates() -> None:
    existing = make_relationship(source_entity=malware_ref("m1"), target_entity=campaign_ref("c1"))
    RelationshipIdentityPolicy.assert_no_duplicate(
        [existing],
        RelationshipType.MALWARE_TO_CAMPAIGN,
        malware_ref("m2"),
        campaign_ref("c1"),
    )


def test_reversed_endpoints_are_not_duplicates() -> None:
    """Identity is an ORDERED pair — (a -> b) and (b -> a) are different
    edges even for a bidirectional claim."""
    existing = make_relationship(source_entity=malware_ref("m1"), target_entity=campaign_ref("c1"))
    key = identity_key(RelationshipType.MALWARE_TO_CAMPAIGN, campaign_ref("c1"), malware_ref("m1"))
    assert existing.identity_key != key


def test_empty_existing_set_is_never_a_duplicate() -> None:
    RelationshipIdentityPolicy.assert_no_duplicate(
        [], RelationshipType.MALWARE_TO_CAMPAIGN, malware_ref("m1"), campaign_ref("c1")
    )
