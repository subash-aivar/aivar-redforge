from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ioc_intelligence.domain.aggregates.ioc import IOC
from ioc_intelligence.domain.events.ioc_events import (
    IocEpistemicStateChanged,
    IocExpired,
    IocObserved,
    IocRefuted,
    IocRevoked,
    IocSourceAdded,
    IocSuperseded,
)
from ioc_intelligence.domain.exceptions.domain_exceptions import (
    DuplicateSourceAttributionError,
    InvalidEpistemicStateTransitionError,
    InvalidLifecycleTransitionError,
    MissingTenantForObservationError,
    TenantMismatchError,
    UnsourcedIocError,
)
from ioc_intelligence.domain.value_objects.enums import EpistemicState, IocLifecycle, IocType
from ioc_intelligence.domain.value_objects.evidence import EvidenceCitation
from ioc_intelligence.domain.value_objects.identifiers import IocId, TenantId
from ioc_intelligence.domain.value_objects.indicator_value import IndicatorCanonicalKey
from ioc_intelligence.domain.value_objects.provenance import SourceAttribution
from ioc_intelligence.domain.value_objects.validity import ValidityWindow


def _now() -> datetime:
    return datetime(2026, 8, 4, tzinfo=UTC)


def _validity() -> ValidityWindow:
    return ValidityWindow(valid_from=_now(), valid_until=None)


def _attribution(
    source_system: str = "alienvault_otx", external_id: str = "pulse-1"
) -> SourceAttribution:
    from ioc_intelligence.domain.value_objects.enums import SourceConfidence

    return SourceAttribution(
        source_system=source_system,
        external_id=external_id,
        content_hash=None,
        observed_at=_now(),
        weight_applied=0.9,
        confidence=SourceConfidence.HIGH,
    )


def _canonical_key(value: str = "1.2.3.4") -> IndicatorCanonicalKey:
    return IndicatorCanonicalKey.for_type(IocType.IP, value)


class TestObservation:
    def test_valid_global_ioc_observed_from_approved_source(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        assert ioc.tenant_id is None
        assert ioc.lifecycle is IocLifecycle.ACTIVE
        assert ioc.epistemic_state is EpistemicState.OBSERVATION
        events = ioc.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], IocObserved)

    def test_valid_tenant_ioc_observed_from_tenant_evidence(self) -> None:
        tenant_id = TenantId.generate()
        ioc = IOC.observe_tenant(
            ioc_id=IocId.generate(),
            tenant_id=tenant_id,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            evidence_citations=(EvidenceCitation("internal-finding-1"),),
        )
        assert ioc.tenant_id == tenant_id
        events = ioc.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], IocObserved)

    def test_unsourced_ioc_rejected(self) -> None:
        with pytest.raises(UnsourcedIocError):
            IOC.observe(
                ioc_id=IocId.generate(),
                tenant_id=None,
                canonical_key=_canonical_key(),
                validity_window=_validity(),
                now=_now(),
            )

    def test_tenant_observation_requires_real_tenant_id(self) -> None:
        with pytest.raises(MissingTenantForObservationError):
            IOC.observe_tenant(
                ioc_id=IocId.generate(),
                tenant_id=None,  # type: ignore[arg-type]
                canonical_key=_canonical_key(),
                validity_window=_validity(),
                now=_now(),
                evidence_citations=(EvidenceCitation("x"),),
            )

    def test_no_fake_system_tenant_exists(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        assert ioc.tenant_id is None
        import ioc_intelligence.domain.value_objects.identifiers as identifiers_module

        assert not hasattr(identifiers_module, "SYSTEM_TENANT")
        assert not hasattr(identifiers_module, "SYSTEM_TENANT_ID")

    def test_events_emit_exactly_once(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        first_pop = ioc.pop_events()
        second_pop = ioc.pop_events()
        assert len(first_pop) == 1
        assert second_pop == []


class TestProvenance:
    def test_source_provenance_preserved(self) -> None:
        attribution = _attribution()
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(attribution,),
        )
        assert ioc.source_attributions == (attribution,)
        assert ioc.source_attributions[0].source_system == "alienvault_otx"
        assert ioc.source_attributions[0].external_id == "pulse-1"

    def test_duplicate_source_attribution_rejected(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        ioc.pop_events()
        with pytest.raises(DuplicateSourceAttributionError):
            ioc.add_source_attribution(None, _attribution(), _now())

    def test_new_source_attribution_added_and_emits_event(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        ioc.pop_events()
        ioc.add_source_attribution(None, _attribution(external_id="pulse-2"), _now())
        assert len(ioc.source_attributions) == 2
        events = ioc.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], IocSourceAdded)


class TestTenancy:
    def test_tenant_ioc_cannot_masquerade_as_global(self) -> None:
        tenant_id = TenantId.generate()
        ioc = IOC.observe_tenant(
            ioc_id=IocId.generate(),
            tenant_id=tenant_id,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            evidence_citations=(EvidenceCitation("internal-finding-1"),),
        )
        ioc.pop_events()
        with pytest.raises(TenantMismatchError):
            ioc.add_source_attribution(None, _attribution(), _now())
        with pytest.raises(TenantMismatchError):
            ioc.mark_expired(None, _now())

    def test_global_ioc_cannot_be_mutated_by_a_tenant_caller(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        ioc.pop_events()
        with pytest.raises(TenantMismatchError):
            ioc.mark_expired(TenantId.generate(), _now())


class TestLifecycle:
    def test_lifecycle_transitions_follow_policy(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        ioc.pop_events()
        ioc.supersede(None, _now())
        assert ioc.lifecycle is IocLifecycle.SUPERSEDED
        events = ioc.pop_events()
        assert isinstance(events[0], IocSuperseded)

    def test_expired_terminal_rules_preserved_but_refreshable(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        ioc.pop_events()
        ioc.mark_expired(None, _now())
        assert isinstance(ioc.pop_events()[0], IocExpired)
        ioc.reactivate(None, _now())
        assert ioc.lifecycle is IocLifecycle.ACTIVE

    def test_revoked_terminal_rules_preserved(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        ioc.pop_events()
        ioc.revoke(None, _now())
        assert isinstance(ioc.pop_events()[0], IocRevoked)
        with pytest.raises(InvalidLifecycleTransitionError):
            ioc.mark_expired(None, _now())
        with pytest.raises(InvalidLifecycleTransitionError):
            ioc.reactivate(None, _now())


class TestEpistemicState:
    def test_epistemic_state_transitions_follow_ontology(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        ioc.pop_events()
        ioc.transition_epistemic_state(None, EpistemicState.EVIDENCE, _now())
        assert ioc.epistemic_state is EpistemicState.EVIDENCE
        events = ioc.pop_events()
        assert isinstance(events[0], IocEpistemicStateChanged)
        assert events[0].from_state == "observation"
        assert events[0].to_state == "evidence"

    def test_illegal_epistemic_transition_rejected(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        ioc.pop_events()
        with pytest.raises(InvalidEpistemicStateTransitionError):
            ioc.transition_epistemic_state(None, EpistemicState.VALIDATED, _now())

    def test_disputed_and_refuted_behavior_distinct(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        ioc.pop_events()
        ioc.transition_epistemic_state(None, EpistemicState.EVIDENCE, _now())
        ioc.transition_epistemic_state(None, EpistemicState.HYPOTHESIS, _now())
        ioc.pop_events()
        ioc.transition_epistemic_state(None, EpistemicState.DISPUTED, _now())
        assert ioc.epistemic_state is EpistemicState.DISPUTED
        ioc.transition_epistemic_state(None, EpistemicState.CORROBORATED, _now())
        assert ioc.epistemic_state is EpistemicState.CORROBORATED

        ioc2 = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key("5.6.7.8"),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        ioc2.pop_events()
        ioc2.transition_epistemic_state(None, EpistemicState.EVIDENCE, _now())
        ioc2.transition_epistemic_state(None, EpistemicState.HYPOTHESIS, _now())
        ioc2.pop_events()
        ioc2.refute(None, "confirmed benign infrastructure", _now())
        assert ioc2.epistemic_state is EpistemicState.REFUTED
        events = ioc2.pop_events()
        assert isinstance(events[0], IocRefuted)
        assert events[0].reason == "confirmed benign infrastructure"
        with pytest.raises(InvalidEpistemicStateTransitionError):
            ioc2.transition_epistemic_state(None, EpistemicState.EVIDENCE, _now())

    def test_refute_requires_generic_method_to_reject_refuted_target(self) -> None:
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=_canonical_key(),
            validity_window=_validity(),
            now=_now(),
            source_attributions=(_attribution(),),
        )
        ioc.pop_events()
        ioc.transition_epistemic_state(None, EpistemicState.EVIDENCE, _now())
        ioc.transition_epistemic_state(None, EpistemicState.HYPOTHESIS, _now())
        with pytest.raises(ValueError, match="refute"):
            ioc.transition_epistemic_state(None, EpistemicState.REFUTED, _now())
