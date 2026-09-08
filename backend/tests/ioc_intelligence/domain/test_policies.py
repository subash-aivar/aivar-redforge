from __future__ import annotations

import pytest

from ioc_intelligence.domain.exceptions.domain_exceptions import (
    GlobalEvidenceCitationNotSupportedError,
    InvalidEpistemicStateTransitionError,
    InvalidLifecycleTransitionError,
)
from ioc_intelligence.domain.policies.epistemic_state_policy import EpistemicStatePolicy
from ioc_intelligence.domain.policies.global_evidence_policy import GlobalEvidencePolicy
from ioc_intelligence.domain.policies.lifecycle_policy import IocLifecyclePolicy
from ioc_intelligence.domain.value_objects.enums import EpistemicState, IocLifecycle
from ioc_intelligence.domain.value_objects.identifiers import TenantId


class TestIocLifecyclePolicy:
    def test_active_to_expired_allowed(self) -> None:
        IocLifecyclePolicy.assert_legal_transition(IocLifecycle.ACTIVE, IocLifecycle.EXPIRED)

    def test_active_to_superseded_allowed(self) -> None:
        IocLifecyclePolicy.assert_legal_transition(IocLifecycle.ACTIVE, IocLifecycle.SUPERSEDED)

    def test_expired_to_active_refresh_allowed(self) -> None:
        IocLifecyclePolicy.assert_legal_transition(IocLifecycle.EXPIRED, IocLifecycle.ACTIVE)

    def test_revoked_is_terminal(self) -> None:
        with pytest.raises(InvalidLifecycleTransitionError):
            IocLifecyclePolicy.assert_legal_transition(IocLifecycle.REVOKED, IocLifecycle.ACTIVE)

    def test_superseded_cannot_go_back_to_active(self) -> None:
        with pytest.raises(InvalidLifecycleTransitionError):
            IocLifecyclePolicy.assert_legal_transition(IocLifecycle.SUPERSEDED, IocLifecycle.ACTIVE)


class TestEpistemicStatePolicy:
    def test_linear_progression_allowed(self) -> None:
        EpistemicStatePolicy.assert_legal_transition(
            EpistemicState.OBSERVATION, EpistemicState.EVIDENCE
        )
        EpistemicStatePolicy.assert_legal_transition(
            EpistemicState.EVIDENCE, EpistemicState.HYPOTHESIS
        )
        EpistemicStatePolicy.assert_legal_transition(
            EpistemicState.HYPOTHESIS, EpistemicState.CORROBORATED
        )
        EpistemicStatePolicy.assert_legal_transition(
            EpistemicState.CORROBORATED, EpistemicState.VALIDATED
        )

    def test_disputed_is_re_enterable_not_a_dead_end(self) -> None:
        EpistemicStatePolicy.assert_legal_transition(
            EpistemicState.VALIDATED, EpistemicState.DISPUTED
        )
        EpistemicStatePolicy.assert_legal_transition(
            EpistemicState.DISPUTED, EpistemicState.CORROBORATED
        )
        EpistemicStatePolicy.assert_legal_transition(
            EpistemicState.DISPUTED, EpistemicState.VALIDATED
        )

    def test_disputed_and_refuted_are_behaviorally_distinct(self) -> None:
        EpistemicStatePolicy.assert_legal_transition(
            EpistemicState.DISPUTED, EpistemicState.CORROBORATED
        )
        with pytest.raises(InvalidEpistemicStateTransitionError):
            EpistemicStatePolicy.assert_legal_transition(
                EpistemicState.REFUTED, EpistemicState.CORROBORATED
            )
        assert not EpistemicStatePolicy.is_terminal(EpistemicState.DISPUTED)
        assert EpistemicStatePolicy.is_terminal(EpistemicState.REFUTED)

    def test_historical_retired_refuted_are_all_terminal(self) -> None:
        for terminal in (
            EpistemicState.HISTORICAL,
            EpistemicState.RETIRED,
            EpistemicState.REFUTED,
        ):
            assert EpistemicStatePolicy.is_terminal(terminal)
            with pytest.raises(InvalidEpistemicStateTransitionError):
                EpistemicStatePolicy.assert_legal_transition(terminal, EpistemicState.HYPOTHESIS)

    def test_observation_cannot_skip_to_validated(self) -> None:
        with pytest.raises(InvalidEpistemicStateTransitionError):
            EpistemicStatePolicy.assert_legal_transition(
                EpistemicState.OBSERVATION, EpistemicState.VALIDATED
            )


class TestGlobalEvidencePolicy:
    """M51.2 Slice 2.1: formalizes the previously-duplicated-inline
    "global IOCs cannot carry evidence citations" rule as one policy
    object with one exception type — see
    `GlobalEvidenceCitationNotSupportedError`'s docstring for the full
    architectural rationale (Evidence has no platform/global ownership
    concept anywhere in the domain model today)."""

    def test_global_scope_with_citations_is_rejected(self) -> None:
        with pytest.raises(GlobalEvidenceCitationNotSupportedError):
            GlobalEvidencePolicy.assert_evidence_citations_supported(
                None, ("SecurityCondition:some-id",)
            )

    def test_global_scope_with_zero_citations_is_allowed(self) -> None:
        GlobalEvidencePolicy.assert_evidence_citations_supported(None, ())

    def test_tenant_scope_with_citations_is_allowed(self) -> None:
        GlobalEvidencePolicy.assert_evidence_citations_supported(
            TenantId.generate(), ("SecurityCondition:some-id",)
        )

    def test_tenant_scope_with_zero_citations_is_allowed(self) -> None:
        GlobalEvidencePolicy.assert_evidence_citations_supported(TenantId.generate(), ())

    def test_rejection_message_names_the_architectural_reason(self) -> None:
        """The error must explain WHY (Evidence has no global-ownership
        concept), not just state the rule — an operator hitting this
        via the API should understand it is a deliberate boundary, not
        an arbitrary restriction."""
        with pytest.raises(GlobalEvidenceCitationNotSupportedError) as exc_info:
            GlobalEvidencePolicy.assert_evidence_citations_supported(
                None, ("SecurityCondition:some-id",)
            )
        message = str(exc_info.value)
        assert "tenant-owned" in message
        assert "source_attributions" in message
