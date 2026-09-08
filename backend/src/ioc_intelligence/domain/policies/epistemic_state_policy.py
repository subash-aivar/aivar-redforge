"""EpistemicStatePolicy — the legal `EpistemicState` transition table
(M51.2 Phase A), implementing ADR-M51.2-01's Knowledge Lifecycle
exactly, including its explicit correction to the naive linear
example: `Disputed` is re-enterable (not a dead end) and `Refuted` is
a distinct terminal state from `Historical`/`Retired` (Refuted means
"actively wrong"; Historical/Retired mean "no longer relevant").

    Observation -> Evidence -> Hypothesis -> Corroborated -> Validated
                                    |  ^            |
                                    v  |            v
                                  Disputed <--------+
    {Hypothesis, Corroborated, Validated, Disputed}
        -> Historical | Retired | Refuted   (all terminal)

Epistemic state is how strongly RedForge trusts the claim — separate
from `IocLifecycle` (operational relevance); see `IocLifecyclePolicy`
for that axis."""

from __future__ import annotations

from ioc_intelligence.domain.exceptions.domain_exceptions import (
    InvalidEpistemicStateTransitionError,
)
from ioc_intelligence.domain.value_objects.enums import EpistemicState

_TERMINAL: frozenset[EpistemicState] = frozenset(
    {
        EpistemicState.HISTORICAL,
        EpistemicState.RETIRED,
        EpistemicState.REFUTED,
    }
)

_EXIT_STATES: frozenset[EpistemicState] = frozenset(
    {
        EpistemicState.HISTORICAL,
        EpistemicState.RETIRED,
        EpistemicState.REFUTED,
    }
)

_ALLOWED_TRANSITIONS: dict[EpistemicState, frozenset[EpistemicState]] = {
    EpistemicState.OBSERVATION: frozenset({EpistemicState.EVIDENCE}),
    EpistemicState.EVIDENCE: frozenset({EpistemicState.HYPOTHESIS}),
    EpistemicState.HYPOTHESIS: frozenset(
        {EpistemicState.CORROBORATED, EpistemicState.DISPUTED} | _EXIT_STATES
    ),
    EpistemicState.CORROBORATED: frozenset(
        {EpistemicState.VALIDATED, EpistemicState.DISPUTED} | _EXIT_STATES
    ),
    EpistemicState.VALIDATED: frozenset({EpistemicState.DISPUTED} | _EXIT_STATES),
    EpistemicState.DISPUTED: frozenset(
        {EpistemicState.HYPOTHESIS, EpistemicState.CORROBORATED, EpistemicState.VALIDATED}
        | _EXIT_STATES
    ),
    EpistemicState.HISTORICAL: frozenset(),
    EpistemicState.RETIRED: frozenset(),
    EpistemicState.REFUTED: frozenset(),
}


class EpistemicStatePolicy:
    @staticmethod
    def assert_legal_transition(current: EpistemicState, target: EpistemicState) -> None:
        if target not in _ALLOWED_TRANSITIONS[current]:
            raise InvalidEpistemicStateTransitionError(current.value, target.value)

    @staticmethod
    def is_terminal(state: EpistemicState) -> bool:
        return state in _TERMINAL
