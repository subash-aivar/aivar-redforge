"""EpistemicTransitionPolicy — the legal `EpistemicState` transition
table for a relationship claim (M51.4 Phase C1).

This is a LOCAL replication of `ioc_intelligence`'s
`EpistemicStatePolicy` table — same 9 states, same edges, same
terminal set — deliberately duplicated rather than imported, because
importing another bounded context's domain module is forbidden here
and because the two contexts must be free to recalibrate their claim
lifecycles independently.

Transition table (the single source of truth, enforced below):

    Observation -> Evidence -> Hypothesis -> Corroborated -> Validated
                                    |  ^            |
                                    v  |            v
                                  Disputed <--------+
    {Hypothesis, Corroborated, Validated, Disputed}
        -> Historical | Retired | Refuted   (all terminal)

Read in full:

    OBSERVATION  -> {EVIDENCE}
    EVIDENCE     -> {HYPOTHESIS}
    HYPOTHESIS   -> {CORROBORATED, DISPUTED} | exits
    CORROBORATED -> {VALIDATED, DISPUTED}    | exits
    VALIDATED    -> {DISPUTED}               | exits
    DISPUTED     -> {HYPOTHESIS, CORROBORATED, VALIDATED} | exits
    HISTORICAL   -> {}   (terminal)
    RETIRED      -> {}   (terminal)
    REFUTED      -> {}   (terminal)

where `exits` = {HISTORICAL, RETIRED, REFUTED}.

Two properties are load-bearing and deliberate: `DISPUTED` is
re-enterable (a disputed relationship can be re-argued back up the
hierarchy, it is not a dead end), and `REFUTED` ("actively wrong") is
a distinct terminal state from `HISTORICAL`/`RETIRED` ("no longer
relevant"). Epistemic state is how strongly RedForge trusts the claim
— a separate axis from `RelationshipLifecycleStatus` (operational
relevance); see `LifecycleTransitionPolicy` for that one.
"""

from __future__ import annotations

from intelligence_relationships.domain.exceptions.domain_exceptions import (
    InvalidEpistemicStateTransitionError,
)
from intelligence_relationships.domain.value_objects.enums import EpistemicState

_TERMINAL: frozenset[EpistemicState] = frozenset(
    {
        EpistemicState.HISTORICAL,
        EpistemicState.RETIRED,
        EpistemicState.REFUTED,
    }
)

_EXIT_STATES: frozenset[EpistemicState] = _TERMINAL

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


class EpistemicTransitionPolicy:
    @staticmethod
    def assert_legal_transition(current: EpistemicState, target: EpistemicState) -> None:
        if target not in _ALLOWED_TRANSITIONS[current]:
            raise InvalidEpistemicStateTransitionError(current.value, target.value)

    @staticmethod
    def is_terminal(state: EpistemicState) -> bool:
        return state in _TERMINAL

    @staticmethod
    def allowed_targets(current: EpistemicState) -> frozenset[EpistemicState]:
        return _ALLOWED_TRANSITIONS[current]
