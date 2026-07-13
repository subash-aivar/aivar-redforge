"""Unit tests for the default planning pipeline implementations:
DefaultSelectionPolicy, DefaultDependencyResolver, DefaultOrderingPolicy,
and every StrategyProtocol implementation in STRATEGY_REGISTRY."""

from __future__ import annotations

import pytest

from redforge.domain.attack_library.entity import AttackDefinition
from redforge.domain.attack_library.value_objects import (
    AttackCategory,
    AttackMaturity,
    AttackRelationshipType,
    AttackSeverity,
    AttackTechnique,
    Capability,
    SafetyClassification,
)
from redforge.domain.planning.exceptions import PlanningStrategyNotImplementedError
from redforge.domain.planning.planning_strategies import (
    STRATEGY_REGISTRY,
    AdaptiveStrategy,
    CapabilityDrivenStrategy,
    DefaultDependencyResolver,
    DefaultOrderingPolicy,
    DefaultSelectionPolicy,
    EscalationStrategy,
    ParallelStrategy,
    PolicyDrivenStrategy,
    ReconFirstStrategy,
    RiskDrivenStrategy,
    SingleStepStrategy,
    default_priority_of,
    is_topologically_valid,
)
from redforge.domain.planning.value_objects import (
    AttackPriority,
    PlanningStrategy,
    RiskAppetite,
    SelectionCriteria,
)
from redforge.shared.identifiers import EntityId


def _attack(
    name: str = "attack",
    category: AttackCategory = AttackCategory.PROMPT_INJECTION,
    severity: AttackSeverity = AttackSeverity.HIGH,
    safety: SafetyClassification = SafetyClassification.SAFE,
    maturity: AttackMaturity = AttackMaturity.ESTABLISHED,
    required_capabilities: frozenset[Capability] = frozenset(),
    publish: bool = True,
) -> AttackDefinition:
    a = AttackDefinition.create(
        name=f"attack-{name}", display_name=f"Attack {name.title()}", description="...",
        category=category, technique=AttackTechnique(technique="T"),
        severity=severity, safety=safety, maturity=maturity,
        required_capabilities=required_capabilities,
    )
    if publish:
        a.publish()
    a.collect_events()
    return a


class TestDefaultSelectionPolicy:
    def test_selects_executable_compatible_attacks(self) -> None:
        a = _attack()
        result = DefaultSelectionPolicy().select((a,), SelectionCriteria(), frozenset())
        assert result == (a,)

    def test_skips_draft_attacks(self) -> None:
        a = _attack(publish=False)
        result = DefaultSelectionPolicy().select((a,), SelectionCriteria(), frozenset())
        assert result == ()

    def test_skips_capability_mismatch(self) -> None:
        a = _attack(required_capabilities=frozenset({Capability.MCP}))
        result = DefaultSelectionPolicy().select((a,), SelectionCriteria(), frozenset())
        assert result == ()

    def test_includes_when_capability_available(self) -> None:
        a = _attack(required_capabilities=frozenset({Capability.MCP}))
        result = DefaultSelectionPolicy().select(
            (a,), SelectionCriteria(), frozenset({"mcp"}),
        )
        assert result == (a,)

    def test_excludes_experimental_by_default(self) -> None:
        a = _attack(maturity=AttackMaturity.EXPERIMENTAL)
        result = DefaultSelectionPolicy().select((a,), SelectionCriteria(), frozenset())
        assert result == ()

    def test_includes_experimental_when_criteria_allows(self) -> None:
        a = _attack(maturity=AttackMaturity.EXPERIMENTAL)
        criteria = SelectionCriteria(include_experimental=True)
        result = DefaultSelectionPolicy().select((a,), criteria, frozenset())
        assert result == (a,)

    def test_required_categories_filters(self) -> None:
        a = _attack(category=AttackCategory.JAILBREAK)
        b = _attack("other", category=AttackCategory.TOOL_ABUSE)
        criteria = SelectionCriteria(required_categories=frozenset({"jailbreak"}))
        result = DefaultSelectionPolicy().select((a, b), criteria, frozenset())
        assert result == (a,)

    def test_excluded_tags_filters(self) -> None:
        a = _attack()
        a.tag("noisy")
        a.collect_events()
        criteria = SelectionCriteria(excluded_tags=frozenset({"noisy"}))
        result = DefaultSelectionPolicy().select((a,), criteria, frozenset())
        assert result == ()

    def test_deduplicates_by_identity(self) -> None:
        a = _attack()
        result = DefaultSelectionPolicy().select((a, a, a), SelectionCriteria(), frozenset())
        assert result == (a,)

    def test_policy_attack_ids_restricts_selection(self) -> None:
        a = _attack("a")
        b = _attack("b")
        criteria = SelectionCriteria(policy_attack_ids=frozenset({a.id}))
        result = DefaultSelectionPolicy().select((a, b), criteria, frozenset())
        assert result == (a,)

    @pytest.mark.parametrize(
        "appetite,safety,included",
        [
            (RiskAppetite.CONSERVATIVE, SafetyClassification.SAFE, True),
            (RiskAppetite.CONSERVATIVE, SafetyClassification.CAUTION, False),
            (RiskAppetite.CONSERVATIVE, SafetyClassification.RESTRICTED, False),
            (RiskAppetite.BALANCED, SafetyClassification.DESTRUCTIVE, True),
            (RiskAppetite.BALANCED, SafetyClassification.RESTRICTED, False),
            (RiskAppetite.AGGRESSIVE, SafetyClassification.RESTRICTED, True),
        ],
    )
    def test_risk_appetite_gates_safety(
        self, appetite: RiskAppetite, safety: SafetyClassification, included: bool,
    ) -> None:
        a = _attack(safety=safety)
        criteria = SelectionCriteria(risk_appetite=appetite)
        result = DefaultSelectionPolicy().select((a,), criteria, frozenset())
        assert (result == (a,)) is included


class TestDefaultDependencyResolver:
    def test_prerequisite_of_creates_edge(self) -> None:
        a = _attack("a")
        b = _attack("b")
        a.relate_to(b.id, AttackRelationshipType.PREREQUISITE_OF)
        a.collect_events()
        graph = DefaultDependencyResolver().resolve((a, b))
        assert graph.depends_on(a.id) == frozenset({b.id})

    def test_composed_of_creates_edge(self) -> None:
        a = _attack("a")
        b = _attack("b")
        a.relate_to(b.id, AttackRelationshipType.COMPOSED_OF)
        a.collect_events()
        graph = DefaultDependencyResolver().resolve((a, b))
        assert graph.depends_on(a.id) == frozenset({b.id})

    def test_parent_of_does_not_create_dependency_edge(self) -> None:
        """PARENT_OF/DERIVED_FROM are taxonomic, not execution-order —
        must not become dependency edges."""
        a = _attack("a")
        b = _attack("b")
        a.relate_to(b.id, AttackRelationshipType.PARENT_OF)
        a.collect_events()
        graph = DefaultDependencyResolver().resolve((a, b))
        assert graph.depends_on(a.id) == frozenset()

    def test_derived_from_does_not_create_dependency_edge(self) -> None:
        a = _attack("a")
        b = _attack("b")
        a.relate_to(b.id, AttackRelationshipType.DERIVED_FROM)
        a.collect_events()
        graph = DefaultDependencyResolver().resolve((a, b))
        assert graph.depends_on(a.id) == frozenset()

    def test_relationship_to_unselected_attack_is_dropped(self) -> None:
        a = _attack("a")
        unselected_id = EntityId.generate()
        a.relate_to(unselected_id, AttackRelationshipType.PREREQUISITE_OF)
        a.collect_events()
        graph = DefaultDependencyResolver().resolve((a,))
        assert graph.depends_on(a.id) == frozenset()


class TestDefaultOrderingPolicy:
    def test_orders_topologically(self) -> None:
        a = _attack("a")
        b = _attack("b")
        b.relate_to(a.id, AttackRelationshipType.PREREQUISITE_OF)
        b.collect_events()
        graph = DefaultDependencyResolver().resolve((a, b))
        sequence = DefaultOrderingPolicy().order((a, b), graph, default_priority_of)
        assert sequence.attack_ids.index(a.id) < sequence.attack_ids.index(b.id)

    def test_groups_by_category(self) -> None:
        a = _attack("a", category=AttackCategory.JAILBREAK)
        b = _attack("b", category=AttackCategory.TOOL_ABUSE)
        graph = DefaultDependencyResolver().resolve((a, b))
        sequence = DefaultOrderingPolicy().order((a, b), graph, default_priority_of)
        groups = {s.attack_id: s.group for s in sequence.steps}
        assert groups[a.id] == "jailbreak"
        assert groups[b.id] == "tool_abuse"

    def test_cycle_raises_value_error(self) -> None:
        a = _attack("a")
        b = _attack("b")
        a.relate_to(b.id, AttackRelationshipType.PREREQUISITE_OF)
        b.relate_to(a.id, AttackRelationshipType.PREREQUISITE_OF)
        a.collect_events()
        b.collect_events()
        graph = DefaultDependencyResolver().resolve((a, b))
        with pytest.raises(ValueError, match="cycle"):
            DefaultOrderingPolicy().order((a, b), graph, default_priority_of)


class TestDefaultPriorityOf:
    @pytest.mark.parametrize(
        "severity,expected",
        [
            (AttackSeverity.CRITICAL, AttackPriority.CRITICAL),
            (AttackSeverity.HIGH, AttackPriority.HIGH),
            (AttackSeverity.MEDIUM, AttackPriority.MEDIUM),
            (AttackSeverity.LOW, AttackPriority.LOW),
            (AttackSeverity.INFORMATIONAL, AttackPriority.LOW),
        ],
    )
    def test_maps_severity_to_priority(
        self, severity: AttackSeverity, expected: AttackPriority,
    ) -> None:
        a = _attack(severity=severity)
        assert default_priority_of(a) == expected


def _ordered_sequence_for_strategies() -> tuple:
    """A 3-category sequence with an inter-category dependency, used to
    verify strategies never break dependency validity when reordering."""
    a = _attack("a", category=AttackCategory.MODEL_EXTRACTION, severity=AttackSeverity.LOW)
    b = _attack("b", category=AttackCategory.TOOL_ABUSE, severity=AttackSeverity.CRITICAL)
    c = _attack("c", category=AttackCategory.JAILBREAK, severity=AttackSeverity.MEDIUM)
    c.relate_to(a.id, AttackRelationshipType.PREREQUISITE_OF)
    c.collect_events()
    graph = DefaultDependencyResolver().resolve((a, b, c))
    sequence = DefaultOrderingPolicy().order((a, b, c), graph, default_priority_of)
    return sequence, (a, b, c)


class TestStrategyRegistryCompleteness:
    def test_every_planning_strategy_is_registered(self) -> None:
        assert set(STRATEGY_REGISTRY.keys()) == set(PlanningStrategy)

    def test_multi_turn_and_autonomous_raise_not_implemented(self) -> None:
        sequence, _ = _ordered_sequence_for_strategies()
        for strategy in (PlanningStrategy.MULTI_TURN, PlanningStrategy.AUTONOMOUS):
            with pytest.raises(PlanningStrategyNotImplementedError):
                STRATEGY_REGISTRY[strategy].apply(sequence)


class TestSingleStepStrategy:
    def test_collapses_to_one_group(self) -> None:
        sequence, _ = _ordered_sequence_for_strategies()
        result = SingleStepStrategy().apply(sequence)
        assert result.groups == ("single_step",)
        assert len(result) == len(sequence)

    def test_preserves_order(self) -> None:
        sequence, _ = _ordered_sequence_for_strategies()
        result = SingleStepStrategy().apply(sequence)
        assert result.attack_ids == sequence.attack_ids


class TestEscalationAndRiskDrivenStrategy:
    def test_escalation_is_topologically_valid(self) -> None:
        sequence, _ = _ordered_sequence_for_strategies()
        result = EscalationStrategy().apply(sequence)
        assert is_topologically_valid(result.steps)

    def test_risk_driven_is_topologically_valid(self) -> None:
        sequence, _ = _ordered_sequence_for_strategies()
        result = RiskDrivenStrategy().apply(sequence)
        assert is_topologically_valid(result.steps)

    def test_escalation_and_risk_driven_are_mirror_ordered(self) -> None:
        """Escalation (ascending priority) and RiskDriven (descending)
        on an unconstrained sequence must produce reversed group order."""
        a = _attack("a", category=AttackCategory.JAILBREAK, severity=AttackSeverity.LOW)
        b = _attack("b", category=AttackCategory.TOOL_ABUSE, severity=AttackSeverity.CRITICAL)
        graph = DefaultDependencyResolver().resolve((a, b))
        sequence = DefaultOrderingPolicy().order((a, b), graph, default_priority_of)

        escalated = EscalationStrategy().apply(sequence)
        risk_driven = RiskDrivenStrategy().apply(sequence)
        assert escalated.attack_ids == tuple(reversed(risk_driven.attack_ids))


class TestReconFirstStrategy:
    def test_promotes_recon_category_first(self) -> None:
        sequence, (a, _b, _c) = _ordered_sequence_for_strategies()
        result = ReconFirstStrategy().apply(sequence)
        assert result.attack_ids[0] == a.id
        assert is_topologically_valid(result.steps)

    def test_no_recon_attacks_is_a_noop(self) -> None:
        a = _attack("a", category=AttackCategory.JAILBREAK)
        graph = DefaultDependencyResolver().resolve((a,))
        sequence = DefaultOrderingPolicy().order((a,), graph, default_priority_of)
        result = ReconFirstStrategy().apply(sequence)
        assert result.attack_ids == sequence.attack_ids


class TestParallelStrategy:
    def test_independent_steps_share_a_wave(self) -> None:
        a = _attack("a")
        b = _attack("b")
        graph = DefaultDependencyResolver().resolve((a, b))
        sequence = DefaultOrderingPolicy().order((a, b), graph, default_priority_of)
        result = ParallelStrategy().apply(sequence)
        groups = {s.attack_id: s.group for s in result.steps}
        assert groups[a.id] == groups[b.id] == "wave_0"

    def test_dependent_steps_get_different_waves(self) -> None:
        a = _attack("a")
        b = _attack("b")
        b.relate_to(a.id, AttackRelationshipType.PREREQUISITE_OF)
        b.collect_events()
        graph = DefaultDependencyResolver().resolve((a, b))
        sequence = DefaultOrderingPolicy().order((a, b), graph, default_priority_of)
        result = ParallelStrategy().apply(sequence)
        groups = {s.attack_id: s.group for s in result.steps}
        assert groups[a.id] == "wave_0"
        assert groups[b.id] == "wave_1"


class TestCapabilityDrivenStrategy:
    def test_groups_by_capability_signature(self) -> None:
        a = _attack("a", required_capabilities=frozenset({Capability.MCP}))
        b = _attack("b", required_capabilities=frozenset({Capability.MCP}))
        c = _attack("c", required_capabilities=frozenset({Capability.RAG}))
        graph = DefaultDependencyResolver().resolve((a, b, c))
        sequence = DefaultOrderingPolicy().order((a, b, c), graph, default_priority_of)
        result = CapabilityDrivenStrategy().apply(sequence)
        groups = {s.attack_id: s.group for s in result.steps}
        assert groups[a.id] == groups[b.id]
        assert groups[a.id] != groups[c.id]

    def test_no_capabilities_groups_as_none(self) -> None:
        a = _attack("a")
        graph = DefaultDependencyResolver().resolve((a,))
        sequence = DefaultOrderingPolicy().order((a,), graph, default_priority_of)
        result = CapabilityDrivenStrategy().apply(sequence)
        assert result.steps[0].group == "caps:none"


class TestAdaptiveStrategy:
    def test_is_topologically_valid(self) -> None:
        sequence, _ = _ordered_sequence_for_strategies()
        result = AdaptiveStrategy().apply(sequence)
        assert is_topologically_valid(result.steps)

    def test_combines_wave_and_capability_in_group_label(self) -> None:
        a = _attack("a", required_capabilities=frozenset({Capability.RAG}))
        graph = DefaultDependencyResolver().resolve((a,))
        sequence = DefaultOrderingPolicy().order((a,), graph, default_priority_of)
        result = AdaptiveStrategy().apply(sequence)
        assert "wave_0" in result.steps[0].group
        assert "rag" in result.steps[0].group


class TestPolicyDrivenStrategy:
    def test_is_identity_passthrough(self) -> None:
        sequence, _ = _ordered_sequence_for_strategies()
        result = PolicyDrivenStrategy().apply(sequence)
        assert result == sequence
