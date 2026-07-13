"""Integration tests for AttackPlanner — the full pipeline (Target ->
Capability Discovery -> Attack Selection -> Dependency Resolution ->
Ordering -> Strategy Assignment -> AttackPlan) exercised end-to-end
against fake, in-memory implementations of every Protocol dependency.

"Integration" here means: multiple collaborators (repository +
capability resolver + selection/dependency/ordering policies + strategy
registry) wired together and exercised through AttackPlanner's public
`plan()` method, rather than each piece tested in isolation (see
test_planning_strategies.py for the per-collaborator unit tests).
"""

from __future__ import annotations

import pytest

from redforge.domain.attack_library.entity import AttackDefinition
from redforge.domain.attack_library.taxonomy import AttackTaxonomyNode
from redforge.domain.attack_library.value_objects import (
    AttackCategory,
    AttackMaturity,
    AttackRelationshipType,
    AttackSeverity,
    AttackTechnique,
    Capability,
)
from redforge.domain.planning.exceptions import (
    AttackPlanCycleError,
    NoCompatibleAttacksError,
    PlanningStrategyNotImplementedError,
)
from redforge.domain.planning.planner import AttackPlanner
from redforge.domain.planning.planning_strategies import StaticCapabilityResolver
from redforge.domain.planning.value_objects import (
    PlanningStrategy,
    RiskAppetite,
    SelectionCriteria,
)
from redforge.shared.identifiers import EntityId


class InMemoryAttackLibraryRepository:
    """Minimal AttackLibraryRepository fake — enough surface for
    AttackPlanner (list_executable), matching the real Protocol shape."""

    def __init__(self, attacks: list[AttackDefinition] | None = None) -> None:
        self._attacks: dict[str, AttackDefinition] = {
            str(a.id): a for a in (attacks or [])
        }

    async def get_by_id(self, attack_id: EntityId) -> AttackDefinition | None:
        return self._attacks.get(str(attack_id))

    async def list_by_category(
        self, category: AttackCategory, status: object = None,
    ) -> list[AttackDefinition]:
        return [a for a in self._attacks.values() if a.category == category]

    async def search_by_tags(self, tags: list[str]) -> list[AttackDefinition]:
        return [a for a in self._attacks.values() if a.tags & set(tags)]

    async def list_executable(self) -> list[AttackDefinition]:
        return [a for a in self._attacks.values() if a.is_executable]

    async def save(self, attack: AttackDefinition) -> None:
        self._attacks[str(attack.id)] = attack


class InMemoryAttackTaxonomyRepository:
    """Minimal AttackTaxonomyRepository fake, mirroring the one built
    for the taxonomy use case tests — reused shape, separate instance
    (different test module, no cross-file coupling)."""

    def __init__(self) -> None:
        self._nodes: dict[str, AttackTaxonomyNode] = {}

    async def get_by_id(self, node_id: EntityId) -> AttackTaxonomyNode | None:
        return self._nodes.get(str(node_id))

    async def get_by_key(self, key: str) -> AttackTaxonomyNode | None:
        for node in self._nodes.values():
            if str(node.key) == key.strip().lower():
                return node
        return None

    async def get_children(self, parent_id: EntityId | None) -> list[AttackTaxonomyNode]:
        target = str(parent_id) if parent_id is not None else None
        return [
            n for n in self._nodes.values()
            if (str(n.parent_id) if n.parent_id is not None else None) == target
        ]

    async def get_ancestors(self, node_id: EntityId) -> list[AttackTaxonomyNode]:
        return []

    async def get_descendants(self, node_id: EntityId) -> list[AttackTaxonomyNode]:
        result: list[AttackTaxonomyNode] = []
        frontier = [node_id]
        while frontier:
            parent = frontier.pop()
            for child in await self.get_children(parent):
                result.append(child)
                frontier.append(child.id)
        return result

    async def save(self, node: AttackTaxonomyNode) -> None:
        self._nodes[str(node.id)] = node


def _attack(
    name: str,
    category: AttackCategory = AttackCategory.PROMPT_INJECTION,
    severity: AttackSeverity = AttackSeverity.HIGH,
    required_capabilities: frozenset[Capability] = frozenset(),
) -> AttackDefinition:
    a = AttackDefinition.create(
        name=f"attack-{name}", display_name=f"Attack {name.title()}", description="...",
        category=category, technique=AttackTechnique(technique="T"),
        severity=severity, required_capabilities=required_capabilities,
        maturity=AttackMaturity.ESTABLISHED,
    )
    a.publish()
    a.collect_events()
    return a


@pytest.fixture
def target_id() -> EntityId:
    return EntityId.generate()


@pytest.fixture
def organization_id() -> EntityId:
    return EntityId.generate()


class TestBasicPlanning:
    async def test_produces_a_plan_with_all_compatible_attacks(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        a = _attack("a")
        b = _attack("b")
        repo = InMemoryAttackLibraryRepository([a, b])
        resolver = StaticCapabilityResolver({})
        planner = AttackPlanner(repo, resolver)

        plan = await planner.plan(
            target_id, organization_id, PlanningStrategy.SINGLE_STEP,
            risk_appetite=RiskAppetite.BALANCED,
        )
        assert plan.attack_count == 2
        assert set(plan.sequence.attack_ids) == {a.id, b.id}
        assert plan.target_id == target_id
        assert plan.organization_id == organization_id

    async def test_no_compatible_attacks_raises(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        a = _attack("a", required_capabilities=frozenset({Capability.MCP}))
        repo = InMemoryAttackLibraryRepository([a])
        resolver = StaticCapabilityResolver({})  # target has no capabilities
        planner = AttackPlanner(repo, resolver)

        with pytest.raises(NoCompatibleAttacksError):
            await planner.plan(target_id, organization_id, PlanningStrategy.SINGLE_STEP)

    async def test_empty_library_raises_no_compatible_attacks(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        repo = InMemoryAttackLibraryRepository([])
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))
        with pytest.raises(NoCompatibleAttacksError):
            await planner.plan(target_id, organization_id, PlanningStrategy.SINGLE_STEP)

    async def test_capability_gating_actually_filters(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        compatible = _attack("compatible")
        incompatible = _attack("incompatible", required_capabilities=frozenset({Capability.MCP}))
        repo = InMemoryAttackLibraryRepository([compatible, incompatible])
        resolver = StaticCapabilityResolver({str(target_id): frozenset()})
        planner = AttackPlanner(repo, resolver)

        plan = await planner.plan(target_id, organization_id, PlanningStrategy.SINGLE_STEP)
        assert plan.sequence.attack_ids == (compatible.id,)

    async def test_capability_present_includes_attack(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        a = _attack("needs-mcp", required_capabilities=frozenset({Capability.MCP}))
        repo = InMemoryAttackLibraryRepository([a])
        resolver = StaticCapabilityResolver({str(target_id): frozenset({"mcp"})})
        planner = AttackPlanner(repo, resolver)

        plan = await planner.plan(target_id, organization_id, PlanningStrategy.SINGLE_STEP)
        assert plan.sequence.attack_ids == (a.id,)

    async def test_draft_attacks_are_never_selected(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        draft = AttackDefinition.create(
            name="draft-attack", display_name="Draft Attack", description="...",
            category=AttackCategory.JAILBREAK, technique=AttackTechnique(technique="T"),
            severity=AttackSeverity.HIGH,
        )
        repo = InMemoryAttackLibraryRepository([draft])
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))
        with pytest.raises(NoCompatibleAttacksError):
            await planner.plan(target_id, organization_id, PlanningStrategy.SINGLE_STEP)


class TestDependencyResolutionAndOrdering:
    async def test_respects_declared_prerequisite_order(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        recon = _attack("recon")
        followon = _attack("followon")
        followon.relate_to(recon.id, AttackRelationshipType.PREREQUISITE_OF)
        followon.collect_events()
        repo = InMemoryAttackLibraryRepository([recon, followon])
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))

        plan = await planner.plan(target_id, organization_id, PlanningStrategy.SINGLE_STEP)
        ids = plan.sequence.attack_ids
        assert ids.index(recon.id) < ids.index(followon.id)

    async def test_dependency_cycle_raises_attack_plan_cycle_error(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        a = _attack("a")
        b = _attack("b")
        a.relate_to(b.id, AttackRelationshipType.PREREQUISITE_OF)
        b.relate_to(a.id, AttackRelationshipType.PREREQUISITE_OF)
        a.collect_events()
        b.collect_events()
        repo = InMemoryAttackLibraryRepository([a, b])
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))

        with pytest.raises(AttackPlanCycleError):
            await planner.plan(target_id, organization_id, PlanningStrategy.SINGLE_STEP)

    async def test_three_way_transitive_cycle_raises(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        a, b, c = _attack("a"), _attack("b"), _attack("c")
        a.relate_to(b.id, AttackRelationshipType.PREREQUISITE_OF)
        b.relate_to(c.id, AttackRelationshipType.PREREQUISITE_OF)
        c.relate_to(a.id, AttackRelationshipType.PREREQUISITE_OF)
        for x in (a, b, c):
            x.collect_events()
        repo = InMemoryAttackLibraryRepository([a, b, c])
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))

        with pytest.raises(AttackPlanCycleError):
            await planner.plan(target_id, organization_id, PlanningStrategy.SINGLE_STEP)


class TestTaxonomyScoping:
    async def test_scopes_candidates_to_taxonomy_subtree(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        taxonomy_repo = InMemoryAttackTaxonomyRepository()
        root = AttackTaxonomyNode.create(key="root", name="Root", description="...")
        child = AttackTaxonomyNode.create(
            key="child", name="Child", description="...", parent_id=root.id,
        )
        await taxonomy_repo.save(root)
        await taxonomy_repo.save(child)

        in_scope = _attack("in-scope")
        in_scope.classify_under(child.id)
        in_scope.collect_events()
        out_of_scope = _attack("out-of-scope")

        repo = InMemoryAttackLibraryRepository([in_scope, out_of_scope])
        planner = AttackPlanner(
            repo, StaticCapabilityResolver({}), taxonomy_repository=taxonomy_repo,
        )

        plan = await planner.plan(
            target_id, organization_id, PlanningStrategy.SINGLE_STEP,
            taxonomy_scope_node_id=root.id,
        )
        assert plan.sequence.attack_ids == (in_scope.id,)

    async def test_taxonomy_scope_without_repository_raises(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        repo = InMemoryAttackLibraryRepository([_attack("a")])
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))  # no taxonomy_repository
        with pytest.raises(ValueError, match="taxonomy_repository"):
            await planner.plan(
                target_id, organization_id, PlanningStrategy.SINGLE_STEP,
                taxonomy_scope_node_id=EntityId.generate(),
            )


class TestPolicyDrivenSelection:
    async def test_policy_attack_ids_restrict_selection(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        included = _attack("included")
        excluded = _attack("excluded")
        repo = InMemoryAttackLibraryRepository([included, excluded])
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))

        criteria = SelectionCriteria(policy_attack_ids=frozenset({included.id}))
        plan = await planner.plan(
            target_id, organization_id, PlanningStrategy.POLICY_DRIVEN,
            policy_id=EntityId.generate(), criteria=criteria,
        )
        assert plan.sequence.attack_ids == (included.id,)
        assert plan.policy_id is not None


class TestStrategyAssignment:
    async def test_recon_first_reorders_final_plan(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        recon = _attack("recon", category=AttackCategory.MODEL_EXTRACTION)
        other = _attack("other", category=AttackCategory.JAILBREAK)
        repo = InMemoryAttackLibraryRepository([other, recon])  # deliberately "other" first
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))

        plan = await planner.plan(target_id, organization_id, PlanningStrategy.RECON_FIRST)
        assert plan.sequence.attack_ids[0] == recon.id

    async def test_parallel_strategy_groups_into_waves(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        a = _attack("a")
        b = _attack("b")
        repo = InMemoryAttackLibraryRepository([a, b])
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))

        plan = await planner.plan(target_id, organization_id, PlanningStrategy.PARALLEL)
        assert all(s.group == "wave_0" for s in plan.sequence.steps)

    async def test_unimplemented_strategy_raises(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        repo = InMemoryAttackLibraryRepository([_attack("a")])
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))
        with pytest.raises(PlanningStrategyNotImplementedError):
            await planner.plan(target_id, organization_id, PlanningStrategy.AUTONOMOUS)


class TestPlanMetadataAggregation:
    async def test_risk_level_reflects_highest_severity_selected(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        low = _attack("low", severity=AttackSeverity.LOW)
        critical = _attack("critical", severity=AttackSeverity.CRITICAL)
        repo = InMemoryAttackLibraryRepository([low, critical])
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))

        plan = await planner.plan(target_id, organization_id, PlanningStrategy.SINGLE_STEP)
        assert plan.risk_level == "critical"

    async def test_cost_and_duration_scale_with_step_count(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        attacks = [_attack(f"attack{i}") for i in range(4)]
        repo = InMemoryAttackLibraryRepository(attacks)
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))

        plan = await planner.plan(target_id, organization_id, PlanningStrategy.SINGLE_STEP)
        assert plan.estimated_cost.request_estimate == 4
        assert plan.estimated_duration.seconds == 20


class TestLargeAttackLibraryScale:
    async def test_plans_over_a_large_flat_candidate_pool(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        """A coarse proxy for 'large taxonomy'/large-library behavior:
        500 independent, unrelated attacks — verifies selection,
        (trivial) dependency resolution, and ordering all complete
        correctly and efficiently with no dependency edges at all."""
        attacks = [_attack(f"bulk{i}") for i in range(500)]
        repo = InMemoryAttackLibraryRepository(attacks)
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))

        plan = await planner.plan(target_id, organization_id, PlanningStrategy.PARALLEL)
        assert plan.attack_count == 500
        assert len(set(plan.sequence.attack_ids)) == 500
        assert all(s.group == "wave_0" for s in plan.sequence.steps)

    async def test_plans_over_a_long_dependency_chain(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        chain = [_attack(f"chain{i}") for i in range(50)]
        for i in range(1, 50):
            chain[i].relate_to(chain[i - 1].id, AttackRelationshipType.PREREQUISITE_OF)
            chain[i].collect_events()
        repo = InMemoryAttackLibraryRepository(chain)
        planner = AttackPlanner(repo, StaticCapabilityResolver({}))

        plan = await planner.plan(target_id, organization_id, PlanningStrategy.SINGLE_STEP)
        ids = plan.sequence.attack_ids
        for i in range(1, 50):
            assert ids.index(chain[i - 1].id) < ids.index(chain[i].id)


class TestCustomCollaborators:
    async def test_custom_priority_of_is_honored(
        self, target_id: EntityId, organization_id: EntityId,
    ) -> None:
        from redforge.domain.planning.value_objects import AttackPriority

        a = _attack("a")

        def always_critical(_attack_def: AttackDefinition) -> AttackPriority:
            return AttackPriority.CRITICAL

        repo = InMemoryAttackLibraryRepository([a])
        planner = AttackPlanner(
            repo, StaticCapabilityResolver({}), priority_of=always_critical,
        )
        plan = await planner.plan(target_id, organization_id, PlanningStrategy.SINGLE_STEP)
        assert plan.sequence.steps[0].priority == AttackPriority.CRITICAL
