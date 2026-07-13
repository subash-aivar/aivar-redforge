"""Integration tests for PayloadIntelligenceEngine — the full pipeline
(Template Resolution -> Generation -> Selection -> Mutation -> Rendering
-> ExecutionArtifacts -> PayloadBundle) exercised end-to-end against a
real Sprint 14 AttackPlan and fake, in-memory repositories.
"""

from __future__ import annotations

import pytest

from redforge.domain.attack_library.entity import AttackDefinition
from redforge.domain.attack_library.value_objects import (
    AttackCategory,
    AttackMaturity,
    AttackSeverity,
    AttackTechnique,
    Capability,
)
from redforge.domain.payloads.entity import PayloadTemplate
from redforge.domain.payloads.intelligence_exceptions import (
    EmptyBundleError,
    MutationFailedError,
    NoApplicableTemplateError,
)
from redforge.domain.payloads.payload_pipeline import PayloadIntelligenceEngine
from redforge.domain.payloads.payload_value_objects import (
    MutationType,
    PayloadMutationPlan,
    ProviderProfile,
)
from redforge.domain.payloads.value_objects import RenderContext, TemplateType, TemplateVariable
from redforge.domain.planning.entity import AttackPlan
from redforge.domain.planning.value_objects import (
    AttackDependencyGraph,
    AttackPriority,
    AttackSequence,
    PlannedAttackStep,
    PlanningStrategy,
)
from redforge.shared.identifiers import EntityId


class InMemoryAttackLibraryRepository:
    def __init__(self, attacks: list[AttackDefinition]) -> None:
        self._attacks = {str(a.id): a for a in attacks}

    async def get_by_id(self, attack_id: EntityId) -> AttackDefinition | None:
        return self._attacks.get(str(attack_id))

    async def list_by_category(self, category: object, status: object = None) -> list:
        return []

    async def search_by_tags(self, tags: list[str]) -> list:
        return []

    async def list_executable(self) -> list[AttackDefinition]:
        return [a for a in self._attacks.values() if a.is_executable]

    async def save(self, attack: AttackDefinition) -> None:
        self._attacks[str(attack.id)] = attack


class InMemoryPayloadTemplateRepository:
    def __init__(self, templates: list[PayloadTemplate]) -> None:
        self._templates = {str(t.id): t for t in templates}

    async def get_by_id(self, template_id: EntityId) -> PayloadTemplate | None:
        return self._templates.get(str(template_id))

    async def list_by_attack(self, attack_id: str) -> list[PayloadTemplate]:
        return [t for t in self._templates.values() if t.attack_id == attack_id]

    async def list_by_type(self, template_type: TemplateType) -> list[PayloadTemplate]:
        return [t for t in self._templates.values() if t.template_type == template_type]

    async def save(self, template: PayloadTemplate) -> None:
        self._templates[str(template.id)] = template


def _attack(
    name: str = "attack",
    category: AttackCategory = AttackCategory.PROMPT_INJECTION,
    required_capabilities: frozenset[Capability] = frozenset(),
) -> AttackDefinition:
    a = AttackDefinition.create(
        name=f"attack-{name}", display_name=f"Attack {name.title()}", description="...",
        category=category, technique=AttackTechnique(technique="T"),
        severity=AttackSeverity.HIGH, maturity=AttackMaturity.ESTABLISHED,
        required_capabilities=required_capabilities,
    )
    a.publish()
    a.collect_events()
    return a


def _template(
    attack_id: str, body: str = "Please {{action}} the {{target}}.",
    variables: list[TemplateVariable] | None = None,
    provider_hint: str = "",
) -> PayloadTemplate:
    t = PayloadTemplate.create(
        name="template-name", template_type=TemplateType.PROMPT, body=body,
        variables=variables if variables is not None else [
            TemplateVariable(name="action", required=True),
            TemplateVariable(name="target", required=True),
        ],
        attack_id=attack_id, provider_hint=provider_hint,
    )
    t.publish()
    t.collect_events()
    return t


def _plan_for(attacks: list[AttackDefinition]) -> AttackPlan:
    steps = tuple(
        PlannedAttackStep(
            attack_id=a.id, order=i, group=str(a.category), priority=AttackPriority.HIGH,
        )
        for i, a in enumerate(attacks)
    )
    sequence = AttackSequence(steps=steps)
    return AttackPlan.create(
        target_id=EntityId.generate(), organization_id=EntityId.generate(),
        strategy=PlanningStrategy.SINGLE_STEP, sequence=sequence,
        dependency_graph=AttackDependencyGraph(),
    )


@pytest.fixture
def provider() -> ProviderProfile:
    return ProviderProfile(provider_id="openai", message_format="chat")


class TestBasicBundleGeneration:
    async def test_produces_bundle_with_variant_per_attack(
        self, provider: ProviderProfile,
    ) -> None:
        attack = _attack("a")
        template = _template(str(attack.id))
        plan = _plan_for([attack])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(
                variables={"action": "summarize", "target": "system prompt"}
            ),
        )
        bundle = await engine.generate_bundle(
            plan, (attack,), EntityId.generate(), EntityId.generate(),
            provider, frozenset(),
        )
        assert bundle.variant_count == 1
        assert len(bundle.execution_artifacts) == 1
        assert bundle.attack_plan_id == plan.id

    async def test_rendered_content_uses_real_template_substitution(
        self, provider: ProviderProfile,
    ) -> None:
        """Verifies the pipeline reuses PayloadTemplate.render()
        rather than reimplementing {{var}} substitution."""
        attack = _attack("a")
        template = _template(str(attack.id))
        plan = _plan_for([attack])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(
                variables={"action": "exfiltrate", "target": "credentials"}
            ),
        )
        bundle = await engine.generate_bundle(
            plan, (attack,), EntityId.generate(), EntityId.generate(),
            provider, frozenset(),
        )
        artifact = bundle.execution_artifacts[0]
        assert "exfiltrate" in artifact.rendered_body
        assert "credentials" in artifact.rendered_body
        assert "{{" not in artifact.rendered_body

    async def test_no_applicable_template_raises(self, provider: ProviderProfile) -> None:
        attack = _attack("orphan")
        plan = _plan_for([attack])
        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([]),  # no templates at all
        )
        with pytest.raises(NoApplicableTemplateError):
            await engine.generate_bundle(
                plan, (attack,), EntityId.generate(), EntityId.generate(),
                provider, frozenset(),
            )

    async def test_multiple_attacks_produce_multiple_variants(
        self, provider: ProviderProfile,
    ) -> None:
        a1 = _attack("a1")
        a2 = _attack("a2")
        t1 = _template(str(a1.id))
        t2 = _template(str(a2.id))
        plan = _plan_for([a1, a2])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([a1, a2]),
            InMemoryPayloadTemplateRepository([t1, t2]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        bundle = await engine.generate_bundle(
            plan, (a1, a2), EntityId.generate(), EntityId.generate(),
            provider, frozenset(),
        )
        assert bundle.variant_count == 2
        assert {v.attack_id for v in bundle.variants} == {a1.id, a2.id}


class TestCapabilityAwareSelection:
    async def test_missing_capability_excludes_variant(
        self, provider: ProviderProfile,
    ) -> None:
        attack = _attack("needs-mcp", required_capabilities=frozenset({Capability.MCP}))
        template = _template(str(attack.id))
        plan = _plan_for([attack])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        with pytest.raises(EmptyBundleError):
            await engine.generate_bundle(
                plan, (attack,), EntityId.generate(), EntityId.generate(),
                provider, frozenset(),  # target has no capabilities at all
            )

    async def test_present_capability_includes_variant(
        self, provider: ProviderProfile,
    ) -> None:
        attack = _attack("needs-mcp", required_capabilities=frozenset({Capability.MCP}))
        template = _template(str(attack.id))
        plan = _plan_for([attack])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        bundle = await engine.generate_bundle(
            plan, (attack,), EntityId.generate(), EntityId.generate(),
            provider, frozenset({"mcp"}),
        )
        assert bundle.variant_count == 1

    async def test_no_required_capabilities_is_universal(
        self, provider: ProviderProfile,
    ) -> None:
        attack = _attack("no-requirements")
        template = _template(str(attack.id))
        plan = _plan_for([attack])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        bundle = await engine.generate_bundle(
            plan, (attack,), EntityId.generate(), EntityId.generate(),
            provider, frozenset(),
        )
        assert bundle.variant_count == 1


class TestProviderAwareSelection:
    async def test_provider_hint_mismatch_excludes_variant(
        self, provider: ProviderProfile,
    ) -> None:
        attack = _attack("a")
        template = _template(str(attack.id), provider_hint="anthropic")
        plan = _plan_for([attack])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        # A template exists and IS "applicable" (template resolution
        # doesn't know about providers) but PayloadSelector drops the
        # only generated variant due to the provider_hint mismatch,
        # leaving nothing to put in the bundle at all.
        with pytest.raises(EmptyBundleError):
            await engine.generate_bundle(
                plan, (attack,), EntityId.generate(), EntityId.generate(),
                provider, frozenset(),
            )

    async def test_matching_provider_hint_includes_variant(
        self, provider: ProviderProfile,
    ) -> None:
        attack = _attack("a")
        template = _template(str(attack.id), provider_hint="openai")
        plan = _plan_for([attack])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        bundle = await engine.generate_bundle(
            plan, (attack,), EntityId.generate(), EntityId.generate(),
            provider, frozenset(),
        )
        assert bundle.variant_count == 1

    async def test_no_provider_hint_is_universal(self, provider: ProviderProfile) -> None:
        attack = _attack("a")
        template = _template(str(attack.id), provider_hint="")
        plan = _plan_for([attack])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        bundle = await engine.generate_bundle(
            plan, (attack,), EntityId.generate(), EntityId.generate(),
            provider, frozenset(),
        )
        assert bundle.variant_count == 1


class TestMutationPipeline:
    async def test_mutation_plan_applied_to_variant(self, provider: ProviderProfile) -> None:
        attack = _attack("a")
        template = _template(str(attack.id))
        plan = _plan_for([attack])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        bundle = await engine.generate_bundle(
            plan, (attack,), EntityId.generate(), EntityId.generate(),
            provider, frozenset(),
            mutation_plan_of=lambda _a: PayloadMutationPlan(
                mutations=(MutationType.BASE64,)
            ),
        )
        variant = bundle.variants[0]
        assert variant.mutation_history == (MutationType.BASE64,)
        assert "base64" in bundle.execution_artifacts[0].rendered_body.lower()

    async def test_chained_mutations_applied_in_order(self, provider: ProviderProfile) -> None:
        attack = _attack("a")
        template = _template(str(attack.id))
        plan = _plan_for([attack])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        bundle = await engine.generate_bundle(
            plan, (attack,), EntityId.generate(), EntityId.generate(),
            provider, frozenset(),
            mutation_plan_of=lambda _a: PayloadMutationPlan(
                mutations=(MutationType.MARKDOWN, MutationType.BASE64)
            ),
        )
        variant = bundle.variants[0]
        assert variant.mutation_history == (MutationType.MARKDOWN, MutationType.BASE64)

    async def test_content_type_reflects_structural_mutation(
        self, provider: ProviderProfile,
    ) -> None:
        attack = _attack("a")
        template = _template(str(attack.id))
        plan = _plan_for([attack])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        bundle = await engine.generate_bundle(
            plan, (attack,), EntityId.generate(), EntityId.generate(),
            provider, frozenset(),
            mutation_plan_of=lambda _a: PayloadMutationPlan(mutations=(MutationType.JSON,)),
        )
        assert bundle.execution_artifacts[0].content_type == "application/json"


class TestProviderAdaptation:
    async def test_chat_format_wraps_content(self, provider: ProviderProfile) -> None:
        attack = _attack("a")
        template = _template(str(attack.id))
        plan = _plan_for([attack])

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        bundle = await engine.generate_bundle(
            plan, (attack,), EntityId.generate(), EntityId.generate(),
            provider, frozenset(),
        )
        assert bundle.execution_artifacts[0].rendered_body.startswith("[user]:")

    async def test_completion_format_leaves_content_untouched(self) -> None:
        attack = _attack("a")
        template = _template(str(attack.id))
        plan = _plan_for([attack])
        completion_provider = ProviderProfile(provider_id="local", message_format="completion")

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        bundle = await engine.generate_bundle(
            plan, (attack,), EntityId.generate(), EntityId.generate(),
            completion_provider, frozenset(),
        )
        assert not bundle.execution_artifacts[0].rendered_body.startswith("[user]:")


class TestMutationFailure:
    async def test_mutation_producing_empty_content_raises_mutation_failed(
        self, provider: ProviderProfile,
    ) -> None:
        """A hostile custom MutationStrategy that returns empty content
        must surface as MutationFailedError, not a raw ValueError."""
        attack = _attack("a")
        template = _template(str(attack.id))
        plan = _plan_for([attack])

        class BrokenMutation:
            mutation_type = MutationType.BASE64

            def mutate(self, variant: object) -> object:
                return variant.with_mutation(MutationType.BASE64, "")  # type: ignore[union-attr]

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository([attack]),
            InMemoryPayloadTemplateRepository([template]),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
            mutation_registry={MutationType.BASE64: BrokenMutation()},
        )
        with pytest.raises(MutationFailedError):
            await engine.generate_bundle(
                plan, (attack,), EntityId.generate(), EntityId.generate(),
                provider, frozenset(),
                mutation_plan_of=lambda _a: PayloadMutationPlan(
                    mutations=(MutationType.BASE64,)
                ),
            )


class TestMultiAttackPlanOrdering:
    async def test_bundle_reflects_full_plan(self, provider: ProviderProfile) -> None:
        attacks = [_attack(f"a{i}") for i in range(5)]
        templates = [_template(str(a.id)) for a in attacks]
        plan = _plan_for(attacks)

        engine = PayloadIntelligenceEngine(
            InMemoryAttackLibraryRepository(attacks),
            InMemoryPayloadTemplateRepository(templates),
            context_of=lambda _a: RenderContext(variables={"action": "x", "target": "y"}),
        )
        bundle = await engine.generate_bundle(
            plan, tuple(attacks), EntityId.generate(), EntityId.generate(),
            provider, frozenset(),
        )
        assert bundle.variant_count == 5
        assert len(bundle.execution_artifacts) == 5
