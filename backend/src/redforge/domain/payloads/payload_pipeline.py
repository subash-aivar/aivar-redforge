"""Default implementations of the Payload Intelligence Protocols, and
PayloadIntelligenceEngine — the pipeline orchestrator.

Pipeline: AttackPlan -> (per attack, in plan order) Template Resolution
-> Generation -> Selection -> Mutation -> Rendering -> ExecutionArtifacts
-> PayloadBundle.

PayloadIntelligenceEngine depends only on Protocols — every stage is
injected, swappable, independently testable. It contains NO template
matching, NO rendering, NO mutation, and NO adaptation logic itself; it
only sequences calls to what it was given. Same discipline as
domain.planning.AttackPlanner.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from redforge.domain.payloads.bundle import PayloadBundle
from redforge.domain.payloads.intelligence_exceptions import (
    MutationFailedError,
    NoApplicableTemplateError,
)
from redforge.domain.payloads.mutations import MUTATION_REGISTRY
from redforge.domain.payloads.payload_value_objects import (
    ExecutionArtifacts,
    MutationType,
    PayloadMutationPlan,
    PayloadVariant,
    ProviderProfile,
)
from redforge.domain.payloads.value_objects import RenderContext
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from collections.abc import Callable

    from redforge.domain.attack_library.entity import AttackDefinition
    from redforge.domain.attack_library.repository import AttackLibraryRepository
    from redforge.domain.payloads.bundle_repository import PayloadBundleRepository
    from redforge.domain.payloads.entity import PayloadTemplate
    from redforge.domain.payloads.protocols import (
        MutationStrategy,
        PayloadGenerator,
        PayloadRenderer,
        PayloadSelector,
        ProviderAdapter,
        TemplateResolver,
    )
    from redforge.domain.payloads.repository import PayloadTemplateRepository
    from redforge.domain.planning.entity import AttackPlan


# ─── TemplateResolver ───────────────────────────────────────────────────────


class DefaultTemplateResolver:
    """Resolves applicable templates: published templates directly
    linked to the attack (`PayloadTemplate.attack_id`) take priority;
    if none are linked, falls back to any published template whose
    `template_type` matches the attack's `execution_strategy` (e.g. a
    MULTI_TURN attack matches MULTI_TURN or CONVERSATION templates)."""

    _STRATEGY_TO_TEMPLATE_TYPES: ClassVar[dict[str, frozenset[str]]] = {
        "single_turn": frozenset({"prompt", "raw"}),
        "multi_turn": frozenset({"multi_turn", "conversation"}),
        "chained": frozenset({"multi_turn", "conversation"}),
        "adaptive": frozenset({"prompt", "conversation", "raw"}),
        "automated_agent": frozenset({"function_call", "tool_use"}),
    }

    def resolve(
        self,
        attack: AttackDefinition,
        candidates: tuple[PayloadTemplate, ...],
    ) -> tuple[PayloadTemplate, ...]:
        published = tuple(c for c in candidates if c.is_renderable)
        linked = tuple(t for t in published if t.attack_id == str(attack.id))
        if linked:
            return linked

        compatible_types = self._STRATEGY_TO_TEMPLATE_TYPES.get(
            str(attack.execution_strategy), frozenset()
        )
        return tuple(t for t in published if str(t.template_type) in compatible_types)


# ─── PayloadGenerator ───────────────────────────────────────────────────────


class DefaultPayloadGenerator:
    """Renders every applicable template into a base PayloadVariant,
    reusing PayloadTemplate.render() — never reimplementing {{var}}
    substitution."""

    def generate(
        self,
        attack: AttackDefinition,
        templates: tuple[PayloadTemplate, ...],
        context: RenderContext,
    ) -> tuple[PayloadVariant, ...]:
        variants = []
        for template in templates:
            rendered = template.render(context)
            metadata = dict(rendered.metadata)
            if template.provider_hint:
                # Propagated so DefaultPayloadSelector can actually
                # gate on it — PayloadTemplate.render()'s RenderedPayload
                # has no notion of provider_hint itself (it's a
                # PayloadTemplate-level field, not a render-context one).
                metadata["provider_hint"] = template.provider_hint
            if attack.required_capabilities:
                # Propagated so DefaultPayloadSelector can gate on it —
                # PayloadVariant has no first-class capability field of
                # its own (capabilities belong to the attack, not the
                # rendered text), so it rides along in metadata as a
                # plain comma-joined string, matching this dict's
                # existing dict[str, str] shape.
                metadata["required_capabilities"] = ",".join(
                    sorted(c.value for c in attack.required_capabilities)
                )
            variants.append(PayloadVariant(
                id=EntityId.generate(),
                attack_id=attack.id,
                template_id=template.id,
                content=rendered.content,
                variables_used=rendered.variables_used,
                language=context.get("language", "en"),
                metadata=metadata,
            ))
        return tuple(variants)


# ─── PayloadSelector ────────────────────────────────────────────────────────


class DefaultPayloadSelector:
    """Keeps variants whose attack's required_capabilities are a subset
    of the target's available capabilities, and whose template's
    provider_hint (if any) matches the resolved provider — mirrors
    DefaultSelectionPolicy's capability-gating from domain.planning.
    """

    def select(
        self,
        variants: tuple[PayloadVariant, ...],
        capabilities: frozenset[str],
        provider: ProviderProfile,
    ) -> tuple[PayloadVariant, ...]:
        selected = []
        for variant in variants:
            provider_hint = variant.metadata.get("provider_hint", "")
            if provider_hint and provider_hint != provider.provider_id:
                continue

            required_raw = variant.metadata.get("required_capabilities", "")
            required = {c for c in required_raw.split(",") if c}
            if not required.issubset(capabilities):
                continue

            selected.append(variant)
        return tuple(selected)


# ─── ProviderAdapter ────────────────────────────────────────────────────────


class DefaultProviderAdapter:
    """Purely structural adaptation: wraps content as a labeled chat
    turn for "chat"-format providers, leaves "completion"/"raw" content
    untouched. NOT an HTTP/wire-format adapter — see protocols.py."""

    def adapt(self, content: str, provider: ProviderProfile) -> str:
        if provider.message_format == "chat":
            return f"[user]: {content}"
        return content


# ─── PayloadRenderer ────────────────────────────────────────────────────────


_CONTENT_TYPE_BY_MUTATION_SUFFIX: dict[str, str] = {
    "json": "application/json",
    "xml": "application/xml",
    "yaml": "application/yaml",
    "html": "text/html",
    "markdown": "text/markdown",
}


class DefaultPayloadRenderer:
    """Assembles the final ExecutionArtifacts for a variant, applying
    provider adaptation and inferring a content_type from the most
    recent structural mutation applied (if any)."""

    def render(
        self,
        variant: PayloadVariant,
        provider: ProviderProfile,
        provider_adapter: ProviderAdapter,
    ) -> ExecutionArtifacts:
        adapted = provider_adapter.adapt(variant.content, provider)
        content_type = "text/plain"
        for mutation in reversed(variant.mutation_history):
            if str(mutation) in _CONTENT_TYPE_BY_MUTATION_SUFFIX:
                content_type = _CONTENT_TYPE_BY_MUTATION_SUFFIX[str(mutation)]
                break

        return ExecutionArtifacts(
            variant_id=variant.id,
            attack_id=variant.attack_id,
            rendered_body=adapted,
            content_type=content_type,
            provider_hint=provider.provider_id,
            metadata={"language": variant.language, "version": str(variant.version)},
        )


# ─── Orchestrator ───────────────────────────────────────────────────────────


class PayloadIntelligenceEngine:
    """Default pipeline orchestrator: AttackPlan -> PayloadBundle.

    Every collaborator has a sensible default but can be overridden at
    construction time — the same extension seam
    domain.planning.AttackPlanner established.
    """

    def __init__(
        self,
        attack_repository: AttackLibraryRepository,
        template_repository: PayloadTemplateRepository,
        *,
        template_resolver: TemplateResolver | None = None,
        payload_generator: PayloadGenerator | None = None,
        payload_selector: PayloadSelector | None = None,
        payload_renderer: PayloadRenderer | None = None,
        provider_adapter: ProviderAdapter | None = None,
        mutation_registry: dict[MutationType, MutationStrategy] | None = None,
        bundle_repository: PayloadBundleRepository | None = None,
        context_of: Callable[[AttackDefinition], RenderContext] | None = None,
    ) -> None:
        self._attack_repository = attack_repository
        self._template_repository = template_repository
        self._template_resolver: TemplateResolver = template_resolver or DefaultTemplateResolver()
        self._payload_generator: PayloadGenerator = payload_generator or DefaultPayloadGenerator()
        self._payload_selector: PayloadSelector = payload_selector or DefaultPayloadSelector()
        self._payload_renderer: PayloadRenderer = payload_renderer or DefaultPayloadRenderer()
        self._provider_adapter: ProviderAdapter = provider_adapter or DefaultProviderAdapter()
        self._mutation_registry = mutation_registry or MUTATION_REGISTRY
        self._bundle_repository = bundle_repository
        self._context_of = context_of or (lambda _attack: RenderContext())

    async def generate_bundle(
        self,
        attack_plan: AttackPlan,
        attack_definitions: tuple[AttackDefinition, ...],
        target_id: EntityId,
        organization_id: EntityId,
        provider: ProviderProfile,
        available_capabilities: frozenset[str],
        *,
        mutation_plan_of: Callable[[AttackDefinition], PayloadMutationPlan] | None = None,
    ) -> PayloadBundle:
        """Run the full pipeline and produce an immutable PayloadBundle.

        Raises:
            NoApplicableTemplateError: If an attack in the plan has no
                applicable template.
            MutationFailedError: If a declared mutation cannot be applied.
        """
        attacks_by_id = {a.id: a for a in attack_definitions}
        mutation_plan_of = mutation_plan_of or (lambda _attack: PayloadMutationPlan())

        all_variants: list[PayloadVariant] = []
        all_artifacts: list[ExecutionArtifacts] = []

        for step in attack_plan.sequence.steps:
            attack = attacks_by_id[step.attack_id]
            templates = tuple(await self._template_repository.list_by_attack(str(attack.id)))
            applicable = self._template_resolver.resolve(attack, templates)
            if not applicable:
                raise NoApplicableTemplateError(str(attack.id))

            context = self._context_of(attack)
            generated = self._payload_generator.generate(attack, applicable, context)
            selected = self._payload_selector.select(generated, available_capabilities, provider)

            plan = mutation_plan_of(attack)
            for variant in selected:
                mutated = self._apply_mutations(variant, plan)
                all_variants.append(mutated)
                all_artifacts.append(
                    self._payload_renderer.render(mutated, provider, self._provider_adapter)
                )

        bundle = PayloadBundle.create(
            attack_plan_id=attack_plan.id,
            target_id=target_id,
            organization_id=organization_id,
            variants=tuple(all_variants),
            execution_artifacts=tuple(all_artifacts),
        )
        if self._bundle_repository is not None:
            await self._bundle_repository.save(bundle)
        return bundle

    def _apply_mutations(
        self, variant: PayloadVariant, plan: PayloadMutationPlan,
    ) -> PayloadVariant:
        current = variant
        for mutation_type in plan.mutations:
            strategy = self._mutation_registry[mutation_type]
            try:
                current = strategy.mutate(current)
            except ValueError as exc:
                raise MutationFailedError(
                    str(mutation_type), str(variant.id), str(exc)
                ) from exc
        return current
