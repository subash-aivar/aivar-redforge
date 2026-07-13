"""Protocols for the Payload Intelligence pipeline.

Given: AttackPlan, AttackDefinition, Target, Target Capabilities,
Provider, Execution Strategy.
Produces: PayloadBundle (variants + execution artifacts).

Pipeline: Attack -> Template Resolution -> Generation -> Selection ->
Mutation -> Rendering -> ExecutionArtifacts -> PayloadBundle.

Every stage is a Protocol; PayloadIntelligenceEngine (payload_pipeline.py)
depends on none of the concrete implementations directly — swapping any
stage never requires touching the orchestrator. No switch statements:
mutation dispatch is MUTATION_REGISTRY, a dict keyed by MutationType
(mutations.py), built from data.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.attack_library.entity import AttackDefinition
    from redforge.domain.payloads.entity import PayloadTemplate
    from redforge.domain.payloads.payload_value_objects import (
        ExecutionArtifacts,
        MutationType,
        PayloadVariant,
        ProviderProfile,
    )
    from redforge.domain.payloads.value_objects import RenderContext


@runtime_checkable
class TemplateResolver(Protocol):
    """Resolves which PayloadTemplates are applicable to an attack, out
    of an already-loaded candidate pool (I/O happens before this is
    called — resolution itself is a pure filtering decision)."""

    def resolve(
        self,
        attack: AttackDefinition,
        candidates: tuple[PayloadTemplate, ...],
    ) -> tuple[PayloadTemplate, ...]:
        ...


@runtime_checkable
class PayloadGenerator(Protocol):
    """Renders applicable templates into base (unmutated) PayloadVariants.

    Deliberately a different altitude than
    application.runtime.attacks.contracts.PayloadGenerator — see
    payload_value_objects.py's module docstring for the full
    disambiguation. This one may produce MULTIPLE variants per attack
    (e.g. one per applicable template, or one per supported language),
    reusing PayloadTemplate.render() rather than reimplementing
    substitution.
    """

    def generate(
        self,
        attack: AttackDefinition,
        templates: tuple[PayloadTemplate, ...],
        context: RenderContext,
    ) -> tuple[PayloadVariant, ...]:
        ...


@runtime_checkable
class PayloadSelector(Protocol):
    """Filters generated variants: capability-aware (drops variants
    whose template targets a capability the target lacks — via the
    template's declared provider_hint/metadata) and provider-aware
    (keeps only variants compatible with the resolved ProviderProfile).
    """

    def select(
        self,
        variants: tuple[PayloadVariant, ...],
        capabilities: frozenset[str],
        provider: ProviderProfile,
    ) -> tuple[PayloadVariant, ...]:
        ...


@runtime_checkable
class MutationStrategy(Protocol):
    """One pluggable payload mutation — encoding, obfuscation, or
    structural transformation. Each implementation is pure: given a
    PayloadVariant, return a NEW PayloadVariant with the mutation
    applied and recorded in mutation_history. Never mutates its input.
    """

    @property
    def mutation_type(self) -> MutationType:
        ...

    def mutate(self, variant: PayloadVariant) -> PayloadVariant:
        ...


@runtime_checkable
class ProviderAdapter(Protocol):
    """Purely structural, domain-layer content adaptation for a
    provider's message format (e.g. wrapping raw text as a chat
    message vs. leaving it as a completion prompt) — NOT HTTP/wire
    construction, which stays in domain.execution.repository.ProviderAdapter
    and the infrastructure.providers.* adapters that implement it.
    """

    def adapt(self, content: str, provider: ProviderProfile) -> str:
        ...


@runtime_checkable
class PayloadRenderer(Protocol):
    """Assembles a final PayloadVariant (after selection and mutation)
    into wire-ready ExecutionArtifacts, applying provider adaptation."""

    def render(
        self,
        variant: PayloadVariant,
        provider: ProviderProfile,
        provider_adapter: ProviderAdapter,
    ) -> ExecutionArtifacts:
        ...
