"""Value objects for the Payload Intelligence Engine — the layer above
PayloadTemplate that converts a rendered template into a versioned,
capability/provider-aware, optionally-mutated executable artifact.

Layering, so nothing here is confused with what already exists:
  - `PayloadTemplate.render()` (entity.py) does {{var}} substitution —
    reused as-is by the default PayloadGenerator (payload_pipeline.py),
    never reimplemented here.
  - `application.runtime.attacks.contracts.PayloadGenerator` is a
    narrower, single-attack, single-turn Protocol already wired into
    `AttackPipelineRunner`. The `PayloadGenerator` Protocol in this
    package (protocols.py) is deliberately a different, higher-altitude
    concept (multi-variant, multi-language, mutation-aware, driven by a
    whole AttackPlan) — same "same name, different altitude, different
    module path" resolution Sprint 14 used for `AttackPlan`/
    `ExecutionStrategy`, applied consistently here.
  - `domain.execution.repository.ProviderAdapter` translates a rendered
    payload into a specific provider's wire format at execution time
    (an infra-adjacent concern). The `ProviderAdapter` Protocol here is
    a narrower, purely-structural, domain-layer concept (chat-message
    wrapping vs. raw-text) — it does not construct HTTP payloads.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum, unique
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId


@unique
class MutationType(StrEnum):
    """Pluggable payload mutation strategies.

    A closed enum naming *which* strategies exist, dispatched through
    MUTATION_REGISTRY (a dict, built from data) rather than an
    if/elif/switch chain — the same "enum + registry, not enum + switch"
    pattern Sprint 14 used for PlanningStrategy/STRATEGY_REGISTRY.
    Adding a new mutation is one new class + one registry entry, never
    a new branch anywhere.
    """

    UNICODE = "unicode"
    BASE64 = "base64"
    ZERO_WIDTH = "zero_width"
    MARKDOWN = "markdown"
    HTML = "html"
    XML = "xml"
    YAML = "yaml"
    JSON = "json"
    TYPOGLYCEMIA = "typoglycemia"
    WHITESPACE = "whitespace"
    CASE_MUTATION = "case_mutation"
    MULTI_PART = "multi_part"


@dataclass(frozen=True, slots=True)
class PayloadMutationPlan:
    """A declared, ordered sequence of mutations to apply to a
    PayloadVariant, and why — the audit trail for "why does this
    payload look like this."""

    mutations: tuple[MutationType, ...] = ()
    rationale: str = ""

    def __post_init__(self) -> None:
        if len(self.mutations) != len(set(self.mutations)):
            raise ValueError("PayloadMutationPlan must not repeat a mutation type")


@dataclass(frozen=True, slots=True)
class ProviderProfile:
    """A lightweight, domain-layer snapshot of a target's provider —
    deliberately NOT the full `domain.providers.ProviderRegistration`
    entity (that would pull a heavier cross-context dependency into
    payload generation for no benefit). Mirrors the same
    resolved-snapshot pattern Sprint 14's CapabilityResolver used
    (`frozenset[str]` capability values, not entity references).
    """

    provider_id: str
    message_format: str = "chat"  # "chat" | "completion" | "raw"
    supported_capabilities: frozenset[str] = frozenset()
    model_family: str = ""

    def __post_init__(self) -> None:
        if not self.provider_id:
            raise ValueError("provider_id must not be empty")
        if self.message_format not in {"chat", "completion", "raw"}:
            raise ValueError(
                f"message_format must be 'chat', 'completion', or 'raw', "
                f"got '{self.message_format}'"
            )


class PayloadVariant:
    """One rendered, optionally mutated candidate payload for one
    attack — identity-bearing (unlike most value objects here) because
    a PayloadBundle needs to track a specific variant through selection
    and a chain of mutations, and because two variants that happen to
    render identical content are still distinct planning decisions
    (e.g. two languages that happen to translate the same short
    phrase identically).

    Mutation is represented as producing a NEW PayloadVariant (frozen,
    via `with_mutation()`) that keeps the same `id` — the identity is
    "this variant, now further transformed," not "a new variant."
    """

    __slots__ = (
        "_attack_id",
        "_content",
        "_id",
        "_language",
        "_metadata",
        "_mutation_history",
        "_template_id",
        "_variables_used",
        "_version",
    )

    def __init__(
        self,
        id: EntityId,
        attack_id: EntityId,
        template_id: EntityId,
        content: str,
        variables_used: dict[str, str],
        language: str = "en",
        mutation_history: tuple[MutationType, ...] = (),
        version: int = 1,
        metadata: dict[str, str] | None = None,
    ) -> None:
        if not content:
            raise ValueError("PayloadVariant content must not be empty")
        if version < 1:
            raise ValueError("version must be >= 1")
        self._id = id
        self._attack_id = attack_id
        self._template_id = template_id
        self._content = content
        self._variables_used = dict(variables_used)
        self._language = language
        self._mutation_history = mutation_history
        self._version = version
        self._metadata = dict(metadata or {})

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def attack_id(self) -> EntityId:
        return self._attack_id

    @property
    def template_id(self) -> EntityId:
        return self._template_id

    @property
    def content(self) -> str:
        return self._content

    @property
    def variables_used(self) -> dict[str, str]:
        return dict(self._variables_used)

    @property
    def language(self) -> str:
        return self._language

    @property
    def mutation_history(self) -> tuple[MutationType, ...]:
        return self._mutation_history

    @property
    def version(self) -> int:
        return self._version

    @property
    def metadata(self) -> dict[str, str]:
        return dict(self._metadata)

    @property
    def is_mutated(self) -> bool:
        return len(self._mutation_history) > 0

    def with_mutation(self, mutation_type: MutationType, new_content: str) -> PayloadVariant:
        """Return a new PayloadVariant reflecting one applied mutation.
        Does not mutate self — PayloadVariant instances never change
        after construction."""
        if not new_content:
            raise ValueError("Mutation must not produce empty content")
        return PayloadVariant(
            id=self._id,
            attack_id=self._attack_id,
            template_id=self._template_id,
            content=new_content,
            variables_used=self._variables_used,
            language=self._language,
            mutation_history=(*self._mutation_history, mutation_type),
            version=self._version + 1,
            metadata=self._metadata,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PayloadVariant):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"PayloadVariant(id={self._id}, attack_id={self._attack_id}, "
            f"language={self._language!r}, version={self._version}, "
            f"mutations={[str(m) for m in self._mutation_history]})"
        )


@dataclass(frozen=True, slots=True)
class ExecutionArtifacts:
    """The final, wire-ready artifact for one PayloadVariant — what a
    future (not-this-sprint) execution engine would place directly into
    `domain.evidence.value_objects.RequestPayload.body`. `rendered_body`
    is deliberately a plain string (not a structured object) to stay
    compatible with that existing type.

    `checksum` is a sha256 hex digest of `rendered_body` — cheap
    integrity/audit value letting evidence later prove exactly what was
    sent without re-deriving it from a possibly-since-changed template.
    """

    variant_id: EntityId
    attack_id: EntityId
    rendered_body: str
    content_type: str = "text/plain"
    encoding: str = "utf-8"
    provider_hint: str = ""
    checksum: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.rendered_body:
            raise ValueError("rendered_body must not be empty")
        expected = hashlib.sha256(self.rendered_body.encode("utf-8")).hexdigest()
        if self.checksum and self.checksum != expected:
            raise ValueError("checksum does not match rendered_body")
        if not self.checksum:
            object.__setattr__(self, "checksum", expected)


@unique
class BundleStatus(StrEnum):
    """Lifecycle status of a PayloadBundle — the same two-state
    immutable-except-supersede pattern as domain.planning.PlanStatus."""

    ACTIVE = "active"
    SUPERSEDED = "superseded"
