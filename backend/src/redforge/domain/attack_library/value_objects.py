"""Value objects for the Attack Library bounded context.

Models the classification, capabilities, and framework mappings
of reusable AI security attack techniques.
"""

from dataclasses import dataclass
from enum import StrEnum, unique

from redforge.shared.identifiers import EntityId


@unique
class AttackCategory(StrEnum):
    """Top-level classification of attack techniques."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    HALLUCINATION = "hallucination"
    TOOL_ABUSE = "tool_abuse"
    FUNCTION_CALLING = "function_calling"
    RAG_POISONING = "rag_poisoning"
    CONTEXT_MANIPULATION = "context_manipulation"
    MEMORY_POISONING = "memory_poisoning"
    AGENT_HIJACKING = "agent_hijacking"
    MODEL_EXTRACTION = "model_extraction"
    POLICY_BYPASS = "policy_bypass"
    GUARDRAIL_EVASION = "guardrail_evasion"
    DENIAL_OF_SERVICE = "denial_of_service"


@unique
class AttackStatus(StrEnum):
    """Lifecycle status of an attack definition.

    - DRAFT: Under development, not available for execution.
    - PUBLISHED: Available for use in validation runs.
    - DEPRECATED: Still executable for backwards compat, but discouraged.
    - ARCHIVED: No longer executable, preserved for historical evidence.
    - SUPERSEDED: Replaced by a newer version.
    """

    DRAFT = "draft"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"
    SUPERSEDED = "superseded"


@unique
class AttackSeverity(StrEnum):
    """Potential impact severity if the attack succeeds."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@unique
class SafetyClassification(StrEnum):
    """Safety level for executing this attack.

    Determines guardrails and approval requirements.
    - SAFE: No risk to target system stability.
    - CAUTION: May trigger rate limits or alerts.
    - DESTRUCTIVE: Could affect target system state.
    - RESTRICTED: Requires explicit approval to execute.
    """

    SAFE = "safe"
    CAUTION = "caution"
    DESTRUCTIVE = "destructive"
    RESTRICTED = "restricted"


@unique
class AttackMaturity(StrEnum):
    """How well-established this attack technique is."""

    EXPERIMENTAL = "experimental"
    EMERGING = "emerging"
    ESTABLISHED = "established"
    WELL_KNOWN = "well_known"


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    """Technique and optional sub-technique classification.

    Mirrors MITRE-style technique/sub-technique hierarchy.
    Example: technique="Prompt Injection", sub_technique="Indirect Injection"
    """

    technique: str
    sub_technique: str = ""

    def __post_init__(self) -> None:
        if not self.technique:
            raise ValueError("technique must not be empty")

    @property
    def full_name(self) -> str:
        if self.sub_technique:
            return f"{self.technique}: {self.sub_technique}"
        return self.technique


@dataclass(frozen=True, slots=True)
class AttackVersion:
    """Semantic version for an attack definition."""

    major: int
    minor: int
    patch: int

    def __post_init__(self) -> None:
        if self.major < 0 or self.minor < 0 or self.patch < 0:
            raise ValueError("Version components must be non-negative")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @classmethod
    def initial(cls) -> "AttackVersion":
        return cls(1, 0, 0)

    @classmethod
    def from_string(cls, value: str) -> "AttackVersion":
        parts = value.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid version: '{value}'")
        try:
            return cls(int(parts[0]), int(parts[1]), int(parts[2]))
        except ValueError as exc:
            raise ValueError(f"Invalid version: '{value}'") from exc


@dataclass(frozen=True, slots=True)
class FrameworkMapping:
    """Mapping to an external security framework.

    Links attacks to MITRE ATLAS, OWASP GenAI, NIST, etc.
    """

    framework: str
    identifier: str
    name: str = ""

    def __post_init__(self) -> None:
        if not self.framework:
            raise ValueError("framework must not be empty")
        if not self.identifier:
            raise ValueError("identifier must not be empty")


@dataclass(frozen=True, slots=True)
class ProviderCompatibility:
    """Defines which AI providers and target types an attack supports.

    An attack may only be applicable to certain providers (e.g., only
    OpenAI chat models) or target types (e.g., only RAG systems).
    """

    supported_target_types: frozenset[str]
    supported_providers: frozenset[str]
    supported_model_families: frozenset[str] = frozenset()

    @classmethod
    def universal(cls) -> "ProviderCompatibility":
        """Attack works with all providers and target types."""
        return cls(
            supported_target_types=frozenset(),
            supported_providers=frozenset(),
            supported_model_families=frozenset(),
        )

    @property
    def is_universal(self) -> bool:
        """Whether this attack has no provider/type restrictions."""
        return (
            len(self.supported_target_types) == 0
            and len(self.supported_providers) == 0
        )


@unique
class Capability(StrEnum):
    """A capability surface a target AI system may expose.

    Attacks declare which capabilities a target must have for the
    attack to even be applicable (e.g. an MCP Abuse attack requires
    MCP; a RAG Poisoning attack requires RAG). This is deliberately a
    closed enum, not a data-driven registry: unlike AttackCategory
    (attack techniques, which are genuinely unbounded — see
    AttackTaxonomyNode), the set of capability *surfaces* a target
    system can expose is a much smaller, slower-moving vocabulary
    (roughly bounded by "what kinds of I/O and affordances an AI
    system architecture can have"). Extending it is a deliberate,
    reviewed platform decision, not routine content authoring — that
    asymmetry is why it is an enum here and a tree there.
    """

    TOOL_CALLING = "tool_calling"
    MEMORY = "memory"
    MCP = "mcp"
    RAG = "rag"
    IMAGE_INPUT = "image_input"
    AUDIO = "audio"
    MULTIMODAL = "multimodal"
    AGENTS = "agents"
    BROWSER = "browser"
    CODE_EXECUTION = "code_execution"
    FILE_UPLOAD = "file_upload"
    LONG_CONTEXT = "long_context"
    STREAMING = "streaming"
    REASONING = "reasoning"
    COMPUTER_USE = "computer_use"


@unique
class ExecutionStrategy(StrEnum):
    """How an attack is meant to be carried out against a target.

    Declarative only — this sprint does not implement execution. This
    tells a future execution engine what shape of interaction the
    attack needs (a single request, a scripted conversation, an
    adaptive loop that reacts to responses, etc.) without prescribing
    how that engine works.
    """

    SINGLE_TURN = "single_turn"
    MULTI_TURN = "multi_turn"
    ADAPTIVE = "adaptive"
    CHAINED = "chained"
    AUTOMATED_AGENT = "automated_agent"


@dataclass(frozen=True, slots=True)
class AttackPrerequisite:
    """A condition that must hold before this attack is applicable.

    Distinct from AttackRelationship(PREREQUISITE_OF, ...): a
    relationship points at a specific *other attack* that must run
    first; a prerequisite is a free-form condition (optionally backed
    by required capabilities) that may or may not correspond to any
    single other attack definition — e.g. "target must be mid
    multi-turn conversation" or "requires prior reconnaissance of
    system prompt structure."
    """

    description: str
    required_capabilities: frozenset[Capability] = frozenset()

    def __post_init__(self) -> None:
        if not self.description:
            raise ValueError("description must not be empty")


@dataclass(frozen=True, slots=True)
class ExpectedOutcome:
    """A documented, expected result if the attack succeeds.

    `indicator` is the observable signal a future Evaluation Engine
    would look for (e.g. "response contains verbatim system prompt
    text") — declared here as data, not implemented as evaluation
    logic.
    """

    description: str
    indicator: str = ""

    def __post_init__(self) -> None:
        if not self.description:
            raise ValueError("description must not be empty")


@dataclass(frozen=True, slots=True)
class EvaluationRequirement:
    """What kind of evaluation this attack's results need.

    `method` names the evaluation approach (e.g. "keyword_match",
    "semantic_similarity", "llm_judge", "human_review") as a free-form
    string, not an enum: RedForge has no Evaluation Engine bounded
    context yet (explicitly out of scope for this sprint), so there is
    no canonical vocabulary to close this over yet. Declaring the
    requirement now — without inventing the engine that fulfills it —
    is exactly this sprint's scope.
    """

    method: str
    description: str = ""

    def __post_init__(self) -> None:
        if not self.method:
            raise ValueError("method must not be empty")


@dataclass(frozen=True, slots=True)
class CvssMetadata:
    """CVSS scoring for an attack, where a CVSS score is meaningful.

    Many AI attack techniques (e.g. jailbreaks, prompt injection) do
    not map cleanly onto CVSS's vulnerability-scoring model — this is
    why it is an optional field on AttackDefinition, not a required
    one. Where it IS meaningful (e.g. an attack chained with a genuine
    software vulnerability in a tool/plugin), this captures it in
    standard form rather than inventing a parallel scoring scheme.
    """

    version: str
    vector: str
    base_score: float

    def __post_init__(self) -> None:
        if not self.version:
            raise ValueError("version must not be empty")
        if not self.vector:
            raise ValueError("vector must not be empty")
        if not 0.0 <= self.base_score <= 10.0:
            raise ValueError("base_score must be between 0.0 and 10.0")


@dataclass(frozen=True, slots=True)
class AttackReference:
    """A citation attached to an attack definition — research paper,
    advisory, blog post, CVE record, or other external source."""

    url: str
    title: str
    source: str = ""

    def __post_init__(self) -> None:
        if not self.url:
            raise ValueError("url must not be empty")
        if not self.title:
            raise ValueError("title must not be empty")


@unique
class AttackRelationshipType(StrEnum):
    """Semantic relationship between two attack definitions.

    SUPERSEDES is deliberately excluded here — that lifecycle fact is
    already modeled by AttackDefinition.supersede()/superseded_by,
    which is a stateful transition (with its own invariants: only a
    PUBLISHED/DEPRECATED attack can be superseded), not a freely
    addable graph edge. Modeling it twice would create two competing
    sources of truth for the same fact.
    """

    PARENT_OF = "parent_of"
    DERIVED_FROM = "derived_from"
    PREREQUISITE_OF = "prerequisite_of"
    COMPOSED_OF = "composed_of"


@dataclass(frozen=True, slots=True)
class AttackRelationship:
    """A directed, typed edge from this attack to another attack.

    Graph traversal over these edges (ancestors, descendants,
    composition trees, prerequisite chains) is provided by the
    platform's existing knowledge graph (application/knowledge_graph.py)
    rather than reimplemented here — the domain layer only declares the
    facts; traversal is an application-layer concern over a projection
    of those facts. See knowledge_graph_populator for the projection.
    """

    related_attack_id: EntityId
    relationship_type: AttackRelationshipType
    notes: str = ""
