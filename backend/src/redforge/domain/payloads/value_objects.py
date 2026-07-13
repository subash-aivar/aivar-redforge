"""Value objects for the Prompt & Payload Engine.

Templates define reusable payload structures. Variables are resolved
at render time. The execution engine receives only rendered payloads.
"""

from dataclasses import dataclass, field
from enum import StrEnum, unique


@unique
class TemplateStatus(StrEnum):
    """Lifecycle status of a payload template."""

    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"


@unique
class TemplateType(StrEnum):
    """What kind of payload the template produces."""

    PROMPT = "prompt"
    CONVERSATION = "conversation"
    FUNCTION_CALL = "function_call"
    TOOL_USE = "tool_use"
    MULTI_TURN = "multi_turn"
    RAW = "raw"


@unique
class VariableType(StrEnum):
    """Type of a template variable for validation."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    LIST = "list"
    JSON = "json"


@dataclass(frozen=True, slots=True)
class TemplateVariable:
    """A declared variable within a template.

    Variables are placeholders resolved at render time with
    context from the target, attack, or execution environment.
    """

    name: str
    variable_type: VariableType = VariableType.STRING
    required: bool = True
    default_value: str = ""
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Variable name must not be empty")
        if not self.name.isidentifier():
            raise ValueError(
                f"Variable name must be a valid identifier: '{self.name}'"
            )


@dataclass(frozen=True, slots=True)
class TemplateVersion:
    """Semantic version for a template."""

    major: int
    minor: int
    patch: int

    def __post_init__(self) -> None:
        if self.major < 0 or self.minor < 0 or self.patch < 0:
            raise ValueError("Version components must be non-negative")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @classmethod
    def initial(cls) -> "TemplateVersion":
        return cls(1, 0, 0)


@dataclass(frozen=True, slots=True)
class RenderedPayload:
    """The output of template rendering — ready for provider dispatch.

    This is what the execution engine passes to a ProviderAdapter.
    """

    content: str
    template_id: str
    variables_used: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.content:
            raise ValueError("Rendered payload content must not be empty")
        if not self.template_id:
            raise ValueError("template_id must not be empty")


@dataclass(frozen=True, slots=True)
class RenderContext:
    """Context provided at render time for variable resolution.

    Contains values from the target, attack definition, and
    execution environment.
    """

    variables: dict[str, str] = field(default_factory=dict)
    target_metadata: dict[str, str] = field(default_factory=dict)
    attack_metadata: dict[str, str] = field(default_factory=dict)

    def get(self, key: str, default: str = "") -> str:
        """Resolve a variable from the context hierarchy."""
        if key in self.variables:
            return self.variables[key]
        if key in self.target_metadata:
            return self.target_metadata[key]
        if key in self.attack_metadata:
            return self.attack_metadata[key]
        return default
