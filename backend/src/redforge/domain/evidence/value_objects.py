"""Value objects for the Evidence bounded context.

Evidence is immutable. These value objects represent the captured
data from a single security check execution against an AI target.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum, unique


@unique
class EvidenceResult(StrEnum):
    """Outcome of a single evidence-producing check.

    - PASS: The check passed — no security issue detected.
    - FAIL: The check failed — a security issue was detected.
    - ERROR: The check could not complete due to an error.
    - INCONCLUSIVE: The check produced ambiguous results.
    """

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class Confidence:
    """Confidence score for an evidence result.

    Represents how confident the system is in the result classification.
    Scale: 0.0 (no confidence) to 1.0 (absolute certainty).
    """

    score: float

    def __post_init__(self) -> None:
        if self.score < 0.0 or self.score > 1.0:
            raise ValueError(
                f"Confidence score must be between 0.0 and 1.0, got {self.score}"
            )

    @property
    def is_high(self) -> bool:
        """Whether confidence exceeds 0.8 threshold."""
        return self.score >= 0.8

    @property
    def is_low(self) -> bool:
        """Whether confidence is below 0.5 threshold."""
        return self.score < 0.5


@dataclass(frozen=True, slots=True)
class TestCaseReference:
    """Reference to the test case that produced this evidence.

    Links evidence back to a specific test definition in an attack module.
    """

    test_id: str
    test_name: str
    category: str

    def __post_init__(self) -> None:
        if not self.test_id:
            raise ValueError("test_id must not be empty")
        if not self.test_name:
            raise ValueError("test_name must not be empty")
        if not self.category:
            raise ValueError("category must not be empty")


@dataclass(frozen=True, slots=True)
class AttackReference:
    """Reference to the attack module that generated this evidence.

    Links evidence to the specific attack strategy used.
    """

    attack_id: str
    attack_name: str
    attack_type: str
    version: str = "1.0"

    def __post_init__(self) -> None:
        if not self.attack_id:
            raise ValueError("attack_id must not be empty")
        if not self.attack_name:
            raise ValueError("attack_name must not be empty")
        if not self.attack_type:
            raise ValueError("attack_type must not be empty")


@dataclass(frozen=True, slots=True)
class RequestPayload:
    """The request sent to the AI target during the check.

    Captures exactly what was sent so the evidence is reproducible.
    """

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def __post_init__(self) -> None:
        if not self.method:
            raise ValueError("method must not be empty")
        if not self.url:
            raise ValueError("url must not be empty")


@dataclass(frozen=True, slots=True)
class ResponsePayload:
    """The response received from the AI target.

    Captures the raw response for analysis and reproducibility.
    """

    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    latency_ms: int = 0

    def __post_init__(self) -> None:
        if self.status_code < 0:
            raise ValueError("status_code must be non-negative")
        if self.latency_ms < 0:
            raise ValueError("latency_ms must be non-negative")


@dataclass(frozen=True, slots=True)
class Artifact:
    """An immutable artifact attached to evidence.

    Artifacts are binary or text data captured during execution
    (screenshots, logs, full conversation transcripts, etc.).
    """

    artifact_id: str
    name: str
    content_type: str
    size_bytes: int
    storage_ref: str

    def __post_init__(self) -> None:
        if not self.artifact_id:
            raise ValueError("artifact_id must not be empty")
        if not self.name:
            raise ValueError("name must not be empty")
        if not self.content_type:
            raise ValueError("content_type must not be empty")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")
        if not self.storage_ref:
            raise ValueError("storage_ref must not be empty")


@dataclass(frozen=True, slots=True)
class TraceMetadata:
    """Distributed tracing metadata for evidence lineage.

    Enables correlation of evidence back to specific execution
    contexts, spans, and infrastructure.
    """

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    service_name: str = "redforge-engine"

    def __post_init__(self) -> None:
        if not self.trace_id:
            raise ValueError("trace_id must not be empty")
        if not self.span_id:
            raise ValueError("span_id must not be empty")


@dataclass(frozen=True, slots=True)
class ExecutionMetadata:
    """Metadata about the execution environment and timing.

    Captures when and where the check was executed for auditability.
    """

    executed_at: datetime
    duration_ms: int
    engine_version: str
    worker_id: str | None = None

    def __post_init__(self) -> None:
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be non-negative")
        if not self.engine_version:
            raise ValueError("engine_version must not be empty")
