"""Evidence aggregate root.

Evidence is the immutable source of truth in RedForge. Each piece of evidence
captures a single interaction with an AI target during a security check.

Key architectural invariant: Evidence is NEVER modified after finalization.
Once finalized, it is sealed. Findings are generated FROM evidence and can
always be regenerated without re-executing the validation.

Lifecycle:
1. record() — Create evidence with core data (request, response, result).
2. attach_artifact() — Add supporting artifacts (before finalization).
3. attach_trace() — Add tracing metadata (before finalization).
4. finalize() — Seal the evidence. No further mutations allowed.
"""

from typing import Self

from redforge.domain.evidence.events import (
    ArtifactAttached,
    EvidenceArchived,
    EvidenceEvent,
    EvidenceFinalized,
    EvidenceRecorded,
    _now,
)
from redforge.domain.evidence.exceptions import EvidenceImmutableError
from redforge.domain.evidence.value_objects import (
    Artifact,
    AttackReference,
    Confidence,
    EvidenceResult,
    ExecutionMetadata,
    RequestPayload,
    ResponsePayload,
    TestCaseReference,
    TraceMetadata,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


class Evidence:
    """Evidence aggregate root — immutable after finalization.

    Invariants:
    - Evidence always belongs to an Organization, ValidationRun, and AITarget.
    - Once finalized, no mutations are permitted (append-only).
    - Artifacts and traces can only be attached before finalization.
    - Evidence must have a request, response, and result to be recorded.
    """

    __slots__ = (
        "_artifacts",
        "_attack_ref",
        "_confidence",
        "_events",
        "_execution_metadata",
        "_finalized",
        "_id",
        "_is_archived",
        "_organization_id",
        "_request",
        "_response",
        "_result",
        "_run_id",
        "_target_id",
        "_test_case_ref",
        "_timestamps",
        "_trace",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        run_id: EntityId,
        target_id: EntityId,
        test_case_ref: TestCaseReference,
        attack_ref: AttackReference,
        request: RequestPayload,
        response: ResponsePayload,
        result: EvidenceResult,
        confidence: Confidence,
        execution_metadata: ExecutionMetadata,
        trace: TraceMetadata | None,
        artifacts: list[Artifact],
        finalized: bool,
        is_archived: bool,
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._run_id = run_id
        self._target_id = target_id
        self._test_case_ref = test_case_ref
        self._attack_ref = attack_ref
        self._request = request
        self._response = response
        self._result = result
        self._confidence = confidence
        self._execution_metadata = execution_metadata
        self._trace = trace
        self._artifacts = artifacts
        self._finalized = finalized
        self._is_archived = is_archived
        self._timestamps = timestamps
        self._events: list[EvidenceEvent] = []

    @classmethod
    def record(
        cls,
        organization_id: EntityId,
        run_id: EntityId,
        target_id: EntityId,
        test_case_ref: TestCaseReference,
        attack_ref: AttackReference,
        request: RequestPayload,
        response: ResponsePayload,
        result: EvidenceResult,
        confidence: Confidence,
        execution_metadata: ExecutionMetadata,
    ) -> Self:
        """Record a new piece of evidence.

        Creates evidence in an unfinalised state. Artifacts and traces
        can be attached before calling finalize().
        """
        evidence = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            run_id=run_id,
            target_id=target_id,
            test_case_ref=test_case_ref,
            attack_ref=attack_ref,
            request=request,
            response=response,
            result=result,
            confidence=confidence,
            execution_metadata=execution_metadata,
            trace=None,
            artifacts=[],
            finalized=False,
            is_archived=False,
            timestamps=AuditTimestamps.create(),
        )
        evidence._record_event(
            EvidenceRecorded(
                occurred_at=_now(),
                evidence_id=str(evidence._id),
                run_id=str(run_id),
                target_id=str(target_id),
                result=str(result),
            )
        )
        return evidence

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def run_id(self) -> EntityId:
        return self._run_id

    @property
    def target_id(self) -> EntityId:
        return self._target_id

    @property
    def test_case_ref(self) -> TestCaseReference:
        return self._test_case_ref

    @property
    def attack_ref(self) -> AttackReference:
        return self._attack_ref

    @property
    def request(self) -> RequestPayload:
        return self._request

    @property
    def response(self) -> ResponsePayload:
        return self._response

    @property
    def result(self) -> EvidenceResult:
        return self._result

    @property
    def confidence(self) -> Confidence:
        return self._confidence

    @property
    def execution_metadata(self) -> ExecutionMetadata:
        return self._execution_metadata

    @property
    def trace(self) -> TraceMetadata | None:
        return self._trace

    @property
    def artifacts(self) -> tuple[Artifact, ...]:
        return tuple(self._artifacts)

    @property
    def is_finalized(self) -> bool:
        return self._finalized

    @property
    def is_archived(self) -> bool:
        return self._is_archived

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    # ─── Behavior ─────────────────────────────────────────────────────────

    def attach_artifact(self, artifact: Artifact) -> None:
        """Attach a supporting artifact to this evidence.

        Only permitted before finalization.
        """
        self._require_mutable()
        self._artifacts.append(artifact)
        self._record_event(
            ArtifactAttached(
                occurred_at=_now(),
                evidence_id=str(self._id),
                artifact_id=artifact.artifact_id,
                artifact_name=artifact.name,
            )
        )

    def attach_trace(self, trace: TraceMetadata) -> None:
        """Attach distributed tracing metadata.

        Only permitted before finalization.
        """
        self._require_mutable()
        self._trace = trace

    def finalize(self) -> None:
        """Seal this evidence. No further mutations are allowed.

        After finalization, this evidence becomes the immutable source
        of truth that findings are generated from.
        """
        self._require_mutable()
        self._finalized = True
        self._record_event(
            EvidenceFinalized(
                occurred_at=_now(),
                evidence_id=str(self._id),
                run_id=str(self._run_id),
            )
        )

    def archive(self) -> None:
        """Mark evidence as archived (moved to cold storage).

        Archived evidence remains immutable and queryable but may
        have slower access times.
        """
        if not self._finalized:
            self._require_mutable()
        self._is_archived = True
        self._record_event(
            EvidenceArchived(
                occurred_at=_now(),
                evidence_id=str(self._id),
            )
        )

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[EvidenceEvent]:
        """Return and clear all pending domain events."""
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_mutable(self) -> None:
        """Guard: raises if evidence is finalized."""
        if self._finalized:
            raise EvidenceImmutableError(str(self._id))

    def _record_event(self, event: EvidenceEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Evidence):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"Evidence(id={self._id}, result={self._result}, "
            f"finalized={self._finalized})"
        )
