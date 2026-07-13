"""Application use cases for the Evidence bounded context.

Evidence use cases are append-only operations. There is no update or delete.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.evidence.entity import Evidence
from redforge.domain.evidence.exceptions import EvidenceNotFoundError
from redforge.domain.evidence.value_objects import (
    AttackReference,
    Confidence,
    EvidenceResult,
    ExecutionMetadata,
    RequestPayload,
    ResponsePayload,
    TestCaseReference,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from redforge.domain.evidence.events import EvidenceEvent
    from redforge.domain.evidence.repository import EvidenceRepository


# ─── Commands ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RecordEvidenceCommand:
    """Input for recording a new piece of evidence."""

    organization_id: str
    run_id: str
    target_id: str
    test_id: str
    test_name: str
    test_category: str
    attack_id: str
    attack_name: str
    attack_type: str
    attack_version: str
    request_method: str
    request_url: str
    request_headers: dict[str, str]
    request_body: str
    response_status_code: int
    response_headers: dict[str, str]
    response_body: str
    response_latency_ms: int
    result: str
    confidence: float
    engine_version: str
    duration_ms: int
    worker_id: str | None = None


# ─── Results ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class EvidenceResultDTO:
    """Read-only representation of Evidence at the application boundary."""

    id: str
    organization_id: str
    run_id: str
    target_id: str
    test_case_id: str
    test_case_name: str
    attack_id: str
    attack_name: str
    result: str
    confidence: float
    is_finalized: bool
    is_archived: bool
    created_at: str

    @classmethod
    def from_entity(cls, evidence: Evidence) -> EvidenceResultDTO:
        return cls(
            id=str(evidence.id),
            organization_id=str(evidence.organization_id),
            run_id=str(evidence.run_id),
            target_id=str(evidence.target_id),
            test_case_id=evidence.test_case_ref.test_id,
            test_case_name=evidence.test_case_ref.test_name,
            attack_id=evidence.attack_ref.attack_id,
            attack_name=evidence.attack_ref.attack_name,
            result=str(evidence.result),
            confidence=evidence.confidence.score,
            is_finalized=evidence.is_finalized,
            is_archived=evidence.is_archived,
            created_at=evidence.timestamps.created_at.isoformat(),
        )


# ─── Use Cases ────────────────────────────────────────────────────────────────


class RecordEvidenceUseCase:
    """Record a new piece of evidence from a security check execution.

    Creates evidence, immediately finalizes it (the execution is complete),
    and persists. Evidence is born immutable.
    """

    def __init__(self, repository: EvidenceRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: RecordEvidenceCommand
    ) -> tuple[EvidenceResultDTO, list[EvidenceEvent]]:
        evidence = Evidence.record(
            organization_id=EntityId.from_string(command.organization_id),
            run_id=EntityId.from_string(command.run_id),
            target_id=EntityId.from_string(command.target_id),
            test_case_ref=TestCaseReference(
                test_id=command.test_id,
                test_name=command.test_name,
                category=command.test_category,
            ),
            attack_ref=AttackReference(
                attack_id=command.attack_id,
                attack_name=command.attack_name,
                attack_type=command.attack_type,
                version=command.attack_version,
            ),
            request=RequestPayload(
                method=command.request_method,
                url=command.request_url,
                headers=command.request_headers,
                body=command.request_body,
            ),
            response=ResponsePayload(
                status_code=command.response_status_code,
                headers=command.response_headers,
                body=command.response_body,
                latency_ms=command.response_latency_ms,
            ),
            result=EvidenceResult(command.result),
            confidence=Confidence(score=command.confidence),
            execution_metadata=ExecutionMetadata(
                executed_at=utc_now(),
                duration_ms=command.duration_ms,
                engine_version=command.engine_version,
                worker_id=command.worker_id,
            ),
        )

        evidence.finalize()
        await self._repository.save(evidence)
        events = evidence.collect_events()

        return EvidenceResultDTO.from_entity(evidence), events


class GetEvidenceUseCase:
    """Retrieve evidence by id."""

    def __init__(self, repository: EvidenceRepository) -> None:
        self._repository = repository

    async def execute(self, evidence_id: str) -> EvidenceResultDTO:
        entity_id = EntityId.from_string(evidence_id)
        evidence = await self._repository.get_by_id(entity_id)
        if evidence is None:
            raise EvidenceNotFoundError(evidence_id)
        return EvidenceResultDTO.from_entity(evidence)


class ListEvidenceByRunUseCase:
    """List all evidence for a validation run."""

    def __init__(self, repository: EvidenceRepository) -> None:
        self._repository = repository

    async def execute(
        self, run_id: str, result_filter: str | None = None
    ) -> list[EvidenceResultDTO]:
        entity_id = EntityId.from_string(run_id)
        result = EvidenceResult(result_filter) if result_filter else None
        evidence_list = await self._repository.list_by_run(entity_id, result=result)
        return [EvidenceResultDTO.from_entity(e) for e in evidence_list]
