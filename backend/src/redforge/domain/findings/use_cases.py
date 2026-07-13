"""Application use cases for the Finding bounded context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.findings.entity import Finding
from redforge.domain.findings.exceptions import FindingNotFoundError
from redforge.domain.findings.value_objects import (
    ComplianceReference,
    MitreReference,
    OwaspReference,
    RiskScore,
    Severity,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.domain.findings.events import FindingEvent
    from redforge.domain.findings.repository import FindingRepository


# ─── Commands ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CreateFindingCommand:
    """Input for creating a finding from evidence."""

    organization_id: str
    run_id: str
    target_id: str
    evidence_ids: list[str]
    title: str
    description: str
    severity: str
    risk_score: float
    recommendation: str = ""


@dataclass(frozen=True, slots=True)
class AddReferenceCommand:
    """Input for adding a framework reference to a finding."""

    finding_id: str
    reference_type: str  # "compliance", "mitre", "owasp"
    framework: str = ""
    requirement_id: str = ""
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    category_id: str = ""
    category_name: str = ""
    description: str = ""


# ─── Results ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class FindingResult:
    """Read-only representation of a Finding."""

    id: str
    organization_id: str
    run_id: str
    target_id: str
    evidence_ids: list[str]
    title: str
    description: str
    severity: str
    risk_score: float
    status: str
    recommendation: str
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, finding: Finding) -> FindingResult:
        return cls(
            id=str(finding.id),
            organization_id=str(finding.organization_id),
            run_id=str(finding.run_id),
            target_id=str(finding.target_id),
            evidence_ids=[str(eid) for eid in finding.evidence_ids],
            title=finding.title,
            description=finding.description,
            severity=str(finding.severity),
            risk_score=finding.risk_score.score,
            status=str(finding.status),
            recommendation=finding.recommendation,
            created_at=finding.timestamps.created_at.isoformat(),
            updated_at=finding.timestamps.updated_at.isoformat(),
        )


# ─── Use Cases ────────────────────────────────────────────────────────────────


class CreateFindingUseCase:
    """Create a Finding derived from evidence."""

    def __init__(self, repository: FindingRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: CreateFindingCommand
    ) -> tuple[FindingResult, list[FindingEvent]]:
        finding = Finding.create_from_evidence(
            organization_id=EntityId.from_string(command.organization_id),
            run_id=EntityId.from_string(command.run_id),
            target_id=EntityId.from_string(command.target_id),
            evidence_ids=[EntityId.from_string(eid) for eid in command.evidence_ids],
            title=command.title,
            description=command.description,
            severity=Severity(command.severity),
            risk_score=RiskScore(score=command.risk_score),
            recommendation=command.recommendation,
        )
        await self._repository.save(finding)
        events = finding.collect_events()
        return FindingResult.from_entity(finding), events


class AcceptRiskUseCase:
    """Accept the risk for a finding."""

    def __init__(self, repository: FindingRepository) -> None:
        self._repository = repository

    async def execute(
        self, finding_id: str
    ) -> tuple[FindingResult, list[FindingEvent]]:
        finding = await self._load(finding_id)
        finding.accept_risk()
        await self._repository.save(finding)
        events = finding.collect_events()
        return FindingResult.from_entity(finding), events

    async def _load(self, finding_id: str) -> Finding:
        entity_id = EntityId.from_string(finding_id)
        finding = await self._repository.get_by_id(entity_id)
        if finding is None:
            raise FindingNotFoundError(finding_id)
        return finding


class CloseFindingUseCase:
    """Close a finding."""

    def __init__(self, repository: FindingRepository) -> None:
        self._repository = repository

    async def execute(
        self, finding_id: str
    ) -> tuple[FindingResult, list[FindingEvent]]:
        entity_id = EntityId.from_string(finding_id)
        finding = await self._repository.get_by_id(entity_id)
        if finding is None:
            raise FindingNotFoundError(finding_id)
        finding.close()
        await self._repository.save(finding)
        events = finding.collect_events()
        return FindingResult.from_entity(finding), events


class ReopenFindingUseCase:
    """Reopen a closed or accepted finding."""

    def __init__(self, repository: FindingRepository) -> None:
        self._repository = repository

    async def execute(
        self, finding_id: str
    ) -> tuple[FindingResult, list[FindingEvent]]:
        entity_id = EntityId.from_string(finding_id)
        finding = await self._repository.get_by_id(entity_id)
        if finding is None:
            raise FindingNotFoundError(finding_id)
        finding.reopen()
        await self._repository.save(finding)
        events = finding.collect_events()
        return FindingResult.from_entity(finding), events


class AddReferenceUseCase:
    """Add a compliance/MITRE/OWASP reference to a finding."""

    def __init__(self, repository: FindingRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: AddReferenceCommand
    ) -> tuple[FindingResult, list[FindingEvent]]:
        entity_id = EntityId.from_string(command.finding_id)
        finding = await self._repository.get_by_id(entity_id)
        if finding is None:
            raise FindingNotFoundError(command.finding_id)

        if command.reference_type == "compliance":
            finding.add_compliance_reference(
                ComplianceReference(
                    framework=command.framework,
                    requirement_id=command.requirement_id,
                    description=command.description,
                )
            )
        elif command.reference_type == "mitre":
            finding.add_mitre_reference(
                MitreReference(
                    technique_id=command.technique_id,
                    technique_name=command.technique_name,
                    tactic=command.tactic,
                )
            )
        elif command.reference_type == "owasp":
            finding.add_owasp_reference(
                OwaspReference(
                    category_id=command.category_id,
                    category_name=command.category_name,
                )
            )
        else:
            raise ValueError(f"Unknown reference type: '{command.reference_type}'")

        await self._repository.save(finding)
        events = finding.collect_events()
        return FindingResult.from_entity(finding), events


class GetFindingUseCase:
    """Retrieve a finding by id."""

    def __init__(self, repository: FindingRepository) -> None:
        self._repository = repository

    async def execute(self, finding_id: str) -> FindingResult:
        entity_id = EntityId.from_string(finding_id)
        finding = await self._repository.get_by_id(entity_id)
        if finding is None:
            raise FindingNotFoundError(finding_id)
        return FindingResult.from_entity(finding)
