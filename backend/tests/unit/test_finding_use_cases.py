"""Unit tests for Finding use cases."""

import pytest

from redforge.domain.findings.entity import Finding
from redforge.domain.findings.events import FindingClosed, FindingCreated, FindingRiskAccepted
from redforge.domain.findings.exceptions import FindingNotFoundError
from redforge.domain.findings.use_cases import (
    AcceptRiskUseCase,
    AddReferenceCommand,
    AddReferenceUseCase,
    CloseFindingUseCase,
    CreateFindingCommand,
    CreateFindingUseCase,
    GetFindingUseCase,
    ReopenFindingUseCase,
)
from redforge.shared.identifiers import EntityId


class InMemoryFindingRepository:
    def __init__(self) -> None:
        self._store: dict[str, Finding] = {}

    async def get_by_id(self, finding_id: EntityId) -> Finding | None:
        return self._store.get(str(finding_id))

    async def list_by_run(
        self, run_id: EntityId, severity=None, status=None
    ) -> list[Finding]:
        return [f for f in self._store.values() if f.run_id == run_id]

    async def list_by_target(
        self, target_id: EntityId, severity=None, status=None
    ) -> list[Finding]:
        return [f for f in self._store.values() if f.target_id == target_id]

    async def save(self, finding: Finding) -> None:
        self._store[str(finding.id)] = finding


def _repo() -> InMemoryFindingRepository:
    return InMemoryFindingRepository()


def _cmd() -> CreateFindingCommand:
    return CreateFindingCommand(
        organization_id=str(EntityId.generate()),
        run_id=str(EntityId.generate()),
        target_id=str(EntityId.generate()),
        evidence_ids=[str(EntityId.generate())],
        title="SQL Injection in AI Response",
        description="AI generated SQL that was executed",
        severity="high",
        risk_score=7.5,
        recommendation="Sanitize AI outputs",
    )


class TestCreateFinding:
    async def test_creates(self) -> None:
        repo = _repo()
        uc = CreateFindingUseCase(repo)
        result, events = await uc.execute(_cmd())
        assert result.status == "open"
        assert result.severity == "high"
        assert isinstance(events[0], FindingCreated)

    async def test_persists(self) -> None:
        repo = _repo()
        uc = CreateFindingUseCase(repo)
        result, _ = await uc.execute(_cmd())
        stored = await repo.get_by_id(EntityId.from_string(result.id))
        assert stored is not None


class TestAcceptRisk:
    async def test_accepts(self) -> None:
        repo = _repo()
        create_uc = CreateFindingUseCase(repo)
        created, _ = await create_uc.execute(_cmd())
        uc = AcceptRiskUseCase(repo)
        result, events = await uc.execute(created.id)
        assert result.status == "accepted"
        assert isinstance(events[0], FindingRiskAccepted)

    async def test_not_found_raises(self) -> None:
        repo = _repo()
        uc = AcceptRiskUseCase(repo)
        with pytest.raises(FindingNotFoundError):
            await uc.execute(str(EntityId.generate()))


class TestCloseFinding:
    async def test_closes(self) -> None:
        repo = _repo()
        create_uc = CreateFindingUseCase(repo)
        created, _ = await create_uc.execute(_cmd())
        uc = CloseFindingUseCase(repo)
        result, events = await uc.execute(created.id)
        assert result.status == "closed"
        assert isinstance(events[0], FindingClosed)


class TestReopenFinding:
    async def test_reopens_closed(self) -> None:
        repo = _repo()
        create_uc = CreateFindingUseCase(repo)
        created, _ = await create_uc.execute(_cmd())
        close_uc = CloseFindingUseCase(repo)
        await close_uc.execute(created.id)
        uc = ReopenFindingUseCase(repo)
        result, _ = await uc.execute(created.id)
        assert result.status == "reopened"


class TestAddReference:
    async def test_adds_owasp(self) -> None:
        repo = _repo()
        create_uc = CreateFindingUseCase(repo)
        created, _ = await create_uc.execute(_cmd())
        uc = AddReferenceUseCase(repo)
        result, _ = await uc.execute(AddReferenceCommand(
            finding_id=created.id,
            reference_type="owasp",
            category_id="LLM01",
            category_name="Prompt Injection",
        ))
        stored = await repo.get_by_id(EntityId.from_string(result.id))
        assert stored is not None
        assert len(stored.owasp_refs) == 1

    async def test_invalid_type_raises(self) -> None:
        repo = _repo()
        create_uc = CreateFindingUseCase(repo)
        created, _ = await create_uc.execute(_cmd())
        uc = AddReferenceUseCase(repo)
        with pytest.raises(ValueError, match="Unknown reference type"):
            await uc.execute(AddReferenceCommand(
                finding_id=created.id,
                reference_type="unknown",
            ))


class TestGetFinding:
    async def test_gets(self) -> None:
        repo = _repo()
        create_uc = CreateFindingUseCase(repo)
        created, _ = await create_uc.execute(_cmd())
        uc = GetFindingUseCase(repo)
        result = await uc.execute(created.id)
        assert result.title == "SQL Injection in AI Response"

    async def test_not_found_raises(self) -> None:
        repo = _repo()
        uc = GetFindingUseCase(repo)
        with pytest.raises(FindingNotFoundError):
            await uc.execute(str(EntityId.generate()))
