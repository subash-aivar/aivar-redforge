"""Unit tests for Evidence use cases."""

import pytest

from redforge.domain.evidence.entity import Evidence
from redforge.domain.evidence.events import EvidenceFinalized, EvidenceRecorded
from redforge.domain.evidence.exceptions import EvidenceNotFoundError
from redforge.domain.evidence.use_cases import (
    GetEvidenceUseCase,
    ListEvidenceByRunUseCase,
    RecordEvidenceCommand,
    RecordEvidenceUseCase,
)
from redforge.domain.evidence.value_objects import EvidenceResult
from redforge.shared.identifiers import EntityId


class InMemoryEvidenceRepository:
    def __init__(self) -> None:
        self._store: dict[str, Evidence] = {}

    async def get_by_id(self, evidence_id: EntityId) -> Evidence | None:
        return self._store.get(str(evidence_id))

    async def list_by_run(
        self, run_id: EntityId, result: EvidenceResult | None = None
    ) -> list[Evidence]:
        items = [e for e in self._store.values() if e.run_id == run_id]
        if result:
            items = [e for e in items if e.result == result]
        return items

    async def list_by_target(
        self, target_id: EntityId, result: EvidenceResult | None = None
    ) -> list[Evidence]:
        items = [e for e in self._store.values() if e.target_id == target_id]
        if result:
            items = [e for e in items if e.result == result]
        return items

    async def save(self, evidence: Evidence) -> None:
        self._store[str(evidence.id)] = evidence


def _repo() -> InMemoryEvidenceRepository:
    return InMemoryEvidenceRepository()


def _command(
    run_id: str | None = None,
    result: str = "fail",
) -> RecordEvidenceCommand:
    return RecordEvidenceCommand(
        organization_id=str(EntityId.generate()),
        run_id=run_id or str(EntityId.generate()),
        target_id=str(EntityId.generate()),
        test_id="tc-001",
        test_name="Basic Injection",
        test_category="injection",
        attack_id="atk-001",
        attack_name="Direct Injection",
        attack_type="prompt_injection",
        attack_version="1.0",
        request_method="POST",
        request_url="https://api.target.com/chat",
        request_headers={"Authorization": "Bearer ***"},
        request_body='{"prompt": "test"}',
        response_status_code=200,
        response_headers={"content-type": "application/json"},
        response_body='{"response": "leaked"}',
        response_latency_ms=250,
        result=result,
        confidence=0.9,
        engine_version="1.0.0",
        duration_ms=300,
        worker_id="worker-1",
    )


class TestRecordEvidence:
    async def test_records_and_finalizes(self) -> None:
        repo = _repo()
        uc = RecordEvidenceUseCase(repo)
        result, events = await uc.execute(_command())
        assert result.result == "fail"
        assert result.is_finalized is True
        assert result.confidence == 0.9
        # EvidenceRecorded + EvidenceFinalized
        assert any(isinstance(e, EvidenceRecorded) for e in events)
        assert any(isinstance(e, EvidenceFinalized) for e in events)

    async def test_persists(self) -> None:
        repo = _repo()
        uc = RecordEvidenceUseCase(repo)
        result, _ = await uc.execute(_command())
        stored = await repo.get_by_id(EntityId.from_string(result.id))
        assert stored is not None
        assert stored.is_finalized is True

    async def test_pass_result(self) -> None:
        repo = _repo()
        uc = RecordEvidenceUseCase(repo)
        result, _ = await uc.execute(_command(result="pass"))
        assert result.result == "pass"

    async def test_invalid_result_raises(self) -> None:
        repo = _repo()
        uc = RecordEvidenceUseCase(repo)
        with pytest.raises(ValueError):
            await uc.execute(_command(result="invalid"))


class TestGetEvidence:
    async def test_gets(self) -> None:
        repo = _repo()
        record_uc = RecordEvidenceUseCase(repo)
        recorded, _ = await record_uc.execute(_command())

        uc = GetEvidenceUseCase(repo)
        result = await uc.execute(recorded.id)
        assert result.id == recorded.id
        assert result.test_case_id == "tc-001"

    async def test_not_found_raises(self) -> None:
        repo = _repo()
        uc = GetEvidenceUseCase(repo)
        with pytest.raises(EvidenceNotFoundError):
            await uc.execute(str(EntityId.generate()))


class TestListEvidenceByRun:
    async def test_lists_all(self) -> None:
        repo = _repo()
        record_uc = RecordEvidenceUseCase(repo)
        run_id = str(EntityId.generate())
        await record_uc.execute(_command(run_id=run_id, result="fail"))
        await record_uc.execute(_command(run_id=run_id, result="pass"))

        uc = ListEvidenceByRunUseCase(repo)
        results = await uc.execute(run_id)
        assert len(results) == 2

    async def test_filters_by_result(self) -> None:
        repo = _repo()
        record_uc = RecordEvidenceUseCase(repo)
        run_id = str(EntityId.generate())
        await record_uc.execute(_command(run_id=run_id, result="fail"))
        await record_uc.execute(_command(run_id=run_id, result="pass"))

        uc = ListEvidenceByRunUseCase(repo)
        results = await uc.execute(run_id, result_filter="fail")
        assert len(results) == 1
        assert results[0].result == "fail"

    async def test_empty_run(self) -> None:
        repo = _repo()
        uc = ListEvidenceByRunUseCase(repo)
        results = await uc.execute(str(EntityId.generate()))
        assert results == []
