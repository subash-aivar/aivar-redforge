"""PlaybookTestResult — append-only dry-run outcome."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from playbook.domain.value_objects.enums import TestOutcome
from playbook.domain.value_objects.identifiers import (
    PlaybookId,
    PlaybookTestResultId,
    PlaybookVersionId,
    TenantId,
)


@dataclass
class PlaybookTestResult:
    test_id: PlaybookTestResultId
    tenant_id: TenantId
    playbook_id: PlaybookId
    version_id: PlaybookVersionId
    content_hash_at_test: str
    outcome: TestOutcome
    steps_tested: int
    steps_passed: int
    coverage_paths: list[str]
    executed_by: str
    executed_at: datetime
    duration_ms: int

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        playbook_id: PlaybookId,
        version_id: PlaybookVersionId,
        content_hash_at_test: str,
        outcome: TestOutcome,
        steps_tested: int,
        steps_passed: int,
        coverage_paths: list[str],
        executed_by: str,
        executed_at: datetime,
        duration_ms: int,
    ) -> PlaybookTestResult:
        return cls(
            PlaybookTestResultId.generate(),
            tenant_id,
            playbook_id,
            version_id,
            content_hash_at_test,
            outcome,
            steps_tested,
            steps_passed,
            coverage_paths,
            executed_by,
            executed_at,
            duration_ms,
        )
