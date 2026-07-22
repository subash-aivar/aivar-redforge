from __future__ import annotations

from datetime import UTC, datetime

from automated_action.domain.value_objects.refs import ExecutionEvidence


class ExecutionEvidenceService:
    def capture(self, execution_id: str, record_ids: list[str]) -> ExecutionEvidence:
        return ExecutionEvidence(execution_id, tuple(record_ids), datetime.now(UTC))
