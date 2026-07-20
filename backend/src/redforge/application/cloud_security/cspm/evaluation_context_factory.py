"""Factory for EvaluationContext value objects."""

from __future__ import annotations

from datetime import UTC, datetime

from redforge.domain.cloud_security.cspm.value_objects import EvaluationContext


class EvaluationContextFactory:
    def build(
        self,
        *,
        organization_id: str,
        evaluation_id: str,
        triggered_by: str,
        cloud_account_id: str | None = None,
        incremental: bool = False,
        policy_ids: tuple[str, ...] = (),
        now: datetime | None = None,
    ) -> EvaluationContext:
        return EvaluationContext(
            organization_id=organization_id,
            cloud_account_id=cloud_account_id,
            evaluation_id=evaluation_id,
            triggered_by=triggered_by,
            incremental=incremental,
            policy_ids=policy_ids,
            started_at=now or datetime.now(UTC),
        )
