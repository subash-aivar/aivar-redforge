"""Manages ValidationBaseline lifecycle: create, compare, promote, expire.

BaselineService coordinates:
  - Manual baseline promotion (promote a specific snapshot to baseline)
  - Baseline supersession (replacing an active baseline with a newer one)
  - Age-based expiry
  - Regression / improvement comparison against the active baseline
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.application.posture.regression_analyzer import RegressionAnalyzer
from redforge.domain.posture.entity import ValidationBaseline
from redforge.domain.posture.exceptions import BaselineNotFoundError
from redforge.domain.posture.value_objects import BaselinePolicy, ValidationRegressionDetail

if TYPE_CHECKING:
    from redforge.application.posture.contracts import (
        BaselineRepositoryPort,
        SnapshotRepositoryPort,
    )
    from redforge.domain.posture.entity import ValidationSnapshot


class BaselineService:
    """Manages ValidationBaseline lifecycle.

    Usage:
        service = BaselineService(baseline_repo, snapshot_repo)
        await service.promote(org_id, target_id, snapshot_id, policy)
    """

    def __init__(
        self,
        baseline_repo: BaselineRepositoryPort,
        snapshot_repo: SnapshotRepositoryPort,
        analyzer: RegressionAnalyzer | None = None,
    ) -> None:
        self._baselines = baseline_repo
        self._snapshots = snapshot_repo
        self._analyzer = analyzer or RegressionAnalyzer()

    async def promote(
        self,
        organization_id: str,
        target_id: str,
        snapshot_id: str,
        policy: BaselinePolicy | None = None,
    ) -> ValidationBaseline:
        """Promote a snapshot to be the active baseline.

        If an active baseline already exists, it is superseded first.
        """
        effective_policy = policy or BaselinePolicy()

        snapshot = await self._snapshots.get_by_id(snapshot_id)
        if snapshot is None:
            from redforge.domain.posture.exceptions import SnapshotNotFoundError

            raise SnapshotNotFoundError(snapshot_id)

        existing = await self._baselines.get_active(organization_id, target_id)
        new_baseline, _events = ValidationBaseline.establish(
            organization_id=organization_id,
            target_id=target_id,
            snapshot=snapshot,
            policy=effective_policy,
            auto_established=False,
        )

        if existing is not None:
            existing.supersede(new_baseline.id)
            await self._baselines.save(existing)

        await self._baselines.save(new_baseline)
        return new_baseline

    async def compare_to_baseline(
        self,
        organization_id: str,
        target_id: str,
        current_snapshot: ValidationSnapshot,
    ) -> ValidationRegressionDetail | None:
        """Compare a snapshot to the active baseline for this target.

        Returns None if no active baseline exists (no comparison possible).
        """
        baseline = await self._baselines.get_active(organization_id, target_id)
        if baseline is None:
            return None
        return self._analyzer.analyze(current_snapshot, baseline)

    async def expire_stale_baselines(self, organization_id: str) -> int:
        """Expire all age-exceeded baselines for an organization.

        Returns the count of baselines expired.
        """
        baselines = await self._baselines.list_for_org(organization_id)
        count = 0
        for baseline in baselines:
            if baseline.is_active() and baseline.is_expired_by_age():
                baseline.expire()
                await self._baselines.save(baseline)
                count += 1
        return count

    async def get_active_baseline(
        self,
        organization_id: str,
        target_id: str,
    ) -> ValidationBaseline:
        """Return the active baseline or raise BaselineNotFoundError."""
        baseline = await self._baselines.get_active(organization_id, target_id)
        if baseline is None:
            raise BaselineNotFoundError(organization_id, target_id)
        return baseline
