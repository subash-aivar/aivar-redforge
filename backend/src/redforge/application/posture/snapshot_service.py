"""Creates ValidationSnapshots from completed ValidationServiceResults.

SnapshotService is the entry point into the posture bounded context.
It is called (post-commit, non-fatally) by ValidationService after a
successful run persists.

The caller is responsible for:
  1. Providing the ConfigurationFingerprint (model, provider, prompt hash, etc.)
  2. Wiring SnapshotRepositoryPort and BaselineRepositoryPort

After saving the snapshot, SnapshotService optionally triggers auto-baseline
establishment if BaselinePolicy.auto_establish is True and no active baseline
exists for the target.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from redforge.domain.posture.entity import ValidationBaseline, ValidationSnapshot
from redforge.domain.posture.value_objects import (
    BaselinePolicy,
    ConfigurationFingerprint,
    SnapshotMetrics,
)

if TYPE_CHECKING:
    from redforge.application.posture.contracts import (
        BaselineRepositoryPort,
        SnapshotRepositoryPort,
    )


@dataclass(frozen=True)
class SnapshotRequest:
    """Everything SnapshotService needs to create a snapshot.

    Callers build this from a ValidationServiceResult + the original request
    context (which carries model, provider, system prompt, etc.).
    """

    organization_id: str
    target_id: str
    run_id: str
    model: str
    provider: str
    system_prompt: str
    attack_categories: frozenset[str]
    total_attacks: int
    failed_attacks: int
    finding_count: int
    duration_ms: int
    tool_names: tuple[str, ...] = ()
    mcp_server_ids: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    critical_finding_count: int = 0
    high_finding_count: int = 0
    mean_confidence: float = 0.0
    metadata: dict[str, str] = field(default_factory=dict)


class SnapshotService:
    """Creates and persists ValidationSnapshots; optionally auto-establishes baselines.

    Usage:
        service = SnapshotService(snapshot_repo, baseline_repo)
        snapshot = await service.create_snapshot(request, policy)
    """

    def __init__(
        self,
        snapshot_repo: SnapshotRepositoryPort,
        baseline_repo: BaselineRepositoryPort,
    ) -> None:
        self._snapshots = snapshot_repo
        self._baselines = baseline_repo

    async def create_snapshot(
        self,
        request: SnapshotRequest,
        policy: BaselinePolicy | None = None,
    ) -> ValidationSnapshot:
        """Create, persist, and optionally auto-baseline a snapshot."""
        effective_policy = policy or BaselinePolicy()

        vulnerability_rate = (
            request.failed_attacks / request.total_attacks
            if request.total_attacks > 0
            else 0.0
        )
        metrics = SnapshotMetrics(
            vulnerability_rate=vulnerability_rate,
            total_attacks=request.total_attacks,
            finding_count=request.finding_count,
            duration_ms=request.duration_ms,
            pass_rate=1.0 - vulnerability_rate,
            critical_finding_count=request.critical_finding_count,
            high_finding_count=request.high_finding_count,
            mean_confidence=request.mean_confidence,
        )
        fingerprint = ConfigurationFingerprint(
            model=request.model,
            provider=request.provider,
            system_prompt_hash=_sha256_prefix(request.system_prompt),
            attack_categories=request.attack_categories,
            tool_names=request.tool_names,
            mcp_server_ids=request.mcp_server_ids,
            capabilities=request.capabilities,
        )

        snapshot, _events = ValidationSnapshot.create(
            organization_id=request.organization_id,
            target_id=request.target_id,
            run_id=request.run_id,
            metrics=metrics,
            fingerprint=fingerprint,
        )
        await self._snapshots.save(snapshot)

        if effective_policy.auto_establish:
            await self._maybe_establish_baseline(snapshot, effective_policy)

        return snapshot

    async def _maybe_establish_baseline(
        self,
        snapshot: ValidationSnapshot,
        policy: BaselinePolicy,
    ) -> None:
        if snapshot.metrics.total_attacks < policy.require_minimum_attacks:
            return

        existing = await self._baselines.get_active(
            snapshot.organization_id,
            snapshot.target_id,
        )
        if existing is not None:
            return

        baseline, _events = ValidationBaseline.establish(
            organization_id=snapshot.organization_id,
            target_id=snapshot.target_id,
            snapshot=snapshot,
            policy=policy,
            auto_established=True,
        )
        await self._baselines.save(baseline)


def _sha256_prefix(text: str, length: int = 16) -> str:
    """Return the first `length` hex chars of the SHA-256 of text."""
    return hashlib.sha256(text.encode()).hexdigest()[:length]
