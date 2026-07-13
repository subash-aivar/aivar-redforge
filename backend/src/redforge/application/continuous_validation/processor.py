"""ContinuousValidationProcessor — M14.

The canonical orchestrator: claim -> authorize -> execute -> snapshot ->
reconcile -> drift -> advance -> release. Reuses
`ValidationExecutionService.create_and_run()` unchanged for the actual
validation run (M10's fresh-per-call authorization gate is inherited
automatically — this processor never re-implements or bypasses it).
No new execution engine, no new correlation engine: M9 correlation
re-evaluation already happens inside `create_and_run()` itself; this
processor's own added work is condition/drift reconciliation only.

CONDITION_REACTIVATED detection: a newly-active condition identity key
is classified as a reactivation (rather than a fresh appearance) only
when its OWN `first_observed_at` predates the previous snapshot's own
`captured_at` — i.e. the row already existed, and therefore must have
been resolved as of the previous comparison (since it was not in that
snapshot's active set), and is active again now. This is derived
entirely from data already on hand — no extra peek-before-ingest
plumbing needed.

Failure semantics per stage:
  - Claim fails (nothing due) -> return None, no side effects.
  - `create_and_run()` raises `IntegrityError` (the partial-unique-index
    backstop on (continuous_policy_id, scheduled_due_at) fired — a
    genuine concurrent double-claim slipped past the SKIP LOCKED claim)
    -> someone else already produced this due boundary's canonical
    execution, so the schedule is advanced normally past it.
  - `create_and_run()` raises any OTHER exception (DB blip, bug, etc.)
    -> the claim is released WITHOUT advancing next_due_at, so the SAME
    due boundary is retried on the next poll cycle rather than being
    silently skipped for a full cadence period. In both cases the
    exception propagates to the caller (the scheduler worker), which
    logs and continues its poll loop rather than crashing.
  - Every post-run mutation (advance/release) re-reads the CURRENT
    policy row under a row lock rather than blindly saving the
    possibly-stale in-memory object captured at claim time, and never
    touches a policy that has since been DISABLED — see
    `_mutate_under_lock()`'s own docstring for the TOCTOU this closes.
  - Reconciliation/drift persistence failures never roll back the
    already-committed ValidationExecution — the run itself is the
    source of truth; reconciliation is best-effort cleanup layered on
    top, exactly like M8/M9's own condition/correlation ingestion is
    already best-effort relative to the execution it derives from.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy.exc import IntegrityError

from redforge.application.continuous_validation.condition_reconciliation import (
    compute_covered_ports_by_rule,
    compute_covered_rule_ids,
)
from redforge.application.continuous_validation.drift_detector import detect_drift
from redforge.application.continuous_validation.snapshot_builder import (
    build_snapshot_from_execution,
)
from redforge.domain.validation_execution.value_objects import ExecutionTrigger
from redforge.infrastructure.database.repositories.continuous_validation import (
    snapshot_repository as _snapshot_repo_module,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.ai_targets import AITargetService
    from redforge.application.continuous_validation.drift_service import SecurityDriftService
    from redforge.application.inventory.tenant_asset_service import TenantAssetService
    from redforge.application.security_conditions.service import (
        SecurityConditionDTO,
        TenantSecurityConditionService,
    )
    from redforge.application.security_correlation.service import (
        TenantSecurityCorrelationService,
    )
    from redforge.application.validation_execution.execution_service import (
        ValidationExecutionDTO,
        ValidationExecutionService,
    )
    from redforge.domain.continuous_validation.entity import ContinuousValidationPolicy


class ContinuousValidationProcessor:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        execution_service: ValidationExecutionService,
        ai_target_service: AITargetService,
        tenant_asset_service: TenantAssetService,
        condition_service: TenantSecurityConditionService,
        correlation_service: TenantSecurityCorrelationService,
        drift_service: SecurityDriftService,
    ) -> None:
        self._session_factory = session_factory
        self._execution_service = execution_service
        self._ai_target_service = ai_target_service
        self._tenant_asset_service = tenant_asset_service
        self._condition_service = condition_service
        self._correlation_service = correlation_service
        self._drift_service = drift_service

    async def process_one_due_policy(self, worker_id: str) -> ValidationExecutionDTO | None:
        """Claim and process exactly one due policy. Returns None when
        nothing is currently due (never an error — an empty poll cycle
        is the normal, expected steady state)."""
        from redforge.infrastructure.database.repositories.continuous_validation.repository import (
            SqlAlchemyContinuousValidationPolicyRepository,
        )

        now = utc_now()
        async with self._session_factory() as session:
            policy_repo = SqlAlchemyContinuousValidationPolicyRepository(session)
            policy = await policy_repo.claim_one_due_policy(now, worker_id)
            await session.commit()

        if policy is None:
            return None

        try:
            execution = await self._execution_service.create_and_run(
                organization_id=str(policy.organization_id),
                target_id=str(policy.target_id),
                requester_user_id=str(policy.requester_user_id),
                profile=str(policy.profile),
                trigger=ExecutionTrigger.SCHEDULED,
                continuous_policy_id=str(policy.id),
                scheduled_due_at=policy.next_due_at,
            )
        except IntegrityError:
            # The partial-unique-index backstop on (continuous_policy_id,
            # scheduled_due_at) fired — a genuine concurrent double-claim
            # slipped past the SKIP LOCKED claim. Someone else already
            # produced this due boundary's canonical execution, so it is
            # safe (and correct) to advance past it normally.
            await self._release_and_advance(policy, now)
            raise
        except Exception:
            # Any OTHER unexpected failure (DB blip, bug, etc.) — never
            # silently skip this due boundary for a full cadence period.
            # Release the claim without advancing next_due_at, so the
            # SAME boundary is retried on the next poll cycle instead.
            await self._release_claim_only(policy)
            raise

        await self._reconcile(policy, execution)
        await self._release_and_advance(policy, now)
        return execution

    async def run_now(self, organization_id: str, policy_id: str) -> ValidationExecutionDTO:
        """Operator-triggered ON_DEMAND run against an existing policy —
        goes through the identical execute -> snapshot -> reconcile ->
        drift pipeline, but is NOT tied to a due boundary (no claim, no
        next_due_at advancement) — see ExecutionTrigger.ON_DEMAND's own
        docstring."""
        from redforge.domain.continuous_validation.exceptions import (
            ContinuousValidationPolicyNotFoundError,
            PolicyDisabledForExecutionError,
        )
        from redforge.domain.continuous_validation.value_objects import PolicyLifecycle
        from redforge.infrastructure.database.repositories.continuous_validation.repository import (
            SqlAlchemyContinuousValidationPolicyRepository,
        )

        try:
            safe_policy_id = EntityId.from_string(policy_id)
            safe_org_id = EntityId.from_string(organization_id)
        except ValueError as exc:
            raise ContinuousValidationPolicyNotFoundError(policy_id) from exc

        async with self._session_factory() as session:
            policy_repo = SqlAlchemyContinuousValidationPolicyRepository(session)
            policy = await policy_repo.get_by_id_for_organization(safe_policy_id, safe_org_id)
        if policy is None:
            raise ContinuousValidationPolicyNotFoundError(policy_id)
        if policy.lifecycle == PolicyLifecycle.DISABLED:
            raise PolicyDisabledForExecutionError(policy_id)

        execution = await self._execution_service.create_and_run(
            organization_id=str(policy.organization_id),
            target_id=str(policy.target_id),
            requester_user_id=str(policy.requester_user_id),
            profile=str(policy.profile),
            trigger=ExecutionTrigger.ON_DEMAND,
            continuous_policy_id=str(policy.id),
            scheduled_due_at=None,
        )
        await self._reconcile(policy, execution)
        return execution

    # ─── Private ──────────────────────────────────────────────────────────

    async def _release_and_advance(
        self, policy: ContinuousValidationPolicy, now: datetime,
    ) -> None:
        """Advances the schedule and releases the claim. Always re-reads
        the CURRENT row under a row lock rather than blindly saving the
        stale in-memory `policy` captured at claim time — an operator's
        disable()/pause() call may have committed while the (possibly
        long-running) validation run was in flight, and save()'s own
        blind field-copy has no optimistic-concurrency check. A
        DISABLED policy is never touched further here: DISABLED is
        terminal (see PolicyLifecycle's own docstring) and must never
        be silently resurrected to ACTIVE by this post-run step."""
        def _advance_and_release(fresh: ContinuousValidationPolicy) -> None:
            fresh.advance_schedule(now)
            fresh.release_claim()

        await self._mutate_under_lock(policy, _advance_and_release)

    async def _release_claim_only(self, policy: ContinuousValidationPolicy) -> None:
        """Used when `create_and_run()` raised an unexpected (non-claim-
        collision) exception — releases the claim WITHOUT advancing
        next_due_at, so the same due boundary is retried on the next
        poll cycle instead of being silently skipped for a full cadence
        period."""
        await self._mutate_under_lock(policy, lambda fresh: fresh.release_claim())

    async def _mutate_under_lock(
        self,
        policy: ContinuousValidationPolicy,
        mutate: Callable[[ContinuousValidationPolicy], None],
    ) -> None:
        """Row-locks the CURRENT policy row (via
        get_by_id_for_organization_for_update()), applies `mutate` to
        the freshly-read entity, and saves it — never the stale
        `policy` object passed in. This is what closes the TOCTOU
        between a long-running scheduled validation run and a
        concurrent operator lifecycle action: the operator's own
        `_transition()` uses the identical row-locked read, so the two
        genuinely serialize on the same database row rather than one
        blindly clobbering the other's committed write. A row that has
        already become DISABLED is skipped entirely — never mutated,
        matching DISABLED's terminal invariant."""
        from redforge.domain.continuous_validation.value_objects import PolicyLifecycle
        from redforge.infrastructure.database.repositories.continuous_validation.repository import (
            SqlAlchemyContinuousValidationPolicyRepository,
        )

        async with self._session_factory() as session:
            policy_repo = SqlAlchemyContinuousValidationPolicyRepository(session)
            fresh = await policy_repo.get_by_id_for_organization_for_update(
                policy.id, policy.organization_id,
            )
            if fresh is None or fresh.lifecycle == PolicyLifecycle.DISABLED:
                await session.commit()
                return
            mutate(fresh)
            await policy_repo.save(fresh)
            await session.commit()

    async def _related_asset_ids(self, policy: ContinuousValidationPolicy) -> set[str]:
        target = await self._ai_target_service.get_by_id(
            str(policy.target_id), str(policy.organization_id),
        )
        host = await self._tenant_asset_service.get_or_create_for_target(
            str(policy.organization_id), str(policy.target_id),
            target.name, target.target_type,
        )
        relationships = await self._tenant_asset_service.get_relationships_for_org(
            host.id, str(policy.organization_id),
        )
        return {host.id} | {r["target_asset_id"] for r in relationships}

    async def _list_active_conditions_by_asset(
        self, policy: ContinuousValidationPolicy, related_asset_ids: set[str],
    ) -> dict[str, list[SecurityConditionDTO]]:
        result: dict[str, list[SecurityConditionDTO]] = {}
        for asset_id in related_asset_ids:
            result[asset_id] = await self._condition_service.list_active_for_asset(
                str(policy.organization_id), asset_id,
            )
        return result

    async def _asset_ports(
        self, policy: ContinuousValidationPolicy, related_asset_ids: set[str],
    ) -> dict[str, int | None]:
        """Each SERVICE asset's own port, read back from the metadata
        `TenantAssetService.update_metadata_for_org()` stamps on it
        (`{"port": "<n>", ...}` — see execution_service.py's own
        canonical enrichment). None for the HOST asset (no port) or any
        asset created before M12's own port-metadata convention
        existed."""
        ports: dict[str, int | None] = {}
        for asset_id in related_asset_ids:
            asset = await self._tenant_asset_service.get_for_org(
                asset_id, str(policy.organization_id),
            )
            raw_port = asset.metadata.get("port")
            ports[asset_id] = int(raw_port) if raw_port and raw_port.isdigit() else None
        return ports

    async def _target_port(self, policy: ContinuousValidationPolicy) -> int:
        from redforge.application.validation_execution.target_normalizer import normalize_target

        target = await self._ai_target_service.get_by_id(
            str(policy.target_id), str(policy.organization_id),
        )
        try:
            return normalize_target(target.endpoint).port
        except Exception:
            return 443 if target.endpoint.startswith("https") else 80

    async def _reconcile(
        self, policy: ContinuousValidationPolicy, execution: ValidationExecutionDTO,
    ) -> None:
        """Best-effort: snapshot -> condition reconciliation -> drift.
        A failure here never invalidates the already-committed
        ValidationExecution."""
        org_id = EntityId.from_string(str(policy.organization_id))
        related_asset_ids = await self._related_asset_ids(policy)
        target_port = await self._target_port(policy)

        # Fetched BEFORE resolution — this is the candidate set
        # `_resolve_absent_conditions` reasons about (which of these
        # were freshly re-observed THIS run vs. now provably absent).
        conditions_before = await self._list_active_conditions_by_asset(
            policy, related_asset_ids,
        )
        asset_ports = await self._asset_ports(policy, related_asset_ids)
        await self._resolve_absent_conditions(policy, execution, conditions_before, asset_ports)

        # Re-fetched AFTER resolution — the truly current active state,
        # used for both the snapshot's active_condition_keys and the
        # reactivation first_observed_at lookup. Using the pre-
        # resolution set here would incorrectly still count a
        # just-resolved condition as "active" in this run's own
        # snapshot.
        conditions_after = await self._list_active_conditions_by_asset(
            policy, related_asset_ids,
        )
        active_condition_keys = [
            c.identity_key
            for conditions in conditions_after.values()
            for c in conditions
            if c.identity_key
        ]

        active_correlation_keys: list[str] = []
        if related_asset_ids:
            active_correlations = await self._correlation_service.list_for_org(
                str(policy.organization_id), lifecycle="active", limit=500,
            )
            active_correlation_keys = [
                corr.identity_key for corr in active_correlations
                if corr.identity_key and set(corr.entity_ids) & related_asset_ids
            ]

        current_snapshot = build_snapshot_from_execution(
            execution, org_id, policy.id, target_port,
            active_condition_keys, active_correlation_keys,
        )

        async with self._session_factory() as session:
            snapshot_repo = _snapshot_repo_module.SqlAlchemyValidationStateSnapshotRepository(
                session,
            )
            previous_snapshot = await snapshot_repo.get_latest_for_policy(policy.id, org_id)
            await snapshot_repo.save(current_snapshot)
            await session.commit()

        reactivated_keys = _compute_reactivated_keys(
            previous_snapshot, current_snapshot, conditions_after,
        )
        drift_events = detect_drift(
            previous_snapshot, current_snapshot, org_id, policy.id,
            EntityId.from_string(execution.id), reactivated_keys,
        )
        await self._drift_service.persist(drift_events)

    async def _resolve_absent_conditions(
        self,
        policy: ContinuousValidationPolicy,
        execution: ValidationExecutionDTO,
        conditions_by_asset: dict[str, list[SecurityConditionDTO]],
        asset_ports: dict[str, int | None],
    ) -> None:
        covered_rule_ids = compute_covered_rule_ids(execution)
        if not covered_rule_ids:
            return
        covered_ports_by_rule = compute_covered_ports_by_rule(execution)
        started_at = _parse_iso_utc(execution.started_at or execution.created_at)

        for asset_id, conditions in conditions_by_asset.items():
            by_rule: dict[str, list[SecurityConditionDTO]] = {}
            for c in conditions:
                by_rule.setdefault(c.stable_rule_id, []).append(c)
            for rule_id in covered_rule_ids & set(by_rule.keys()):
                # Port-scoped rules (see condition_reconciliation.py's own
                # docstring): a covering step somewhere in the execution
                # is NOT enough — this SPECIFIC asset's own port must be
                # among the ports that step actually re-checked this run.
                covered_ports = covered_ports_by_rule.get(rule_id)
                if covered_ports is not None:
                    asset_port = asset_ports.get(asset_id)
                    if asset_port is None or asset_port not in covered_ports:
                        continue
                still_active = {
                    c.identity_key for c in by_rule[rule_id]
                    if _parse_iso_utc(c.last_observed_at) >= started_at
                }
                await self._condition_service.resolve_stale_for_rule_and_asset(
                    str(policy.organization_id), rule_id, asset_id, still_active,
                )


def _compute_reactivated_keys(
    previous_snapshot: object | None,
    current_snapshot: object,
    conditions_by_asset: dict[str, list[SecurityConditionDTO]],
) -> frozenset[str]:
    if previous_snapshot is None:
        return frozenset()

    previous_active = set(previous_snapshot.active_condition_keys)  # type: ignore[attr-defined]
    current_active = set(current_snapshot.active_condition_keys)  # type: ignore[attr-defined]
    newly_active = current_active - previous_active
    if not newly_active:
        return frozenset()

    first_observed_by_key = {
        c.identity_key: c.first_observed_at
        for conditions in conditions_by_asset.values()
        for c in conditions
    }
    previous_captured_at = _ensure_utc(previous_snapshot.captured_at)  # type: ignore[attr-defined]

    reactivated = set()
    for key in newly_active:
        first_observed = first_observed_by_key.get(key)
        if first_observed and _parse_iso_utc(first_observed) < previous_captured_at:
            reactivated.add(key)
    return frozenset(reactivated)


def _parse_iso_utc(value: str) -> datetime:
    """Parses an ISO-8601 timestamp string, defaulting to UTC when the
    string itself carries no offset. SQLite (used by unit/isolation
    tests) does not reliably round-trip timezone-aware DateTime columns
    the way PostgreSQL does — a value written as UTC-aware can come back
    naive, producing a string with no "+00:00" suffix. Every timestamp
    in this bounded context is UTC by convention (see
    shared.timestamps.utc_now()), so defaulting a naive parse to UTC is
    always correct here, never a guess."""
    return _ensure_utc(datetime.fromisoformat(value))


def _ensure_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
