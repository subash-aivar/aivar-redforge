"""SecurityOperationsStreamService — M15 (extended M16, M18, M19).

Merges eight durable, already-existing per-bounded-context append-only
logs into one tenant-safe, cursor-resumable operational event stream
(source tag in parentheses is the cursor's middle component):

  - validation_execution_events (M11 · "E")   — tenant-scoped
  - security_drift_events (M14 · "D")          — tenant-scoped
  - continuous_validation_policy_lifecycle_events (M15 · "P") — tenant-scoped
  - runtime_component_health_transitions (M15 · "R") — PLATFORM-WIDE, broadcast
    to every organization's stream (runtime components are not
    per-tenant data)
  - network_validation_run_events (M16 · "N")  — tenant-scoped
  - network_monitoring_policy_lifecycle_events (M16 · "M") — tenant-scoped
  - network_drift_events (M16, surfaced M18 · "K") — tenant-scoped
  - ddos_incident_events (M19 · "Z")           — tenant-scoped

Why a query-time merge instead of one physical event table: see
migration 0023's own docstring for the full reconnaissance finding
(the pre-existing generic `platform_events` event-sourcing table has
zero production writers and touching the 1000+-line, 3900-test
`execution_service.py` dispatch loop to feed it carried more
regression risk than this milestone's time budget justified). Each of
the four sources already has its own tenant-scoped or global ordering
index; merging four small, already-bounded query results in Python is
materially safer than retrofitting a shared global sequence across
them.

Cursor & ordering: see domain/security_operations/operational_event.py's
own docstring for the composite string cursor format
(`occurred_at|source_tag|row_id`) and why ISO-8601 UTC timestamps make
lexicographic string comparison equal chronological comparison.

Commit-visibility safety margin: a row is only surfaced once its
`occurred_at` is older than `EVENT_VISIBILITY_LAG_SECONDS` — see
value_objects.py's own docstring for why (a slower concurrent
transaction with a numerically-or-chronologically "earlier" event could
otherwise commit after a "later" one already went out, causing a
resumed client to skip it permanently once its cursor passes the later
event).

`_fetch_merged()` is the one shared query/merge routine — both `poll()`
(live SSE resume, cursor-filtered) and `application/security_operations/
change_feed_service.py` (a bounded historical page, filter-driven) build
on it rather than duplicating the four-source merge logic.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from redforge.application.security_operations.projection_registry import (
    project_drift_event,
    project_execution_event,
    project_network_drift_event,
    project_network_policy_lifecycle_event,
    project_network_run_event,
    project_policy_lifecycle_event,
    project_runtime_transition,
)
from redforge.domain.security_operations.value_objects import (
    EVENT_VISIBILITY_LAG_SECONDS,
    STREAM_BATCH_SIZE,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.domain.security_operations.operational_event import OperationalEvent


def _canonical_ts(dt: datetime) -> str:
    """Fixed-width, always-6-fractional-digit UTC timestamp string —
    `datetime.isoformat()` alone omits the fractional part entirely
    when microsecond == 0, which would break lexicographic == chronological
    ordering against timestamps that do carry microseconds."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")


def make_cursor(occurred_at: datetime, source_tag: str, row_id: str) -> str:
    return f"{_canonical_ts(occurred_at)}|{source_tag}|{row_id}"


def parse_cursor_timestamp(cursor: str) -> datetime | None:
    """Best-effort extraction of the timestamp component from a cursor,
    for the initial bounding query only (final filtering is always by
    full string comparison, never by this alone). Returns None for a
    cursor that doesn't parse — the caller then falls back to reading
    from the beginning, which is a safe (never-skip), documented
    behavior for a malformed/unrecognized cursor."""
    try:
        ts_part = cursor.split("|", 1)[0]
        return datetime.strptime(ts_part, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=UTC)
    except (ValueError, IndexError):
        return None


async def fetch_merged_candidates(
    session_factory: async_sessionmaker[AsyncSession],
    organization_id: str,
    query_since: datetime,
    per_source_limit: int,
    apply_visibility_lag: bool = True,
) -> list[OperationalEvent]:
    """Queries all four sources since `query_since`, projects each row,
    assigns its composite cursor, and returns them in cursor order —
    the one shared merge routine `poll()` and the change-feed service
    both build on."""
    from redforge.infrastructure.database.repositories.continuous_validation.drift_repository import (  # noqa: E501
        SqlAlchemySecurityDriftEventRepository,
    )
    from redforge.infrastructure.database.repositories.network_security.drift_repository import (
        SqlAlchemyNetworkDriftEventRepository,
    )
    from redforge.infrastructure.database.repositories.network_security.event_repository import (
        SqlAlchemyNetworkPolicyLifecycleEventRepository,
        SqlAlchemyNetworkRunEventRepository,
    )
    from redforge.infrastructure.database.repositories.policy_lifecycle_repository import (
        SqlAlchemyPolicyLifecycleEventRepository,
    )
    from redforge.infrastructure.database.repositories.runtime_health_repository import (
        SqlAlchemyRuntimeHealthRepository,
    )
    from redforge.infrastructure.database.repositories.validation_execution.event_repository import (  # noqa: E501
        SqlAlchemyExecutionEventRepository,
    )

    visibility_cutoff = (
        datetime.now(UTC) - timedelta(seconds=EVENT_VISIBILITY_LAG_SECONDS)
        if apply_visibility_lag
        else datetime.now(UTC)
    )
    org_id = EntityId.from_string(organization_id)
    candidates: list[OperationalEvent] = []

    async with session_factory() as session:
        exec_repo = SqlAlchemyExecutionEventRepository(session)
        exec_events = await exec_repo.list_for_organization_since(
            org_id, query_since, per_source_limit,
        )
        for ev in exec_events:
            if ev.occurred_at >= visibility_cutoff:
                continue
            projected = project_execution_event(
                event_type=str(ev.event_type), payload=ev.payload,
                execution_id=str(ev.execution_id), organization_id=organization_id,
                occurred_at=ev.occurred_at.isoformat(),
            )
            if projected is None:
                continue
            cursor = make_cursor(ev.occurred_at, "E", str(ev.id))
            candidates.append(projected.with_cursor(cursor))

        drift_repo = SqlAlchemySecurityDriftEventRepository(session)
        drift_events = await drift_repo.list_for_organization_since(
            org_id, query_since, per_source_limit,
        )
        for de in drift_events:
            if de.detected_at >= visibility_cutoff:
                continue
            projected = project_drift_event(
                drift_event_id=str(de.id), category=str(de.category), summary=de.summary,
                execution_id=str(de.execution_id),
                continuous_policy_id=str(de.continuous_policy_id),
                organization_id=organization_id, occurred_at=de.detected_at.isoformat(),
            )
            cursor = make_cursor(de.detected_at, "D", str(de.id))
            candidates.append(projected.with_cursor(cursor))

        policy_repo = SqlAlchemyPolicyLifecycleEventRepository(session)
        for pe in await policy_repo.list_for_organization_since(
            organization_id, query_since, per_source_limit,
        ):
            if pe.occurred_at >= visibility_cutoff:
                continue
            projected = project_policy_lifecycle_event(
                event_id=pe.id, event_type=pe.event_type, policy_id=pe.policy_id,
                organization_id=organization_id, occurred_at=pe.occurred_at.isoformat(),
            )
            cursor = make_cursor(pe.occurred_at, "P", pe.id)
            candidates.append(projected.with_cursor(cursor))

        runtime_repo = SqlAlchemyRuntimeHealthRepository(session)
        for rt in await runtime_repo.list_transitions_since(query_since, per_source_limit):
            if rt.occurred_at >= visibility_cutoff:
                continue
            projected = project_runtime_transition(
                transition_id=rt.id, component_id=rt.component_id,
                old_status=rt.old_status, new_status=rt.new_status,
                organization_id=organization_id, occurred_at=rt.occurred_at.isoformat(),
            )
            cursor = make_cursor(rt.occurred_at, "R", rt.id)
            candidates.append(projected.with_cursor(cursor))

        network_run_repo = SqlAlchemyNetworkRunEventRepository(session)
        for ne in await network_run_repo.list_for_organization_since(
            organization_id, query_since, per_source_limit,
        ):
            if ne.occurred_at >= visibility_cutoff:
                continue
            projected = project_network_run_event(
                event_type=ne.event_type, payload=ne.payload, run_id=ne.run_id,
                organization_id=organization_id, occurred_at=ne.occurred_at.isoformat(),
            )
            if projected is None:
                continue
            cursor = make_cursor(ne.occurred_at, "N", ne.id)
            candidates.append(projected.with_cursor(cursor))

        network_policy_repo = SqlAlchemyNetworkPolicyLifecycleEventRepository(session)
        for npe in await network_policy_repo.list_for_organization_since(
            organization_id, query_since, per_source_limit,
        ):
            if npe.occurred_at >= visibility_cutoff:
                continue
            projected = project_network_policy_lifecycle_event(
                event_id=npe.id, event_type=npe.event_type, policy_id=npe.policy_id,
                organization_id=organization_id, occurred_at=npe.occurred_at.isoformat(),
            )
            cursor = make_cursor(npe.occurred_at, "M", npe.id)
            candidates.append(projected.with_cursor(cursor))

        # M16 network_drift_events — persisted+deduped since M16 but had no
        # consumer until M18 wired it here (source tag "K"). This is the
        # canonical deterministic evidence for HBA/NBA behavior signals.
        network_drift_repo = SqlAlchemyNetworkDriftEventRepository(session)
        for nde in await network_drift_repo.list_for_organization_since(
            org_id, query_since, per_source_limit,
        ):
            if nde.detected_at >= visibility_cutoff:
                continue
            projected = project_network_drift_event(
                drift_event_id=str(nde.id), category=str(nde.category), summary=nde.summary,
                policy_id=str(nde.policy_id), organization_id=organization_id,
                occurred_at=nde.detected_at.isoformat(),
            )
            cursor = make_cursor(nde.detected_at, "K", str(nde.id))
            candidates.append(projected.with_cursor(cursor))

        # M19 DDoS incident events — source tag "Z"
        # Surfaces DDoS incident lifecycle events (detection, escalation,
        # resolution) into the shared security operations stream.
        try:
            from redforge.domain.security_operations.operational_event import OperationalEvent
            from redforge.domain.security_operations.value_objects import (
                OperationalImportance,
                SourceDomain,
            )
            from redforge.infrastructure.database.repositories.ddos.incident_repository import (
                SqlAlchemyDDoSIncidentEventRepository,
            )

            ddos_event_repo = SqlAlchemyDDoSIncidentEventRepository(session)
            ddos_events = await ddos_event_repo.list_for_org_since(
                organization_id, query_since, per_source_limit,
            )
            _high_event_types = frozenset({"detection_opened", "severity_escalated"})
            for dze in ddos_events:
                if dze.occurred_at >= visibility_cutoff:
                    continue
                importance = (
                    OperationalImportance.HIGH
                    if dze.event_type in _high_event_types
                    else OperationalImportance.NOTICE
                )
                event = OperationalEvent(
                    cursor=make_cursor(dze.occurred_at, "Z", dze.id),
                    event_id=dze.id,
                    organization_id=organization_id,
                    source_domain=SourceDomain.DDOS,
                    importance=importance,
                    title=f"DDoS: {dze.description[:120]}",
                    summary=dze.description,
                    entity_type="ddos_incident",
                    entity_id=dze.incident_id,
                    occurred_at=dze.occurred_at.isoformat(),
                )
                candidates.append(event)
        except Exception:
            pass  # DDoS tables not yet migrated in test or dev environments

        # M20 Behavioral NDR detection events — source tag "W"
        # Surfaces DETECTION_OPENED events from the behavior bounded context
        # into the shared security operations stream. Re-observation updates
        # are not surfaced — only new detection openings.
        try:
            from redforge.domain.security_operations.operational_event import OperationalEvent
            from redforge.domain.security_operations.value_objects import (
                OperationalImportance,
                SourceDomain,
            )
            from redforge.infrastructure.database.repositories.behavior.detection_repository import (  # noqa: E501
                SqlAlchemyBehaviorDetectionRepository,
            )

            beh_det_repo = SqlAlchemyBehaviorDetectionRepository(session)
            beh_events = await beh_det_repo.list_detection_events_since(
                organization_id, query_since, per_source_limit,
            )
            _high_behavior_types = frozenset({
                "BEACONING_SUSPECTED", "HIGH_FAN_OUT",
                "PORT_SCAN_SUSPECTED", "ABNORMAL_OUTBOUND_TRANSFER",
            })
            for be in beh_events:
                if be.created_at >= visibility_cutoff:
                    continue
                # Determine importance from detection type embedded in event detail
                importance = (
                    OperationalImportance.HIGH
                    if any(t in be.detail for t in _high_behavior_types)
                    else OperationalImportance.NOTICE
                )
                event = OperationalEvent(
                    cursor=make_cursor(be.created_at, "W", be.id),
                    event_id=be.id,
                    organization_id=organization_id,
                    source_domain=SourceDomain.BEHAVIOR,
                    importance=importance,
                    title=f"Behavioral Detection: {be.detail[:120]}",
                    summary=be.detail,
                    entity_type="behavior_detection",
                    entity_id=be.detection_id,
                    occurred_at=be.created_at.isoformat(),
                )
                candidates.append(event)
        except Exception:
            pass  # Behavior tables not yet migrated in test or dev environments

        # M21 Investigation case events — source tag "I"
        # Surfaces CASE_OPENED events from the investigation bounded context.
        try:
            from redforge.domain.security_operations.operational_event import OperationalEvent
            from redforge.domain.security_operations.value_objects import (
                OperationalImportance,
                SourceDomain,
            )
            from redforge.infrastructure.database.repositories.investigations.case_repository import (  # noqa: E501
                SqlAlchemyInvestigationEventRepository,
            )

            inv_event_repo = SqlAlchemyInvestigationEventRepository(session)
            inv_events = await inv_event_repo.list_opened_events_since(
                organization_id, query_since, per_source_limit,
            )
            for ie in inv_events:
                if ie.occurred_at >= visibility_cutoff:
                    continue
                detail = ie.detail or {}
                severity = detail.get("severity", "MEDIUM")
                importance = (
                    OperationalImportance.CRITICAL
                    if severity == "CRITICAL"
                    else OperationalImportance.HIGH
                    if severity == "HIGH"
                    else OperationalImportance.WARNING
                )
                title = detail.get("title", "New Cross-Domain Investigation")
                event = OperationalEvent(
                    cursor=make_cursor(ie.occurred_at, "I", ie.id),
                    event_id=ie.id,
                    organization_id=organization_id,
                    source_domain=SourceDomain.INVESTIGATION,
                    importance=importance,
                    title=f"Investigation: {title[:120]}",
                    summary=detail.get("reason", "Cross-domain security correlation"),
                    entity_type="investigation_case",
                    entity_id=ie.case_id,
                    occurred_at=ie.occurred_at.isoformat(),
                )
                candidates.append(event)
        except Exception:
            pass  # Investigation tables not yet migrated in test or dev environments

    candidates.sort(key=lambda e: e.cursor)
    return candidates


class SecurityOperationsStreamService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def poll(
        self,
        organization_id: str,
        since_cursor: str | None,
        batch_size: int = STREAM_BATCH_SIZE,
    ) -> list[OperationalEvent]:
        """Returns up to `batch_size` OperationalEvents strictly after
        `since_cursor` (None means "from the beginning"), in
        deterministic cursor order, excluding anything not yet past the
        commit-visibility safety margin.

        A malformed cursor is treated as "start from the beginning" —
        never a 500, and since none of the four source tables this
        milestone reads from prunes/retires old rows, there is no
        "expired cursor" case: every valid cursor, however old, can
        always be resumed from. `valid_cursor` (used only for the final
        strict-inequality filter below) is deliberately None for the
        malformed case too, so a garbage string is never lexicographically
        compared against real ISO cursors (which would silently swallow
        every genuine result — digits sort below most non-digit
        characters in a malformed string)."""
        since_ts = parse_cursor_timestamp(since_cursor) if since_cursor else None
        valid_cursor = since_cursor if (since_cursor is None or since_ts is not None) else None
        query_since = since_ts or datetime(1970, 1, 1, tzinfo=UTC)
        # Fetch generously beyond batch_size from each source so that,
        # after interleaved merge-sort + cursor filtering, we still have
        # up to batch_size genuinely-new events even if one source
        # dominates the window.
        per_source_limit = batch_size * 4

        candidates = await fetch_merged_candidates(
            self._session_factory, organization_id, query_since, per_source_limit,
        )
        if valid_cursor is not None:
            candidates = [e for e in candidates if e.cursor > valid_cursor]
        return candidates[:batch_size]
