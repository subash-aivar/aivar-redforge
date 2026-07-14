"""Deterministic behavior analytics — UEBA / HBA / NBA — M18.

Every signal here is a DETERMINISTIC rule evaluation over real persisted
rows, never ML or an opaque risk score:

  - UEBA: over the organization admin audit log (M17,
    organization_admin_audit_log) — per-actor administrative action
    volume and privilege-change activity within a bounded window.
  - HBA: over M16 network_drift_events — host/service appear/disappear
    categories (a host gaining or losing a reachable service).
  - NBA: over M16 network_drift_events — service-identity / protocol /
    TLS change categories (how a service's network identity changed).

Every emitted signal carries the exact source rows (evidence) that
produced it. If a signal has no backing rows, it is not emitted — there
is no path to a fabricated signal. Thresholds are fixed, documented
module constants; severities come from a fixed table, never inferred.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from redforge.domain.command_center.value_objects import BehaviorDomain, BehaviorSeverity
from redforge.domain.security_operations.value_objects import (
    BoundedPeriod,
    bounded_period_seconds,
)
from redforge.infrastructure.audit.organization_admin_audit_log import (
    PostgresOrganizationAdminAuditLog,
)
from redforge.infrastructure.database.repositories.network_security.drift_repository import (
    SqlAlchemyNetworkDriftEventRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.domain.network_security.entity import NetworkDriftEvent
    from redforge.infrastructure.audit.organization_admin_audit_log import (
        OrganizationAdminAuditEntry,
    )

# ── Fixed, documented thresholds ───────────────────────────────────────────
# Per-actor administrative action count within the window at/above which
# an "elevated_admin_action_volume" signal is raised (HIGH at the higher
# band). These are deliberately simple, deterministic counts — not a
# learned baseline.
_ADMIN_VOLUME_WARNING = 10
_ADMIN_VOLUME_HIGH = 25
# Total privilege-change actions in the window at/above which an
# "elevated_privilege_change_activity" signal is raised.
_PRIVILEGE_CHANGE_THRESHOLD = 5
# How many rows to scan (bounded) and how much evidence to attach.
_AUDIT_SCAN_LIMIT = 1000
_MAX_EVIDENCE = 20
_DRIFT_SCAN_LIMIT = 1000

# Actions that constitute a privilege/access change (a deterministic set).
_PRIVILEGE_CHANGE_ACTIONS = frozenset(
    {
        "rbac.role_created", "rbac.role_updated", "rbac.role_deleted",
        "rbac.role_permissions_changed", "rbac.group_created", "rbac.group_updated",
        "rbac.group_deleted", "rbac.group_member_added", "rbac.group_member_removed",
        "rbac.group_role_assigned", "rbac.group_role_revoked", "rbac.user_role_assigned",
        "rbac.user_role_revoked", "membership.role_changed", "membership.suspended",
        "membership.removed", "membership.ownership_transferred",
    }
)

# network_drift categories → (signal_type, severity, label)
_HBA_CATEGORIES: dict[str, tuple[str, BehaviorSeverity, str]] = {
    "ip_observed": ("new_host_observed", BehaviorSeverity.NOTICE, "New IP address(es) observed"),
    "ip_no_longer_observed": (
        "host_disappeared", BehaviorSeverity.WARNING, "IP address(es) no longer observed",
    ),
    "port_became_reachable": (
        "service_appeared", BehaviorSeverity.WARNING, "Port(s) became reachable",
    ),
    "port_no_longer_reachable": (
        "service_disappeared", BehaviorSeverity.NOTICE, "Port(s) no longer reachable",
    ),
}
_NBA_CATEGORIES: dict[str, tuple[str, BehaviorSeverity, str]] = {
    "protocol_validated": (
        "protocol_identified", BehaviorSeverity.INFO, "Protocol(s) newly validated",
    ),
    "protocol_no_longer_validated": (
        "protocol_lost", BehaviorSeverity.WARNING, "Protocol(s) no longer validated",
    ),
    "protocol_changed": (
        "protocol_changed", BehaviorSeverity.WARNING, "Service protocol identity changed",
    ),
    "tls_certificate_changed": (
        "tls_certificate_changed", BehaviorSeverity.WARNING, "TLS certificate changed",
    ),
}


@dataclass(frozen=True, slots=True)
class BehaviorEvidence:
    source: str
    source_id: str
    occurred_at: str
    detail: str


@dataclass(frozen=True, slots=True)
class BehaviorSignal:
    domain: str
    signal_type: str
    severity: str
    subject: str
    summary: str
    observed_window: str
    evidence_count: int
    evidence: list[BehaviorEvidence]


class BehaviorAnalyticsService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def signals(
        self, organization_id: str, period: BoundedPeriod, domain: BehaviorDomain | None,
    ) -> list[BehaviorSignal]:
        window_start = utc_now() - timedelta(seconds=bounded_period_seconds(period))
        out: list[BehaviorSignal] = []
        if domain in (None, BehaviorDomain.USER):
            out.extend(await self._ueba(organization_id, period, window_start))
        if domain in (None, BehaviorDomain.HOST):
            out.extend(await self._drift_signals(
                organization_id, period, window_start, BehaviorDomain.HOST, _HBA_CATEGORIES,
            ))
        if domain in (None, BehaviorDomain.NETWORK):
            out.extend(await self._drift_signals(
                organization_id, period, window_start, BehaviorDomain.NETWORK, _NBA_CATEGORIES,
            ))
        return out

    async def _ueba(
        self, organization_id: str, period: BoundedPeriod, window_start: datetime,
    ) -> list[BehaviorSignal]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            audit = PostgresOrganizationAdminAuditLog(uow.session)
            entries = await audit.query_for_organization(
                organization_id, limit=_AUDIT_SCAN_LIMIT, offset=0,
            )
        in_window = [e for e in entries if e.occurred_at >= window_start]
        signals: list[BehaviorSignal] = []

        # Rule 1 — per-actor administrative action volume.
        by_actor: dict[str, list[OrganizationAdminAuditEntry]] = {}
        for e in in_window:
            by_actor.setdefault(e.actor_id, []).append(e)
        for actor_id, actor_entries in sorted(by_actor.items()):
            count = len(actor_entries)
            if count < _ADMIN_VOLUME_WARNING:
                continue
            severity = (
                BehaviorSeverity.HIGH if count >= _ADMIN_VOLUME_HIGH else BehaviorSeverity.WARNING
            )
            signals.append(
                BehaviorSignal(
                    domain=BehaviorDomain.USER.value,
                    signal_type="elevated_admin_action_volume",
                    severity=severity.value,
                    subject=actor_id,
                    summary=(
                        f"Actor performed {count} administrative actions in the "
                        f"{period.value} window."
                    ),
                    observed_window=period.value,
                    evidence_count=count,
                    evidence=[
                        BehaviorEvidence(
                            source="organization_admin_audit_log", source_id=e.target_id,
                            occurred_at=e.occurred_at.isoformat(),
                            detail=f"{e.action} on {e.target_type}",
                        )
                        for e in actor_entries[:_MAX_EVIDENCE]
                    ],
                )
            )

        # Rule 2 — elevated privilege-change activity (org-wide in window).
        priv = [e for e in in_window if e.action in _PRIVILEGE_CHANGE_ACTIONS]
        if len(priv) >= _PRIVILEGE_CHANGE_THRESHOLD:
            signals.append(
                BehaviorSignal(
                    domain=BehaviorDomain.USER.value,
                    signal_type="elevated_privilege_change_activity",
                    severity=BehaviorSeverity.WARNING.value,
                    subject=organization_id,
                    summary=(
                        f"{len(priv)} privilege/access-change actions in the "
                        f"{period.value} window."
                    ),
                    observed_window=period.value,
                    evidence_count=len(priv),
                    evidence=[
                        BehaviorEvidence(
                            source="organization_admin_audit_log", source_id=e.target_id,
                            occurred_at=e.occurred_at.isoformat(),
                            detail=f"{e.action} by {e.actor_id}",
                        )
                        for e in priv[:_MAX_EVIDENCE]
                    ],
                )
            )
        return signals

    async def _drift_signals(
        self,
        organization_id: str,
        period: BoundedPeriod,
        window_start: datetime,
        domain: BehaviorDomain,
        category_map: dict[str, tuple[str, BehaviorSeverity, str]],
    ) -> list[BehaviorSignal]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyNetworkDriftEventRepository(uow.session)
            events = await repo.list_for_organization_since(
                EntityId.from_string(organization_id), window_start, _DRIFT_SCAN_LIMIT,
            )
        by_category: dict[str, list[NetworkDriftEvent]] = {}
        for e in events:
            category = str(e.category)
            if category in category_map:
                by_category.setdefault(category, []).append(e)
        signals: list[BehaviorSignal] = []
        for category in sorted(by_category):
            rows = by_category[category]
            signal_type, severity, label = category_map[category]
            signals.append(
                BehaviorSignal(
                    domain=domain.value,
                    signal_type=signal_type,
                    severity=severity.value,
                    subject=category,
                    summary=f"{label}: {len(rows)} event(s) in the {period.value} window.",
                    observed_window=period.value,
                    evidence_count=len(rows),
                    evidence=[
                        BehaviorEvidence(
                            source="network_drift_events", source_id=str(e.id),
                            occurred_at=e.detected_at.isoformat(),
                            detail=e.summary,
                        )
                        for e in rows[:_MAX_EVIDENCE]
                    ],
                )
            )
        return signals
