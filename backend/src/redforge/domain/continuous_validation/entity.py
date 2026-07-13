"""Aggregates/entities for the Continuous Validation bounded context (M14).

`ContinuousValidationPolicy` is the tenant-owned aggregate root: it
declares WHAT to continuously validate (target, profile), HOW OFTEN
(cadence), and its own lifecycle. It never validates anything itself —
see `application/continuous_validation/processor.py` for the
claim -> authorize -> execute -> snapshot -> reconcile -> drift ->
advance -> release orchestration that reuses
`ValidationExecutionService.create_and_run()` for the actual run.

`SecurityDriftEvent` is a separate, small, append-only entity — one row
per detected canonical-state change, never updated after creation
(mirrors `ExecutionEvent`'s immutability rationale exactly).

`ValidationStateSnapshot` is an immutable comparison artifact: a
normalized, deterministic projection of one ValidationExecution's
canonical result, built once and never mutated, with a content
fingerprint so identical states are trivially comparable without
re-deriving the full projection.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import TYPE_CHECKING, Self

from redforge.domain.continuous_validation.events import (
    ContinuousValidationEvent,
    PolicyActivated,
    PolicyCreated,
    PolicyDisabled,
    PolicyPaused,
    PolicyResumed,
    _now,
)
from redforge.domain.continuous_validation.exceptions import InvalidPolicyTransitionError
from redforge.domain.continuous_validation.value_objects import (
    CLAIM_LEASE_SECONDS,
    PolicyLifecycle,
    ValidationCadence,
    cadence_interval_seconds,
    is_legal_policy_transition,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.domain.continuous_validation.value_objects import SecurityDriftCategory
    from redforge.domain.validation_execution.value_objects import ValidationProfile


class ContinuousValidationPolicy:
    """ContinuousValidationPolicy aggregate root.

    Invariants:
    - Always tenant-owned (organization_id never changes).
    - `requester_user_id` is fixed at creation — every SCHEDULED and
      ON_DEMAND run this policy ever produces is authorized against
      THIS user's SecurityAuthorization scope, re-checked fresh at
      every due boundary (never cached, never permanent — see
      `application/continuous_validation/processor.py`).
    - `next_due_at`/`last_scheduled_at`/`claimed_at`/`claim_owner` are
      only meaningful while ACTIVE; DRAFT and DISABLED policies are
      never eligible for claiming.
    - DISABLED is terminal — see PolicyLifecycle's docstring.
    """

    __slots__ = (
        "_cadence",
        "_claim_owner",
        "_claimed_at",
        "_events",
        "_id",
        "_last_scheduled_at",
        "_lifecycle",
        "_next_due_at",
        "_organization_id",
        "_profile",
        "_requester_user_id",
        "_target_id",
        "_timestamps",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        target_id: EntityId,
        requester_user_id: EntityId,
        profile: ValidationProfile,
        cadence: ValidationCadence,
        lifecycle: PolicyLifecycle,
        timestamps: AuditTimestamps,
        next_due_at: datetime | None = None,
        last_scheduled_at: datetime | None = None,
        claimed_at: datetime | None = None,
        claim_owner: str | None = None,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._target_id = target_id
        self._requester_user_id = requester_user_id
        self._profile = profile
        self._cadence = cadence
        self._lifecycle = lifecycle
        self._timestamps = timestamps
        self._next_due_at = next_due_at
        self._last_scheduled_at = last_scheduled_at
        self._claimed_at = claimed_at
        self._claim_owner = claim_owner
        self._events: list[ContinuousValidationEvent] = []

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        target_id: EntityId,
        requester_user_id: EntityId,
        profile: ValidationProfile,
        cadence: ValidationCadence,
    ) -> Self:
        """Create a new ContinuousValidationPolicy in DRAFT. A client can
        never create anything other than DRAFT — activate() is the only
        path to ACTIVE (and the only path that ever sets next_due_at)."""
        policy = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            target_id=target_id,
            requester_user_id=requester_user_id,
            profile=profile,
            cadence=cadence,
            lifecycle=PolicyLifecycle.DRAFT,
            timestamps=AuditTimestamps.create(),
        )
        policy._record_event(
            PolicyCreated(
                occurred_at=_now(),
                policy_id=str(policy._id),
                organization_id=str(organization_id),
                target_id=str(target_id),
            )
        )
        return policy

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def target_id(self) -> EntityId:
        return self._target_id

    @property
    def requester_user_id(self) -> EntityId:
        return self._requester_user_id

    @property
    def profile(self) -> ValidationProfile:
        return self._profile

    @property
    def cadence(self) -> ValidationCadence:
        return self._cadence

    @property
    def lifecycle(self) -> PolicyLifecycle:
        return self._lifecycle

    @property
    def next_due_at(self) -> datetime | None:
        return self._next_due_at

    @property
    def last_scheduled_at(self) -> datetime | None:
        return self._last_scheduled_at

    @property
    def claimed_at(self) -> datetime | None:
        return self._claimed_at

    @property
    def claim_owner(self) -> str | None:
        return self._claim_owner

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_active(self) -> bool:
        return self._lifecycle == PolicyLifecycle.ACTIVE

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def activate(self, now: datetime) -> None:
        """DRAFT -> ACTIVE. Immediately due (next_due_at = now) — starting
        continuous validation means checking now, not waiting a full
        cadence interval for the first observation."""
        self._require_legal_transition(PolicyLifecycle.ACTIVE)
        self._lifecycle = PolicyLifecycle.ACTIVE
        self._next_due_at = now
        self._touch()
        self._record_event(
            PolicyActivated(
                occurred_at=_now(), policy_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    def pause(self, now: datetime) -> None:
        """ACTIVE -> PAUSED. Preserves next_due_at as-is (not cleared) so
        the eventual resume() has a well-defined prior boundary, but a
        paused policy is never eligible for claiming regardless."""
        self._require_legal_transition(PolicyLifecycle.PAUSED)
        self._lifecycle = PolicyLifecycle.PAUSED
        self._touch()
        self._record_event(
            PolicyPaused(
                occurred_at=_now(), policy_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    def resume(self, now: datetime) -> None:
        """PAUSED -> ACTIVE. Immediately due again, exactly like
        activate() — resuming means "check now", not "silently pick up
        wherever the schedule would have drifted to while paused"."""
        self._require_legal_transition(PolicyLifecycle.ACTIVE)
        self._lifecycle = PolicyLifecycle.ACTIVE
        self._next_due_at = now
        self._touch()
        self._record_event(
            PolicyResumed(
                occurred_at=_now(), policy_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    def disable(self, now: datetime) -> None:
        """{DRAFT, ACTIVE, PAUSED} -> DISABLED. Terminal — see
        PolicyLifecycle's docstring. Releases any outstanding claim so a
        disabled policy can never be mistaken for still-claimed."""
        self._require_legal_transition(PolicyLifecycle.DISABLED)
        self._lifecycle = PolicyLifecycle.DISABLED
        self._claimed_at = None
        self._claim_owner = None
        self._touch()
        self._record_event(
            PolicyDisabled(
                occurred_at=_now(), policy_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    def is_due(self, now: datetime) -> bool:
        """Pure read-side predicate mirroring the atomic claim UPDATE's
        own WHERE clause (see infrastructure repository) — used for
        list/diagnostic reads, never for the actual claim itself, which
        must be a single atomic database statement to be concurrency-safe."""
        if self._lifecycle != PolicyLifecycle.ACTIVE or self._next_due_at is None:
            return False
        if self._next_due_at > now:
            return False
        if self._claimed_at is not None:
            lease_expiry = self._claimed_at + timedelta(seconds=CLAIM_LEASE_SECONDS)
            if lease_expiry > now:
                return False
        return True

    def advance_schedule(self, now: datetime) -> None:
        """Mathematically advance next_due_at past `now`, coalescing any
        missed intervals into one jump — never a loop, never
        individually retrying each missed boundary (bounded backlog
        coalescing, see the M14 brief)."""
        if self._next_due_at is None:
            return
        interval = cadence_interval_seconds(self._cadence)
        elapsed_seconds = (now - self._next_due_at).total_seconds()
        intervals_missed = max(0, int(elapsed_seconds // interval))
        self._next_due_at = self._next_due_at + timedelta(
            seconds=(intervals_missed + 1) * interval
        )
        self._last_scheduled_at = now
        self._touch()

    def release_claim(self) -> None:
        """Release an outstanding claim (called after a scheduled run's
        processing finishes, success or failure) rather than waiting out
        the full lease window — keeps the policy promptly reclaimable."""
        self._claimed_at = None
        self._claim_owner = None
        self._touch()

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[ContinuousValidationEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_legal_transition(self, target: PolicyLifecycle) -> None:
        if not is_legal_policy_transition(self._lifecycle, target):
            raise InvalidPolicyTransitionError(str(self._lifecycle), str(target))

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: ContinuousValidationEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ContinuousValidationPolicy):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"ContinuousValidationPolicy(id={self._id}, org={self._organization_id}, "
            f"lifecycle={self._lifecycle}, cadence={self._cadence})"
        )


class SecurityDriftEvent:
    """One immutable, append-only detected canonical-state change.

    Never updated after creation — the change feed is a pure log.
    `identity_key` is the deterministic dedup identity for this drift
    fact WITHIN one execution's comparison (e.g. `"port:22"`,
    `"condition:TLS_CERTIFICATE_EXPIRED:<asset_id>"`); it deliberately
    never includes `detected_at` or display text, so a genuinely
    duplicate detection within the same comparison collapses to one
    row (enforced at the repository/persistence layer), while the SAME
    fact drifting again in a LATER, distinct execution is correctly a
    new row (the uniqueness scope also includes execution_id).
    """

    __slots__ = (
        "_category",
        "_continuous_policy_id",
        "_detail",
        "_detected_at",
        "_execution_id",
        "_id",
        "_identity_key",
        "_organization_id",
        "_summary",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        continuous_policy_id: EntityId,
        execution_id: EntityId,
        category: SecurityDriftCategory,
        identity_key: str,
        summary: str,
        detail: dict[str, str],
        detected_at: datetime,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._continuous_policy_id = continuous_policy_id
        self._execution_id = execution_id
        self._category = category
        self._identity_key = identity_key
        self._summary = summary
        self._detail = detail
        self._detected_at = detected_at

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        continuous_policy_id: EntityId,
        execution_id: EntityId,
        category: SecurityDriftCategory,
        identity_key: str,
        summary: str,
        detail: dict[str, str] | None = None,
    ) -> Self:
        return cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            continuous_policy_id=continuous_policy_id,
            execution_id=execution_id,
            category=category,
            identity_key=identity_key,
            summary=summary,
            detail=detail or {},
            detected_at=_now(),
        )

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def continuous_policy_id(self) -> EntityId:
        return self._continuous_policy_id

    @property
    def execution_id(self) -> EntityId:
        return self._execution_id

    @property
    def category(self) -> SecurityDriftCategory:
        return self._category

    @property
    def identity_key(self) -> str:
        return self._identity_key

    @property
    def summary(self) -> str:
        return self._summary

    @property
    def detail(self) -> dict[str, str]:
        return dict(self._detail)

    @property
    def detected_at(self) -> datetime:
        return self._detected_at

    def __repr__(self) -> str:
        return (
            f"SecurityDriftEvent(policy={self._continuous_policy_id}, "
            f"category={self._category}, key={self._identity_key})"
        )


class ServiceSnapshotEntry:
    """One normalized service fact inside a ValidationStateSnapshot.
    Deliberately excludes banner/version-string text — never part of
    canonical identity anywhere in this codebase (see
    domain/inventory/identity.py)."""

    __slots__ = ("_port", "_tls_fingerprint_sha256", "_validated_protocol", "_validator_id")

    def __init__(
        self,
        port: int,
        validated_protocol: str | None,
        validator_id: str | None,
        tls_fingerprint_sha256: str | None,
    ) -> None:
        self._port = port
        self._validated_protocol = validated_protocol
        self._validator_id = validator_id
        self._tls_fingerprint_sha256 = tls_fingerprint_sha256

    @property
    def port(self) -> int:
        return self._port

    @property
    def validated_protocol(self) -> str | None:
        return self._validated_protocol

    @property
    def validator_id(self) -> str | None:
        return self._validator_id

    @property
    def tls_fingerprint_sha256(self) -> str | None:
        return self._tls_fingerprint_sha256

    def as_tuple(self) -> tuple[int, str | None, str | None, str | None]:
        return (self._port, self._validated_protocol, self._validator_id,
                self._tls_fingerprint_sha256)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ServiceSnapshotEntry):
            return NotImplemented
        return self.as_tuple() == other.as_tuple()

    def __hash__(self) -> int:
        return hash(self.as_tuple())


_SNAPSHOT_SCHEMA_VERSION = 1


class ValidationStateSnapshot:
    """Immutable, normalized comparison artifact for one
    ContinuousValidationPolicy's ValidationExecution. Built once, never
    updated. Excludes every volatile field (observed_at, execution id,
    event id, latency, ordering, transient exception text, updated_at)
    from its normalized projection and content fingerprint — this is
    the exact comparison boundary drift detection reads from, never a
    diff of raw execution JSON."""

    __slots__ = (
        "_active_condition_keys",
        "_active_correlation_keys",
        "_captured_at",
        "_content_fingerprint",
        "_continuous_policy_id",
        "_execution_id",
        "_id",
        "_organization_id",
        "_reachable_ports",
        "_resolved_ips",
        "_schema_version",
        "_services",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        continuous_policy_id: EntityId,
        execution_id: EntityId,
        schema_version: int,
        resolved_ips: tuple[str, ...],
        reachable_ports: tuple[int, ...],
        services: tuple[ServiceSnapshotEntry, ...],
        active_condition_keys: tuple[str, ...],
        active_correlation_keys: tuple[str, ...],
        content_fingerprint: str,
        captured_at: datetime,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._continuous_policy_id = continuous_policy_id
        self._execution_id = execution_id
        self._schema_version = schema_version
        self._resolved_ips = resolved_ips
        self._reachable_ports = reachable_ports
        self._services = services
        self._active_condition_keys = active_condition_keys
        self._active_correlation_keys = active_correlation_keys
        self._content_fingerprint = content_fingerprint
        self._captured_at = captured_at

    @classmethod
    def build(
        cls,
        organization_id: EntityId,
        continuous_policy_id: EntityId,
        execution_id: EntityId,
        resolved_ips: list[str],
        reachable_ports: list[int],
        services: list[ServiceSnapshotEntry],
        active_condition_keys: list[str],
        active_correlation_keys: list[str],
    ) -> Self:
        norm_ips = tuple(sorted(set(resolved_ips)))
        norm_ports = tuple(sorted(set(reachable_ports)))
        norm_services = tuple(sorted(services, key=lambda s: s.port))
        norm_conditions = tuple(sorted(set(active_condition_keys)))
        norm_correlations = tuple(sorted(set(active_correlation_keys)))
        fingerprint = _compute_fingerprint(
            norm_ips, norm_ports, norm_services, norm_conditions, norm_correlations,
        )
        return cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            continuous_policy_id=continuous_policy_id,
            execution_id=execution_id,
            schema_version=_SNAPSHOT_SCHEMA_VERSION,
            resolved_ips=norm_ips,
            reachable_ports=norm_ports,
            services=norm_services,
            active_condition_keys=norm_conditions,
            active_correlation_keys=norm_correlations,
            content_fingerprint=fingerprint,
            captured_at=_now(),
        )

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def continuous_policy_id(self) -> EntityId:
        return self._continuous_policy_id

    @property
    def execution_id(self) -> EntityId:
        return self._execution_id

    @property
    def schema_version(self) -> int:
        return self._schema_version

    @property
    def resolved_ips(self) -> tuple[str, ...]:
        return self._resolved_ips

    @property
    def reachable_ports(self) -> tuple[int, ...]:
        return self._reachable_ports

    @property
    def services(self) -> tuple[ServiceSnapshotEntry, ...]:
        return self._services

    @property
    def active_condition_keys(self) -> tuple[str, ...]:
        return self._active_condition_keys

    @property
    def active_correlation_keys(self) -> tuple[str, ...]:
        return self._active_correlation_keys

    @property
    def content_fingerprint(self) -> str:
        return self._content_fingerprint

    @property
    def captured_at(self) -> datetime:
        return self._captured_at

    def is_identical_to(self, other: ValidationStateSnapshot) -> bool:
        """Identical canonical state MUST produce zero drift events — this
        is the single fast-path check the comparison module consults
        before doing any field-by-field diffing."""
        return self._content_fingerprint == other._content_fingerprint


def _compute_fingerprint(
    resolved_ips: tuple[str, ...],
    reachable_ports: tuple[int, ...],
    services: tuple[ServiceSnapshotEntry, ...],
    active_condition_keys: tuple[str, ...],
    active_correlation_keys: tuple[str, ...],
) -> str:
    payload = {
        "resolved_ips": list(resolved_ips),
        "reachable_ports": list(reachable_ports),
        "services": [list(s.as_tuple()) for s in services],
        "active_condition_keys": list(active_condition_keys),
        "active_correlation_keys": list(active_correlation_keys),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
