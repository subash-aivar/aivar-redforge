"""Aggregates/entities for the Network Security bounded context (M16).

See domain/network_security/__init__.py for why these mirror (rather
than reuse) ValidationExecution/ContinuousValidationPolicy/
SecurityDriftEvent/ValidationStateSnapshot's exact shapes and
disciplines.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import TYPE_CHECKING, Self

from redforge.domain.network_security.events import (
    NetworkPolicyActivated,
    NetworkPolicyCreated,
    NetworkPolicyDisabled,
    NetworkPolicyPaused,
    NetworkPolicyResumed,
    NetworkRunAuthorized,
    NetworkRunCancelled,
    NetworkRunCreated,
    NetworkRunFinished,
    NetworkRunPolicyDenied,
    NetworkRunStarted,
    NetworkSecurityEvent,
    _now,
)
from redforge.domain.network_security.exceptions import (
    InvalidNetworkPolicyTransitionError,
    InvalidNetworkRunTransitionError,
)
from redforge.domain.network_security.value_objects import (
    CLAIM_LEASE_SECONDS,
    TERMINAL_RUN_STATUSES,
    NetworkRunStatus,
    NetworkValidationProfile,
    PolicyLifecycle,
    is_legal_network_run_transition,
    is_legal_policy_transition,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.domain.continuous_validation.value_objects import SecurityDriftCategory
    from redforge.domain.network_security.value_objects import ValidationCadence


class NetworkValidationRun:
    """NetworkValidationRun aggregate root — the execution-lifecycle
    truth for one authorized network validation attempt against one
    NETWORK or IP_ADDRESS AIAsset.

    Invariants (mirrors ValidationExecution exactly):
    - Always tenant-owned (organization_id never changes).
    - target_asset_id never changes after creation.
    - A DENIED run never reaches RUNNING.
    - A CANCELLED run stops scheduling new steps immediately.
    - finish() computes the final status from step-level evidence the
      orchestrator supplies — never optimistically marked COMPLETED.
    """

    __slots__ = (
        "_authorization_id",
        "_cancellation_requested",
        "_continuous_policy_id",
        "_events",
        "_finished_at",
        "_id",
        "_organization_id",
        "_profile",
        "_requester_user_id",
        "_scheduled_due_at",
        "_started_at",
        "_status",
        "_target_asset_id",
        "_timestamps",
        "_trigger",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        target_asset_id: EntityId,
        requester_user_id: EntityId,
        profile: NetworkValidationProfile,
        status: NetworkRunStatus,
        timestamps: AuditTimestamps,
        trigger: str = "manual",
        continuous_policy_id: EntityId | None = None,
        scheduled_due_at: datetime | None = None,
        authorization_id: EntityId | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        cancellation_requested: bool = False,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._target_asset_id = target_asset_id
        self._requester_user_id = requester_user_id
        self._profile = profile
        self._status = status
        self._timestamps = timestamps
        self._trigger = trigger
        self._continuous_policy_id = continuous_policy_id
        self._scheduled_due_at = scheduled_due_at
        self._authorization_id = authorization_id
        self._started_at = started_at
        self._finished_at = finished_at
        self._cancellation_requested = cancellation_requested
        self._events: list[NetworkSecurityEvent] = []

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        target_asset_id: EntityId,
        requester_user_id: EntityId,
        profile: NetworkValidationProfile,
        trigger: str = "manual",
        continuous_policy_id: EntityId | None = None,
        scheduled_due_at: datetime | None = None,
    ) -> Self:
        run = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            target_asset_id=target_asset_id,
            requester_user_id=requester_user_id,
            profile=profile,
            status=NetworkRunStatus.PENDING,
            timestamps=AuditTimestamps.create(),
            trigger=trigger,
            continuous_policy_id=continuous_policy_id,
            scheduled_due_at=scheduled_due_at,
        )
        run._record_event(
            NetworkRunCreated(
                occurred_at=_now(), run_id=str(run._id),
                organization_id=str(organization_id), target_asset_id=str(target_asset_id),
            )
        )
        return run

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def target_asset_id(self) -> EntityId:
        return self._target_asset_id

    @property
    def requester_user_id(self) -> EntityId:
        return self._requester_user_id

    @property
    def profile(self) -> NetworkValidationProfile:
        return self._profile

    @property
    def status(self) -> NetworkRunStatus:
        return self._status

    @property
    def trigger(self) -> str:
        return self._trigger

    @property
    def continuous_policy_id(self) -> EntityId | None:
        return self._continuous_policy_id

    @property
    def scheduled_due_at(self) -> datetime | None:
        return self._scheduled_due_at

    @property
    def authorization_id(self) -> EntityId | None:
        return self._authorization_id

    @property
    def started_at(self) -> datetime | None:
        return self._started_at

    @property
    def finished_at(self) -> datetime | None:
        return self._finished_at

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_terminal(self) -> bool:
        return self._status in TERMINAL_RUN_STATUSES

    @property
    def cancellation_requested(self) -> bool:
        return self._cancellation_requested

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def request_cancellation(self) -> None:
        """Monotonic: once True, stays True — repeated calls are a
        no-op (idempotent), and calling this on an already-terminal run
        is harmless (the flag is inert once no further probing can
        possibly occur). The actual lifecycle transition to CANCELLED
        is a SEPARATE step performed only by the orchestrator once it
        cooperatively observes this flag (see cancel()) — this method
        never touches `_status` itself, so requesting cancellation can
        never illegally skip a state or race the orchestrator's own
        transition."""
        self._cancellation_requested = True
        self._touch()

    def begin_policy_check(self) -> None:
        self._require_legal_transition(NetworkRunStatus.POLICY_CHECKING)
        self._status = NetworkRunStatus.POLICY_CHECKING
        self._touch()

    def deny(self, reason_code: str) -> None:
        self._require_legal_transition(NetworkRunStatus.DENIED)
        self._status = NetworkRunStatus.DENIED
        self._finished_at = _now()
        self._touch()
        self._record_event(
            NetworkRunPolicyDenied(
                occurred_at=_now(), run_id=str(self._id),
                organization_id=str(self._organization_id), reason_code=reason_code,
            )
        )

    def authorize(self, authorization_id: EntityId) -> None:
        self._require_legal_transition(NetworkRunStatus.AUTHORIZED)
        self._status = NetworkRunStatus.AUTHORIZED
        self._authorization_id = authorization_id
        self._touch()
        self._record_event(
            NetworkRunAuthorized(
                occurred_at=_now(), run_id=str(self._id),
                organization_id=str(self._organization_id),
                authorization_id=str(authorization_id),
            )
        )

    def start(self) -> None:
        self._require_legal_transition(NetworkRunStatus.RUNNING)
        self._status = NetworkRunStatus.RUNNING
        self._started_at = _now()
        self._touch()
        self._record_event(
            NetworkRunStarted(
                occurred_at=_now(), run_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    def finish(self, status: NetworkRunStatus, payload: dict[str, str] | None = None) -> None:
        if status not in (
            NetworkRunStatus.COMPLETED, NetworkRunStatus.PARTIALLY_COMPLETED,
            NetworkRunStatus.FAILED,
        ):
            raise InvalidNetworkRunTransitionError(str(self._status), str(status))
        self._require_legal_transition(status)
        self._status = status
        self._finished_at = _now()
        self._touch()
        self._record_event(
            NetworkRunFinished(
                occurred_at=_now(), run_id=str(self._id),
                organization_id=str(self._organization_id), status=str(status),
                payload=payload or {},
            )
        )

    def cancel(self) -> None:
        self._require_legal_transition(NetworkRunStatus.CANCELLED)
        self._status = NetworkRunStatus.CANCELLED
        self._finished_at = _now()
        self._touch()
        self._record_event(
            NetworkRunCancelled(
                occurred_at=_now(), run_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[NetworkSecurityEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_legal_transition(self, target: NetworkRunStatus) -> None:
        if not is_legal_network_run_transition(self._status, target):
            raise InvalidNetworkRunTransitionError(str(self._status), str(target))

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: NetworkSecurityEvent) -> None:
        self._events.append(event)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NetworkValidationRun):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"NetworkValidationRun(id={self._id}, org={self._organization_id}, "
            f"status={self._status})"
        )


class NetworkMonitoringPolicy:
    """NetworkMonitoringPolicy aggregate root — continuous network
    monitoring configuration for one NETWORK or IP_ADDRESS AIAsset.
    Mirrors ContinuousValidationPolicy exactly (imports the SAME
    PolicyLifecycle/ValidationCadence enums, same claim-lease
    discipline)."""

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
        "_target_asset_id",
        "_timestamps",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        target_asset_id: EntityId,
        requester_user_id: EntityId,
        profile: NetworkValidationProfile,
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
        self._target_asset_id = target_asset_id
        self._requester_user_id = requester_user_id
        self._profile = profile
        self._cadence = cadence
        self._lifecycle = lifecycle
        self._timestamps = timestamps
        self._next_due_at = next_due_at
        self._last_scheduled_at = last_scheduled_at
        self._claimed_at = claimed_at
        self._claim_owner = claim_owner
        self._events: list[NetworkSecurityEvent] = []

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        target_asset_id: EntityId,
        requester_user_id: EntityId,
        profile: NetworkValidationProfile,
        cadence: ValidationCadence,
    ) -> Self:
        policy = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            target_asset_id=target_asset_id,
            requester_user_id=requester_user_id,
            profile=profile,
            cadence=cadence,
            lifecycle=PolicyLifecycle.DRAFT,
            timestamps=AuditTimestamps.create(),
        )
        policy._record_event(
            NetworkPolicyCreated(
                occurred_at=_now(), policy_id=str(policy._id),
                organization_id=str(organization_id), target_asset_id=str(target_asset_id),
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
    def target_asset_id(self) -> EntityId:
        return self._target_asset_id

    @property
    def requester_user_id(self) -> EntityId:
        return self._requester_user_id

    @property
    def profile(self) -> NetworkValidationProfile:
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
        self._require_legal_transition(PolicyLifecycle.ACTIVE)
        self._lifecycle = PolicyLifecycle.ACTIVE
        self._next_due_at = now
        self._touch()
        self._record_event(
            NetworkPolicyActivated(
                occurred_at=_now(), policy_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    def pause(self, now: datetime) -> None:
        self._require_legal_transition(PolicyLifecycle.PAUSED)
        self._lifecycle = PolicyLifecycle.PAUSED
        self._touch()
        self._record_event(
            NetworkPolicyPaused(
                occurred_at=_now(), policy_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    def resume(self, now: datetime) -> None:
        self._require_legal_transition(PolicyLifecycle.ACTIVE)
        self._lifecycle = PolicyLifecycle.ACTIVE
        self._next_due_at = now
        self._touch()
        self._record_event(
            NetworkPolicyResumed(
                occurred_at=_now(), policy_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    def disable(self, now: datetime) -> None:
        self._require_legal_transition(PolicyLifecycle.DISABLED)
        self._lifecycle = PolicyLifecycle.DISABLED
        self._claimed_at = None
        self._claim_owner = None
        self._touch()
        self._record_event(
            NetworkPolicyDisabled(
                occurred_at=_now(), policy_id=str(self._id),
                organization_id=str(self._organization_id),
            )
        )

    def is_due(self, now: datetime) -> bool:
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
        if self._next_due_at is None:
            return
        from redforge.domain.network_security.value_objects import cadence_interval_seconds

        interval = cadence_interval_seconds(self._cadence)
        elapsed_seconds = (now - self._next_due_at).total_seconds()
        intervals_missed = max(0, int(elapsed_seconds // interval))
        self._next_due_at = self._next_due_at + timedelta(
            seconds=(intervals_missed + 1) * interval
        )
        self._last_scheduled_at = now
        self._touch()

    def release_claim(self) -> None:
        self._claimed_at = None
        self._claim_owner = None
        self._touch()

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[NetworkSecurityEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_legal_transition(self, target: PolicyLifecycle) -> None:
        if not is_legal_policy_transition(self._lifecycle, target):
            raise InvalidNetworkPolicyTransitionError(str(self._lifecycle), str(target))

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: NetworkSecurityEvent) -> None:
        self._events.append(event)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NetworkMonitoringPolicy):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"NetworkMonitoringPolicy(id={self._id}, org={self._organization_id}, "
            f"lifecycle={self._lifecycle}, cadence={self._cadence})"
        )


class NetworkDriftEvent:
    """One immutable, append-only network drift fact. Structurally
    identical to M14's SecurityDriftEvent (same field shapes, same
    dedup discipline) but keyed against this context's own
    NetworkMonitoringPolicy/NetworkValidationRun ids — see
    domain/network_security/__init__.py for why the M14 tables/FKs
    could not be reused directly."""

    __slots__ = (
        "_category",
        "_detail",
        "_detected_at",
        "_id",
        "_identity_key",
        "_organization_id",
        "_policy_id",
        "_run_id",
        "_summary",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        policy_id: EntityId,
        run_id: EntityId,
        category: SecurityDriftCategory,
        identity_key: str,
        summary: str,
        detail: dict[str, str],
        detected_at: datetime,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._policy_id = policy_id
        self._run_id = run_id
        self._category = category
        self._identity_key = identity_key
        self._summary = summary
        self._detail = detail
        self._detected_at = detected_at

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        policy_id: EntityId,
        run_id: EntityId,
        category: SecurityDriftCategory,
        identity_key: str,
        summary: str,
        detail: dict[str, str] | None = None,
    ) -> Self:
        return cls(
            id=EntityId.generate(), organization_id=organization_id, policy_id=policy_id,
            run_id=run_id, category=category, identity_key=identity_key, summary=summary,
            detail=detail or {}, detected_at=_now(),
        )

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def policy_id(self) -> EntityId:
        return self._policy_id

    @property
    def run_id(self) -> EntityId:
        return self._run_id

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
        return f"NetworkDriftEvent(policy={self._policy_id}, category={self._category})"


class NetworkServiceSnapshotEntry:
    """One normalized service fact inside a NetworkStateSnapshot —
    identical shape to M14's ServiceSnapshotEntry."""

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
        if not isinstance(other, NetworkServiceSnapshotEntry):
            return NotImplemented
        return self.as_tuple() == other.as_tuple()

    def __hash__(self) -> int:
        return hash(self.as_tuple())


_NETWORK_SNAPSHOT_SCHEMA_VERSION = 1


class NetworkStateSnapshot:
    """Immutable, normalized comparison artifact for one
    NetworkMonitoringPolicy's NetworkValidationRun. Identical semantics
    to M14's ValidationStateSnapshot: excludes every volatile field,
    deterministic ordering, SHA-256 content fingerprint."""

    __slots__ = (
        "_active_condition_keys",
        "_active_correlation_keys",
        "_captured_at",
        "_content_fingerprint",
        "_id",
        "_organization_id",
        "_policy_id",
        "_reachable_ports",
        "_resolved_ips",
        "_run_id",
        "_schema_version",
        "_services",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        policy_id: EntityId,
        run_id: EntityId,
        schema_version: int,
        resolved_ips: tuple[str, ...],
        reachable_ports: tuple[int, ...],
        services: tuple[NetworkServiceSnapshotEntry, ...],
        active_condition_keys: tuple[str, ...],
        active_correlation_keys: tuple[str, ...],
        content_fingerprint: str,
        captured_at: datetime,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._policy_id = policy_id
        self._run_id = run_id
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
        policy_id: EntityId,
        run_id: EntityId,
        resolved_ips: list[str],
        reachable_ports: list[int],
        services: list[NetworkServiceSnapshotEntry],
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
            id=EntityId.generate(), organization_id=organization_id, policy_id=policy_id,
            run_id=run_id, schema_version=_NETWORK_SNAPSHOT_SCHEMA_VERSION,
            resolved_ips=norm_ips, reachable_ports=norm_ports, services=norm_services,
            active_condition_keys=norm_conditions, active_correlation_keys=norm_correlations,
            content_fingerprint=fingerprint, captured_at=_now(),
        )

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def policy_id(self) -> EntityId:
        return self._policy_id

    @property
    def run_id(self) -> EntityId:
        return self._run_id

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
    def services(self) -> tuple[NetworkServiceSnapshotEntry, ...]:
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

    def is_identical_to(self, other: NetworkStateSnapshot) -> bool:
        return self._content_fingerprint == other._content_fingerprint


def _compute_fingerprint(
    resolved_ips: tuple[str, ...],
    reachable_ports: tuple[int, ...],
    services: tuple[NetworkServiceSnapshotEntry, ...],
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
