"""Connector aggregate root — Enterprise AI Connector & Discovery Framework.

A Connector represents an integration point between RedForge and an external
AI platform (OpenAI, Anthropic, LangSmith, etc.). It is NOT a ProviderAdapter
(domain/providers/) — that is used for attack execution. This is used for
ASSET DISCOVERY: discovering AI assets deployed on those platforms and feeding
them into the Inventory pipeline.

Lifecycle:
  REGISTERED → CONFIGURED → VALIDATED → ENABLED ↔ DISABLED → ARCHIVED
  ARCHIVED is terminal.

A Connector in ENABLED state can run DiscoveryJobs and SyncJobs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redforge.domain.connectors.events import (
    ConnectorArchived,
    ConnectorConfigured,
    ConnectorDisabled,
    ConnectorDomainEvent,
    ConnectorEnabled,
    ConnectorHealthUpdated,
    ConnectorRegistered,
    ConnectorValidated,
    CredentialReferenceUpdated,
    DiscoveryJobCompleted,
    DiscoveryJobFailed,
    DiscoveryJobStarted,
    SyncJobCompleted,
    SyncJobFailed,
    SyncJobStarted,
    SyncPolicyChanged,
)
from redforge.domain.connectors.exceptions import (
    ConnectorAlreadyArchivedError,
    ConnectorNotEnabledError,
    DiscoveryJobConflictError,
    InvalidConnectorTransitionError,
    SyncJobConflictError,
)
from redforge.domain.connectors.value_objects import (
    ConnectorAuditEntry,
    ConnectorCapability,
    ConnectorConfiguration,
    ConnectorCredentialReference,
    ConnectorHealth,
    ConnectorStatus,
    ConnectorType,
    ConnectorVersion,
    DiscoveryJobRecord,
    DiscoveryJobStatus,
    SynchronizationPolicy,
    SyncJobRecord,
    SyncJobStatus,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.shared.timestamps import AuditTimestamps

# Valid lifecycle transitions — dict-dispatched, no switch statements
_LIFECYCLE_TRANSITIONS: dict[ConnectorStatus, frozenset[ConnectorStatus]] = {
    ConnectorStatus.REGISTERED: frozenset({ConnectorStatus.CONFIGURED, ConnectorStatus.ARCHIVED}),
    ConnectorStatus.CONFIGURED: frozenset({ConnectorStatus.VALIDATED, ConnectorStatus.ARCHIVED}),
    ConnectorStatus.VALIDATED: frozenset({ConnectorStatus.ENABLED, ConnectorStatus.ARCHIVED}),
    ConnectorStatus.ENABLED: frozenset({ConnectorStatus.DISABLED, ConnectorStatus.ARCHIVED}),
    ConnectorStatus.DISABLED: frozenset({ConnectorStatus.ENABLED, ConnectorStatus.ARCHIVED}),
    ConnectorStatus.ARCHIVED: frozenset(),  # terminal
}


class Connector:
    """Connector aggregate root.

    Invariants:
    - Belongs to exactly one organization.
    - ARCHIVED is terminal — no mutations allowed.
    - Discovery/sync jobs can only run when ENABLED.
    - At most one running discovery job at a time.
    - At most one running sync job at a time.
    - Credential references never store raw secrets.
    - Audit trail is append-only.
    """

    __slots__ = (
        "_audit_trail",
        "_capabilities",
        "_config",
        "_connector_type",
        "_credential_ref",
        "_description",
        "_discovery_history",
        "_events",
        "_health",
        "_id",
        "_name",
        "_organization_id",
        "_status",
        "_sync_history",
        "_sync_policy",
        "_timestamps",
        "_version",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        connector_type: ConnectorType,
        name: str,
        description: str,
        version: ConnectorVersion,
        capabilities: tuple[ConnectorCapability, ...],
        status: ConnectorStatus,
        config: ConnectorConfiguration | None,
        credential_ref: ConnectorCredentialReference | None,
        health: ConnectorHealth,
        sync_policy: SynchronizationPolicy,
        discovery_history: tuple[DiscoveryJobRecord, ...],
        sync_history: tuple[SyncJobRecord, ...],
        audit_trail: tuple[ConnectorAuditEntry, ...],
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._connector_type = connector_type
        self._name = name
        self._description = description
        self._version = version
        self._capabilities = capabilities
        self._status = status
        self._config = config
        self._credential_ref = credential_ref
        self._health = health
        self._sync_policy = sync_policy
        self._discovery_history = discovery_history
        self._sync_history = sync_history
        self._audit_trail = audit_trail
        self._timestamps = timestamps
        self._events: list[ConnectorDomainEvent] = []

    # ─── Factory ──────────────────────────────────────────────────────────────

    @classmethod
    def register(
        cls,
        organization_id: EntityId,
        connector_type: ConnectorType,
        name: str,
        description: str,
        version: ConnectorVersion,
        capabilities: tuple[ConnectorCapability, ...],
    ) -> Connector:
        """Register a new connector in REGISTERED status."""
        from redforge.shared.timestamps import AuditTimestamps
        connector_id = EntityId.generate()
        connector = cls(
            id=connector_id,
            organization_id=organization_id,
            connector_type=connector_type,
            name=name,
            description=description,
            version=version,
            capabilities=capabilities,
            status=ConnectorStatus.REGISTERED,
            config=None,
            credential_ref=None,
            health=ConnectorHealth.unknown(),
            sync_policy=SynchronizationPolicy(),
            discovery_history=(),
            sync_history=(),
            audit_trail=(),
            timestamps=AuditTimestamps.create(),
        )
        connector._events.append(
            ConnectorRegistered(
                organization_id=str(organization_id),
                connector_id=str(connector_id),
                connector_type=connector_type.value,
                name=name,
            )
        )
        return connector

    # ─── Properties ───────────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def connector_type(self) -> ConnectorType:
        return self._connector_type

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def version(self) -> ConnectorVersion:
        return self._version

    @property
    def capabilities(self) -> tuple[ConnectorCapability, ...]:
        return self._capabilities

    @property
    def status(self) -> ConnectorStatus:
        return self._status

    @property
    def config(self) -> ConnectorConfiguration | None:
        return self._config

    @property
    def credential_ref(self) -> ConnectorCredentialReference | None:
        return self._credential_ref

    @property
    def health(self) -> ConnectorHealth:
        return self._health

    @property
    def sync_policy(self) -> SynchronizationPolicy:
        return self._sync_policy

    @property
    def discovery_history(self) -> tuple[DiscoveryJobRecord, ...]:
        return self._discovery_history

    @property
    def sync_history(self) -> tuple[SyncJobRecord, ...]:
        return self._sync_history

    @property
    def audit_trail(self) -> tuple[ConnectorAuditEntry, ...]:
        return self._audit_trail

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_enabled(self) -> bool:
        return self._status == ConnectorStatus.ENABLED

    @property
    def is_archived(self) -> bool:
        return self._status == ConnectorStatus.ARCHIVED

    @property
    def has_running_discovery(self) -> bool:
        return any(j.status == DiscoveryJobStatus.RUNNING for j in self._discovery_history)

    @property
    def has_running_sync(self) -> bool:
        return any(j.status == SyncJobStatus.RUNNING for j in self._sync_history)

    @property
    def last_discovery(self) -> DiscoveryJobRecord | None:
        return self._discovery_history[-1] if self._discovery_history else None

    @property
    def last_sync(self) -> SyncJobRecord | None:
        return self._sync_history[-1] if self._sync_history else None

    @property
    def total_assets_discovered(self) -> int:
        return sum(j.assets_discovered for j in self._discovery_history if j.succeeded)

    # ─── Lifecycle transitions ─────────────────────────────────────────────────

    def configure(
        self,
        config: ConnectorConfiguration,
        credential_ref: ConnectorCredentialReference | None = None,
        actor_id: str = "",
    ) -> None:
        """Apply configuration and advance to CONFIGURED."""
        self._require_not_archived()
        self._transition_to(ConnectorStatus.CONFIGURED)
        self._config = config
        if credential_ref is not None:
            self._credential_ref = credential_ref
        self._append_audit("configured", actor_id, f"base_url={config.base_url}")
        self._touch()
        self._events.append(
            ConnectorConfigured(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                base_url=config.base_url,
            )
        )

    def mark_validated(self, latency_ms: float = 0.0, actor_id: str = "") -> None:
        """Advance to VALIDATED after successful credential/config check."""
        self._require_not_archived()
        self._transition_to(ConnectorStatus.VALIDATED)
        self._health = ConnectorHealth.healthy(latency_ms)
        self._append_audit("validated", actor_id)
        self._touch()
        self._events.append(
            ConnectorValidated(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                latency_ms=latency_ms,
            )
        )

    def enable(self, actor_id: str = "") -> None:
        """Enable the connector for discovery and sync."""
        self._require_not_archived()
        self._transition_to(ConnectorStatus.ENABLED)
        self._append_audit("enabled", actor_id)
        self._touch()
        self._events.append(
            ConnectorEnabled(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                actor_id=actor_id,
            )
        )

    def disable(self, reason: str = "", actor_id: str = "") -> None:
        """Disable the connector (can be re-enabled)."""
        self._require_not_archived()
        self._transition_to(ConnectorStatus.DISABLED)
        self._append_audit("disabled", actor_id, reason)
        self._touch()
        self._events.append(
            ConnectorDisabled(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                reason=reason,
                actor_id=actor_id,
            )
        )

    def archive(self, reason: str = "", actor_id: str = "") -> None:
        """Archive the connector. Terminal — cannot be reversed."""
        if self._status == ConnectorStatus.ARCHIVED:
            return
        allowed = _LIFECYCLE_TRANSITIONS[self._status]
        if ConnectorStatus.ARCHIVED not in allowed:
            raise InvalidConnectorTransitionError(self._status.value, "archived")
        self._status = ConnectorStatus.ARCHIVED
        self._append_audit("archived", actor_id, reason)
        self._touch()
        self._events.append(
            ConnectorArchived(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                reason=reason,
                actor_id=actor_id,
            )
        )

    # ─── Credential management ─────────────────────────────────────────────────

    def update_credential_reference(
        self, credential_ref: ConnectorCredentialReference, actor_id: str = ""
    ) -> None:
        """Update the credential reference (e.g. after key rotation)."""
        self._require_not_archived()
        self._credential_ref = credential_ref
        self._append_audit("credential_updated", actor_id, credential_ref.reference_id)
        self._touch()
        self._events.append(
            CredentialReferenceUpdated(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                reference_id=credential_ref.reference_id,
                credential_type=credential_ref.credential_type.value,
            )
        )

    # ─── Health management ─────────────────────────────────────────────────────

    def update_health(self, new_health: ConnectorHealth) -> None:
        """Update connector health from a health-check result."""
        old_status = self._health.status
        self._health = new_health
        self._touch()
        if old_status != new_health.status:
            self._events.append(
                ConnectorHealthUpdated(
                    organization_id=str(self._organization_id),
                    connector_id=str(self._id),
                    old_health_status=old_status.value,
                    new_health_status=new_health.status.value,
                    consecutive_failures=new_health.consecutive_failures,
                )
            )

    # ─── Discovery job management ──────────────────────────────────────────────

    def start_discovery_job(
        self,
        job_id: str,
        filters: tuple[tuple[str, str], ...] = (),
    ) -> DiscoveryJobRecord:
        """Record that a discovery job has started."""
        self._require_enabled()
        if self.has_running_discovery:
            raise DiscoveryJobConflictError(str(self._id))
        record = DiscoveryJobRecord(
            job_id=job_id,
            status=DiscoveryJobStatus.RUNNING,
            started_at_iso=datetime.now(UTC).isoformat(),
            filters=filters,
        )
        self._discovery_history = (*self._discovery_history, record)
        self._touch()
        self._events.append(
            DiscoveryJobStarted(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                job_id=job_id,
                filters=filters,
            )
        )
        return record

    def complete_discovery_job(
        self,
        job_id: str,
        assets_discovered: int,
        assets_normalized: int,
        assets_failed: int,
    ) -> None:
        """Mark a running discovery job as completed."""
        self._update_discovery_job(
            job_id,
            DiscoveryJobStatus.COMPLETED,
            assets_discovered=assets_discovered,
            assets_normalized=assets_normalized,
            assets_failed=assets_failed,
        )
        completed_record = next(
            (j for j in self._discovery_history if j.job_id == job_id), None
        )
        self._events.append(
            DiscoveryJobCompleted(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                job_id=job_id,
                assets_discovered=assets_discovered,
                assets_normalized=assets_normalized,
                assets_failed=assets_failed,
                duration_seconds=completed_record.duration_seconds if completed_record else 0.0,
            )
        )

    def fail_discovery_job(self, job_id: str, error_message: str) -> None:
        """Mark a running discovery job as failed."""
        self._update_discovery_job(job_id, DiscoveryJobStatus.FAILED, error_message=error_message)
        self._events.append(
            DiscoveryJobFailed(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                job_id=job_id,
                error_message=error_message,
            )
        )

    # ─── Sync job management ───────────────────────────────────────────────────

    def start_sync_job(self, job_id: str, is_full_sync: bool = False) -> SyncJobRecord:
        """Record that a sync job has started."""
        self._require_enabled()
        if self.has_running_sync:
            raise SyncJobConflictError(str(self._id))
        record = SyncJobRecord(
            job_id=job_id,
            status=SyncJobStatus.RUNNING,
            started_at_iso=datetime.now(UTC).isoformat(),
            is_full_sync=is_full_sync,
        )
        self._sync_history = (*self._sync_history, record)
        self._touch()
        self._events.append(
            SyncJobStarted(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                job_id=job_id,
                is_full_sync=is_full_sync,
            )
        )
        return record

    def complete_sync_job(
        self,
        job_id: str,
        assets_added: int,
        assets_updated: int,
        assets_unchanged: int,
    ) -> None:
        """Mark a running sync job as completed."""
        self._update_sync_job(
            job_id,
            SyncJobStatus.COMPLETED,
            assets_added=assets_added,
            assets_updated=assets_updated,
            assets_unchanged=assets_unchanged,
        )
        self._events.append(
            SyncJobCompleted(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                job_id=job_id,
                assets_added=assets_added,
                assets_updated=assets_updated,
                assets_unchanged=assets_unchanged,
            )
        )

    def fail_sync_job(self, job_id: str, error_message: str) -> None:
        """Mark a running sync job as failed."""
        self._update_sync_job(job_id, SyncJobStatus.FAILED, error_message=error_message)
        self._events.append(
            SyncJobFailed(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                job_id=job_id,
                error_message=error_message,
            )
        )

    # ─── Sync policy ───────────────────────────────────────────────────────────

    def update_sync_policy(self, policy: SynchronizationPolicy, actor_id: str = "") -> None:
        """Update the synchronization policy."""
        self._require_not_archived()
        self._sync_policy = policy
        self._touch()
        self._events.append(
            SyncPolicyChanged(
                organization_id=str(self._organization_id),
                connector_id=str(self._id),
                enabled=policy.enabled,
                cron_expression=policy.cron_expression,
            )
        )

    # ─── Event collection ─────────────────────────────────────────────────────

    def collect_events(self) -> list[ConnectorDomainEvent]:
        """Return and clear pending domain events."""
        events = list(self._events)
        self._events.clear()
        return events

    # ─── Equality ─────────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Connector):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"Connector(id={self._id}, type={self._connector_type.value}, "
            f"status={self._status.value}, org={self._organization_id})"
        )

    # ─── Private helpers ───────────────────────────────────────────────────────

    def _require_not_archived(self) -> None:
        if self._status == ConnectorStatus.ARCHIVED:
            raise ConnectorAlreadyArchivedError(str(self._id))

    def _require_enabled(self) -> None:
        if self._status != ConnectorStatus.ENABLED:
            raise ConnectorNotEnabledError(str(self._id), self._status.value)

    def _transition_to(self, target: ConnectorStatus) -> None:
        allowed = _LIFECYCLE_TRANSITIONS[self._status]
        if target not in allowed:
            raise InvalidConnectorTransitionError(self._status.value, target.value)
        self._status = target

    def _append_audit(self, event_type: str, actor_id: str, details: str = "") -> None:
        entry = ConnectorAuditEntry.record(event_type, actor_id, details)
        self._audit_trail = (*self._audit_trail, entry)

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _update_discovery_job(
        self,
        job_id: str,
        new_status: DiscoveryJobStatus,
        *,
        assets_discovered: int = 0,
        assets_normalized: int = 0,
        assets_failed: int = 0,
        error_message: str = "",
    ) -> None:
        updated = []
        found = False
        for record in self._discovery_history:
            if record.job_id == job_id and record.status == DiscoveryJobStatus.RUNNING:
                updated.append(DiscoveryJobRecord(
                    job_id=record.job_id,
                    status=new_status,
                    started_at_iso=record.started_at_iso,
                    completed_at_iso=datetime.now(UTC).isoformat(),
                    assets_discovered=assets_discovered,
                    assets_normalized=assets_normalized,
                    assets_failed=assets_failed,
                    error_message=error_message,
                    filters=record.filters,
                ))
                found = True
            else:
                updated.append(record)
        if found:
            self._discovery_history = tuple(updated)
            self._touch()

    def _update_sync_job(
        self,
        job_id: str,
        new_status: SyncJobStatus,
        *,
        assets_added: int = 0,
        assets_updated: int = 0,
        assets_unchanged: int = 0,
        error_message: str = "",
    ) -> None:
        updated = []
        found = False
        for record in self._sync_history:
            if record.job_id == job_id and record.status == SyncJobStatus.RUNNING:
                updated.append(SyncJobRecord(
                    job_id=record.job_id,
                    status=new_status,
                    started_at_iso=record.started_at_iso,
                    completed_at_iso=datetime.now(UTC).isoformat(),
                    assets_added=assets_added,
                    assets_updated=assets_updated,
                    assets_unchanged=assets_unchanged,
                    error_message=error_message,
                    is_full_sync=record.is_full_sync,
                ))
                found = True
            else:
                updated.append(record)
        if found:
            self._sync_history = tuple(updated)
            self._touch()
