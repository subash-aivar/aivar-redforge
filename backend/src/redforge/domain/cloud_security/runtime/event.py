"""CloudRuntimeEvent aggregate — normalized runtime telemetry unit."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from redforge.domain.cloud_security.runtime.entities import (
    RuntimeArtifact,
    RuntimeCorrelationReference,
    RuntimeEvidence,
    RuntimeMetadata,
)
from redforge.domain.cloud_security.runtime.events import (
    RuntimeArtifactObserved,
    RuntimeDomainEvent,
    RuntimeEventIngested,
    RuntimeIdentityObserved,
)
from redforge.domain.cloud_security.runtime.exceptions import InvalidRuntimeArgumentError
from redforge.domain.cloud_security.runtime.value_objects import (
    CloudRuntimeEventId,
    EventOutcome,
    RuntimeContainer,
    RuntimeCorrelationRefs,
    RuntimeEventType,
    RuntimeHost,
    RuntimeIdentity,
    RuntimeSeverity,
    RuntimeSource,
)
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId

_MAX_RAW_PAYLOAD_BYTES = 64 * 1024


def _truncate_raw_payload(payload: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")
    if len(encoded) <= _MAX_RAW_PAYLOAD_BYTES:
        return dict(payload)
    # Truncate string values until under limit; keep structure.
    truncated: dict[str, Any] = {
        "_truncated": True,
        "_original_bytes": len(encoded),
        "keys": sorted(str(k) for k in payload)[:50],
    }
    summary = json.dumps(truncated, separators=(",", ":")).encode("utf-8")
    if len(summary) > _MAX_RAW_PAYLOAD_BYTES:
        return {"_truncated": True, "_original_bytes": len(encoded)}
    return truncated


@dataclass
class CloudRuntimeEvent:
    id: CloudRuntimeEventId
    organization_id: OrganizationId
    cloud_account_id: CloudAccountId
    event_type: RuntimeEventType
    source: RuntimeSource
    severity: RuntimeSeverity
    outcome: EventOutcome
    event_time: datetime
    ingested_at: datetime
    identity: RuntimeIdentity
    host: RuntimeHost
    container: RuntimeContainer
    metadata: RuntimeMetadata
    correlation_refs: RuntimeCorrelationRefs
    correlation_links: tuple[RuntimeCorrelationReference, ...]
    artifacts: tuple[RuntimeArtifact, ...]
    evidence: tuple[RuntimeEvidence, ...]
    raw_payload: dict[str, Any]
    source_ip: str
    target_resource: str
    created_at: datetime
    updated_at: datetime
    row_version: int = 1
    _pending_events: list[RuntimeDomainEvent] = field(default_factory=list, repr=False)

    @classmethod
    def ingest(
        cls,
        *,
        organization_id: OrganizationId,
        cloud_account_id: CloudAccountId,
        event_type: RuntimeEventType | str,
        source: RuntimeSource | str,
        event_time: datetime,
        metadata: RuntimeMetadata,
        outcome: EventOutcome | str = EventOutcome.UNKNOWN,
        severity: RuntimeSeverity | str = RuntimeSeverity.INFO,
        identity: RuntimeIdentity | None = None,
        host: RuntimeHost | None = None,
        container: RuntimeContainer | None = None,
        correlation_refs: RuntimeCorrelationRefs | None = None,
        correlation_links: list[RuntimeCorrelationReference] | None = None,
        artifacts: list[RuntimeArtifact] | None = None,
        evidence: list[RuntimeEvidence] | None = None,
        raw_payload: dict[str, Any] | None = None,
        source_ip: str = "",
        target_resource: str = "",
        now: datetime | None = None,
        event_id: CloudRuntimeEventId | None = None,
    ) -> CloudRuntimeEvent:
        if not metadata.provider_event_id.strip():
            raise InvalidRuntimeArgumentError("provider_event_id", "required")
        if not metadata.event_name.strip():
            raise InvalidRuntimeArgumentError("event_name", "required")
        etype = (
            event_type
            if isinstance(event_type, RuntimeEventType)
            else RuntimeEventType(str(event_type).upper())
        )
        src = source if isinstance(source, RuntimeSource) else RuntimeSource(str(source).upper())
        out = outcome if isinstance(outcome, EventOutcome) else EventOutcome(str(outcome).upper())
        sev = (
            severity
            if isinstance(severity, RuntimeSeverity)
            else RuntimeSeverity(str(severity).upper())
        )
        ts = now or datetime.now(UTC)
        eid = event_id or CloudRuntimeEventId.new()
        ident = identity or RuntimeIdentity()
        refs = correlation_refs or RuntimeCorrelationRefs(
            cloud_account_id=cloud_account_id.value,
            organization_id=str(organization_id),
        )
        event = cls(
            id=eid,
            organization_id=organization_id,
            cloud_account_id=cloud_account_id,
            event_type=etype,
            source=src,
            severity=sev,
            outcome=out,
            event_time=event_time,
            ingested_at=ts,
            identity=ident,
            host=host or RuntimeHost(),
            container=container or RuntimeContainer(),
            metadata=metadata,
            correlation_refs=refs,
            correlation_links=tuple(correlation_links or ()),
            artifacts=tuple(artifacts or ()),
            evidence=tuple(evidence or ()),
            raw_payload=_truncate_raw_payload(dict(raw_payload or {})),
            source_ip=(source_ip or "")[:128],
            target_resource=(target_resource or "")[:512],
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )
        event._pending_events.append(
            RuntimeEventIngested(
                occurred_at=ts,
                organization_id=str(organization_id),
                event_id=eid.value,
                event_type=etype.value,
                source=src.value,
                provider_event_id=metadata.provider_event_id,
            )
        )
        if ident.principal_id:
            event._pending_events.append(
                RuntimeIdentityObserved(
                    occurred_at=ts,
                    organization_id=str(organization_id),
                    event_id=eid.value,
                    principal_id=ident.principal_id,
                    principal_type=ident.principal_type,
                )
            )
        for art in event.artifacts:
            event._pending_events.append(
                RuntimeArtifactObserved(
                    occurred_at=ts,
                    organization_id=str(organization_id),
                    event_id=eid.value,
                    artifact_id=art.artifact_id,
                    artifact_type=art.artifact_type,
                    name=art.name,
                )
            )
        return event

    def bind_correlation_refs(self, refs: RuntimeCorrelationRefs) -> None:
        self.correlation_refs = refs
        self.updated_at = datetime.now(UTC)
        self.row_version += 1

    def cspm_snapshot(self) -> dict[str, Any]:
        """Reusable snapshot for PolicyEvaluationEngine (no second policy engine)."""
        return {
            "asset_type": "RUNTIME_EVENT",
            "event_type": self.event_type.value,
            "source": self.source.value,
            "severity": self.severity.value,
            "outcome": self.outcome.value,
            "event_name": self.metadata.event_name,
            "source_ip": self.source_ip,
            "target_resource": self.target_resource,
            "identity": self.identity.to_dict(),
            "host": self.host.to_dict(),
            "container": self.container.to_dict(),
            "normalized_config": {
                "event_type": self.event_type.value,
                "source": self.source.value,
                "outcome": self.outcome.value,
                "event_name": self.metadata.event_name,
                "source_ip": self.source_ip,
                "target_resource": self.target_resource,
                "principal_id": self.identity.principal_id,
                "principal_type": self.identity.principal_type,
                "region": self.metadata.region or self.host.region,
                "attributes": dict(self.metadata.attributes),
            },
        }

    def pop_events(self) -> list[RuntimeDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
