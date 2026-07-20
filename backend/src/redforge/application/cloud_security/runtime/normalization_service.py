"""Raw provider payloads → CloudRuntimeEvent (+ optional related aggregates)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from redforge.domain.cloud_security.ports import RawRuntimeEvent
from redforge.domain.cloud_security.runtime.entities import (
    RuntimeArtifact,
    RuntimeMetadata,
)
from redforge.domain.cloud_security.runtime.event import CloudRuntimeEvent
from redforge.domain.cloud_security.runtime.process import (
    RuntimeFileActivity,
    RuntimeNetworkConnection,
    RuntimeProcess,
)
from redforge.domain.cloud_security.runtime.session import (
    RuntimeExecutionContext,
    RuntimeIdentitySession,
)
from redforge.domain.cloud_security.runtime.value_objects import (
    EventOutcome,
    RuntimeContainer,
    RuntimeCorrelationRefs,
    RuntimeDirection,
    RuntimeEventType,
    RuntimeHost,
    RuntimeIdentity,
    RuntimeProtocol,
    RuntimeSeverity,
    RuntimeSource,
)
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId
from redforge.infrastructure.cloud_security.runtime.adapters.aws_cloudtrail import (
    normalize_cloudtrail_record,
)
from redforge.infrastructure.cloud_security.runtime.adapters.azure_activity import (
    normalize_azure_activity,
)
from redforge.infrastructure.cloud_security.runtime.adapters.gcp_audit import (
    normalize_gcp_audit,
)
from redforge.infrastructure.cloud_security.runtime.adapters.kubernetes_audit import (
    normalize_kubernetes_audit,
)


@dataclass(frozen=True, slots=True)
class NormalizedRuntimeBundle:
    event: CloudRuntimeEvent
    process: RuntimeProcess | None = None
    connection: RuntimeNetworkConnection | None = None
    file_activity: RuntimeFileActivity | None = None
    identity_session: RuntimeIdentitySession | None = None
    execution_context: RuntimeExecutionContext | None = None


def _parse_time(raw: object) -> datetime:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if isinstance(raw, str) and raw.strip():
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return datetime.now(UTC)


def _as_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _infer_source(payload: dict[str, Any], explicit: str | None = None) -> RuntimeSource:
    if explicit:
        try:
            return RuntimeSource(explicit.upper())
        except ValueError:
            pass
    raw_source = str(payload.get("source") or "").upper()
    if raw_source:
        try:
            return RuntimeSource(raw_source)
        except ValueError:
            pass
    provider = str(payload.get("provider") or "").lower()
    if provider == "aws" or "eventName" in payload or "eventSource" in payload:
        return RuntimeSource.CLOUDTRAIL
    if provider == "azure" or "operationName" in payload or "eventDataId" in payload:
        return RuntimeSource.AZURE_ACTIVITY
    if provider == "gcp" or "protoPayload" in payload:
        return RuntimeSource.GCP_AUDIT
    if provider == "kubernetes" or "auditID" in payload or "objectRef" in payload:
        return RuntimeSource.KUBERNETES_AUDIT
    return RuntimeSource.GENERIC


def _raw_or_payload(payload: dict[str, Any]) -> dict[str, Any]:
    raw = payload.get("raw")
    return raw if isinstance(raw, dict) else payload


def _canonicalize(payload: dict[str, Any], source: RuntimeSource) -> dict[str, Any]:
    if "event_id" in payload and "event_name" in payload and "identity" in payload:
        return payload
    if source == RuntimeSource.CLOUDTRAIL:
        return normalize_cloudtrail_record(_raw_or_payload(payload))
    if source == RuntimeSource.AZURE_ACTIVITY:
        return normalize_azure_activity(_raw_or_payload(payload))
    if source == RuntimeSource.GCP_AUDIT:
        return normalize_gcp_audit(_raw_or_payload(payload))
    if source == RuntimeSource.KUBERNETES_AUDIT:
        return normalize_kubernetes_audit(_raw_or_payload(payload))
    return payload


def _infer_event_type(canonical: dict[str, Any], source: RuntimeSource) -> RuntimeEventType:
    name = str(canonical.get("event_name") or "").lower()
    if source == RuntimeSource.KUBERNETES_AUDIT and "exec" in name:
        return RuntimeEventType.CONTAINER_EXECUTION
    if any(token in name for token in ("consolelogin", "signin", "login", "session")):
        return RuntimeEventType.IDENTITY_SESSION
    if any(token in name for token in ("connect", "network", "authorizeSecurityGroup")):
        return RuntimeEventType.NETWORK_CONNECTION
    if any(token in name for token in ("putobject", "getobject", "write", "file")):
        return RuntimeEventType.FILE_ACTIVITY
    if any(token in name for token in ("run", "exec", "process", "startinstances")):
        return RuntimeEventType.PROCESS_EXECUTION
    if source in {
        RuntimeSource.CLOUDTRAIL,
        RuntimeSource.AZURE_ACTIVITY,
        RuntimeSource.GCP_AUDIT,
        RuntimeSource.KUBERNETES_AUDIT,
    }:
        return RuntimeEventType.API_ACTIVITY
    return RuntimeEventType.UNKNOWN


def _infer_outcome(canonical: dict[str, Any]) -> EventOutcome:
    error = str(canonical.get("error_code") or "")
    status = str(canonical.get("status") or "").lower()
    code = canonical.get("response_code")
    if error or status in {"failed", "failure"} or (isinstance(code, int) and code >= 400):
        return EventOutcome.FAILURE
    if status in {"succeeded", "success"} or (isinstance(code, int) and 200 <= code < 400):
        return EventOutcome.SUCCESS
    return EventOutcome.UNKNOWN


class RuntimeNormalizationService:
    def normalize(
        self,
        raw: dict[str, Any] | RawRuntimeEvent,
        *,
        organization_id: OrganizationId | str,
        cloud_account_id: CloudAccountId | UUID,
        source: str | None = None,
    ) -> NormalizedRuntimeBundle:
        if isinstance(raw, RawRuntimeEvent):
            payload = dict(raw.payload)
            if raw.source and not source:
                source = raw.source
            if raw.event_id and "event_id" not in payload:
                payload["event_id"] = raw.event_id
            if "event_time" not in payload:
                payload["event_time"] = raw.event_time.isoformat()
        else:
            payload = dict(raw)

        org = (
            organization_id
            if isinstance(organization_id, OrganizationId)
            else OrganizationId(str(organization_id))
        )
        account = (
            cloud_account_id
            if isinstance(cloud_account_id, CloudAccountId)
            else CloudAccountId(cloud_account_id)
        )
        src = _infer_source(payload, source)
        canonical = _canonicalize(payload, src)
        identity_data = _as_dict(canonical.get("identity"))
        host_data = _as_dict(canonical.get("host"))
        container_data = _as_dict(canonical.get("container"))
        provider_event_id = str(
            canonical.get("event_id")
            or payload.get("event_id")
            or canonical.get("provider_event_id")
            or ""
        )
        event_name = str(canonical.get("event_name") or payload.get("event_name") or "unknown")
        attrs: list[tuple[str, str]] = []
        for key in ("event_source", "aws_region", "severity", "status"):
            if canonical.get(key):
                attrs.append((key, str(canonical[key])))
        metadata = RuntimeMetadata(
            provider_event_id=provider_event_id or event_name,
            event_name=event_name,
            region=str(
                canonical.get("region")
                or canonical.get("aws_region")
                or host_data.get("region")
                or ""
            ),
            user_agent=str(canonical.get("user_agent") or ""),
            request_id=str(canonical.get("request_id") or ""),
            attributes=tuple(attrs),
        )
        artifacts_raw = canonical.get("artifacts") or []
        artifacts: list[RuntimeArtifact] = []
        if isinstance(artifacts_raw, list):
            for item in artifacts_raw:
                if isinstance(item, dict):
                    artifacts.append(RuntimeArtifact.from_dict(item))

        event = CloudRuntimeEvent.ingest(
            organization_id=org,
            cloud_account_id=account,
            event_type=_infer_event_type(canonical, src),
            source=src,
            event_time=_parse_time(canonical.get("event_time") or payload.get("event_time")),
            metadata=metadata,
            outcome=_infer_outcome(canonical),
            severity=RuntimeSeverity.INFO,
            identity=RuntimeIdentity.from_dict(identity_data),
            host=RuntimeHost.from_dict(host_data),
            container=RuntimeContainer.from_dict(container_data),
            correlation_refs=RuntimeCorrelationRefs(
                cloud_account_id=account.value,
                organization_id=str(org),
            ),
            artifacts=artifacts,
            raw_payload=dict(canonical.get("raw") or payload),
            source_ip=str(canonical.get("source_ip") or ""),
            target_resource=str(
                canonical.get("target_resource")
                or canonical.get("resource_id")
                or canonical.get("resource_name")
                or ""
            ),
        )

        process: RuntimeProcess | None = None
        connection: RuntimeNetworkConnection | None = None
        file_activity: RuntimeFileActivity | None = None
        identity_session: RuntimeIdentitySession | None = None
        execution_context: RuntimeExecutionContext | None = None

        process_data = _as_dict(canonical.get("process"))
        wants_process = bool(process_data.get("process_name")) or (
            event.event_type == RuntimeEventType.PROCESS_EXECUTION
        )
        if wants_process:
            name = str(process_data.get("process_name") or event.metadata.event_name)
            pid_raw = process_data.get("pid")
            parent_raw = process_data.get("parent_pid")
            process = RuntimeProcess.observe(
                organization_id=org,
                runtime_event_id=event.id,
                process_name=name,
                executable_path=str(process_data.get("executable_path") or ""),
                pid=int(pid_raw) if pid_raw is not None else None,
                parent_pid=int(parent_raw) if parent_raw is not None else None,
                command_line=str(process_data.get("command_line") or ""),
                user_name=str(
                    process_data.get("user_name") or event.identity.principal_name
                ),
            )

        conn_data = _as_dict(canonical.get("network") or canonical.get("connection"))
        if conn_data or event.event_type == RuntimeEventType.NETWORK_CONNECTION:
            local_port_raw = conn_data.get("local_port")
            remote_port_raw = conn_data.get("remote_port")
            connection = RuntimeNetworkConnection.observe(
                organization_id=org,
                runtime_event_id=event.id,
                direction=str(
                    conn_data.get("direction") or RuntimeDirection.UNKNOWN.value
                ),
                protocol=str(conn_data.get("protocol") or RuntimeProtocol.UNKNOWN.value),
                local_address=str(conn_data.get("local_address") or ""),
                local_port=int(local_port_raw) if local_port_raw is not None else None,
                remote_address=str(conn_data.get("remote_address") or event.source_ip or ""),
                remote_port=int(remote_port_raw) if remote_port_raw is not None else None,
            )

        file_data = _as_dict(canonical.get("file"))
        if file_data.get("path") and file_data.get("operation"):
            file_activity = RuntimeFileActivity.observe(
                organization_id=org,
                runtime_event_id=event.id,
                operation=str(file_data["operation"]),
                path=str(file_data["path"]),
                file_hash=str(file_data.get("file_hash") or ""),
            )

        if event.event_type == RuntimeEventType.IDENTITY_SESSION and (
            event.identity.principal_id or event.identity.principal_name
        ):
            identity_session = RuntimeIdentitySession.observe(
                organization_id=org,
                runtime_event_id=event.id,
                identity=event.identity,
                session_id=str(canonical.get("session_id") or ""),
                mfa_used=bool(canonical.get("mfa_used")),
                source_ip=event.source_ip,
                user_agent=event.metadata.user_agent,
            )

        if process is not None or event.container.container_id or event.host.host_id:
            execution_context = RuntimeExecutionContext.create(
                organization_id=org,
                runtime_event_id=event.id,
                process_id=process.id.value if process is not None else None,
                container_id=event.container.container_id,
                host_id=event.host.host_id,
                workload_ref=event.container.workload_name or event.container.pod_name,
            )

        return NormalizedRuntimeBundle(
            event=event,
            process=process,
            connection=connection,
            file_activity=file_activity,
            identity_session=identity_session,
            execution_context=execution_context,
        )

    def normalize_many(
        self,
        raw_events: list[dict[str, Any] | RawRuntimeEvent],
        *,
        organization_id: OrganizationId | str,
        cloud_account_id: CloudAccountId | UUID,
        source: str | None = None,
    ) -> list[NormalizedRuntimeBundle]:
        return [
            self.normalize(
                raw,
                organization_id=organization_id,
                cloud_account_id=cloud_account_id,
                source=source,
            )
            for raw in raw_events
        ]
