"""Domain ↔ SQLAlchemy mappings for runtime visibility aggregates."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from redforge.domain.cloud_security.runtime.entities import (
    RuntimeArtifact,
    RuntimeCorrelationReference,
    RuntimeEvidence,
    RuntimeMetadata,
)
from redforge.domain.cloud_security.runtime.event import CloudRuntimeEvent
from redforge.domain.cloud_security.runtime.process import (
    RuntimeFileActivity,
    RuntimeFileActivityId,
    RuntimeNetworkConnection,
    RuntimeNetworkConnectionId,
    RuntimeProcess,
    RuntimeProcessId,
)
from redforge.domain.cloud_security.runtime.session import (
    RuntimeExecutionContext,
    RuntimeExecutionContextId,
    RuntimeIdentitySession,
    RuntimeIdentitySessionId,
)
from redforge.domain.cloud_security.runtime.value_objects import (
    CloudRuntimeEventId,
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
from redforge.infrastructure.database.models.cloud_security import (
    CloudRuntimeEventModel,
    RuntimeArtifactModel,
    RuntimeExecutionContextModel,
    RuntimeFileActivityModel,
    RuntimeIdentitySessionModel,
    RuntimeNetworkConnectionModel,
    RuntimeProcessModel,
)


def event_to_model(
    event: CloudRuntimeEvent, existing: CloudRuntimeEventModel | None = None
) -> CloudRuntimeEventModel:
    row = existing or CloudRuntimeEventModel(id=event.id.value, event_time=event.event_time)
    row.organization_id = str(event.organization_id)
    row.cloud_account_id = event.cloud_account_id.value
    row.event_type = event.event_type.value
    row.source = event.source.value
    row.severity = event.severity.value
    row.outcome = event.outcome.value
    row.event_time = event.event_time
    row.ingested_at = event.ingested_at
    row.provider_event_id = event.metadata.provider_event_id
    row.identity = event.identity.to_dict()
    row.host = event.host.to_dict()
    row.container = event.container.to_dict()
    row.metadata_ = event.metadata.to_dict()
    row.correlation_refs = event.correlation_refs.to_dict()
    row.correlation_links = [link.to_dict() for link in event.correlation_links]
    row.artifacts = [art.to_dict() for art in event.artifacts]
    row.evidence = [ev.to_dict() for ev in event.evidence]
    row.raw_payload = dict(event.raw_payload)
    row.source_ip = event.source_ip
    row.target_resource = event.target_resource
    row.created_at = event.created_at
    row.updated_at = event.updated_at
    row.row_version = event.row_version
    return row


def event_from_model(row: CloudRuntimeEventModel) -> CloudRuntimeEvent:
    links = tuple(
        RuntimeCorrelationReference.from_dict(item)
        for item in (row.correlation_links or [])
        if isinstance(item, dict)
    )
    artifacts = tuple(
        RuntimeArtifact.from_dict(item)
        for item in (row.artifacts or [])
        if isinstance(item, dict)
    )
    evidence = tuple(
        RuntimeEvidence.from_dict(item) for item in (row.evidence or []) if isinstance(item, dict)
    )
    return CloudRuntimeEvent(
        id=CloudRuntimeEventId(row.id),
        organization_id=OrganizationId(row.organization_id),
        cloud_account_id=CloudAccountId(row.cloud_account_id),
        event_type=RuntimeEventType(row.event_type),
        source=RuntimeSource(row.source),
        severity=RuntimeSeverity(row.severity),
        outcome=EventOutcome(row.outcome),
        event_time=row.event_time,
        ingested_at=row.ingested_at,
        identity=RuntimeIdentity.from_dict(row.identity),
        host=RuntimeHost.from_dict(row.host),
        container=RuntimeContainer.from_dict(row.container),
        metadata=RuntimeMetadata.from_dict(row.metadata_),
        correlation_refs=RuntimeCorrelationRefs.from_dict(row.correlation_refs),
        correlation_links=links,
        artifacts=artifacts,
        evidence=evidence,
        raw_payload=dict(row.raw_payload or {}),
        source_ip=row.source_ip or "",
        target_resource=row.target_resource or "",
        created_at=row.created_at,
        updated_at=row.updated_at,
        row_version=row.row_version,
    )


def process_to_model(
    process: RuntimeProcess, existing: RuntimeProcessModel | None = None
) -> RuntimeProcessModel:
    row = existing or RuntimeProcessModel(id=process.id.value)
    row.organization_id = str(process.organization_id)
    row.runtime_event_id = process.runtime_event_id.value
    row.process_name = process.process_name
    row.executable_path = process.executable_path
    row.pid = process.pid
    row.parent_pid = process.parent_pid
    row.command_line = process.command_line
    row.user_name = process.user_name
    row.created_at = process.created_at
    row.row_version = process.row_version
    return row


def process_from_model(row: RuntimeProcessModel) -> RuntimeProcess:
    return RuntimeProcess(
        id=RuntimeProcessId(row.id),
        organization_id=OrganizationId(row.organization_id),
        runtime_event_id=CloudRuntimeEventId(row.runtime_event_id),
        process_name=row.process_name,
        executable_path=row.executable_path or "",
        pid=row.pid,
        parent_pid=row.parent_pid,
        command_line=row.command_line or "",
        user_name=row.user_name or "",
        created_at=row.created_at,
        row_version=row.row_version,
    )


def connection_to_model(
    connection: RuntimeNetworkConnection,
    existing: RuntimeNetworkConnectionModel | None = None,
) -> RuntimeNetworkConnectionModel:
    row = existing or RuntimeNetworkConnectionModel(id=connection.id.value)
    row.organization_id = str(connection.organization_id)
    row.runtime_event_id = connection.runtime_event_id.value
    row.direction = connection.direction.value
    row.protocol = connection.protocol.value
    row.local_address = connection.local_address
    row.local_port = connection.local_port
    row.remote_address = connection.remote_address
    row.remote_port = connection.remote_port
    row.created_at = connection.created_at
    row.row_version = connection.row_version
    return row


def connection_from_model(row: RuntimeNetworkConnectionModel) -> RuntimeNetworkConnection:
    return RuntimeNetworkConnection(
        id=RuntimeNetworkConnectionId(row.id),
        organization_id=OrganizationId(row.organization_id),
        runtime_event_id=CloudRuntimeEventId(row.runtime_event_id),
        direction=RuntimeDirection(row.direction),
        protocol=RuntimeProtocol(row.protocol),
        local_address=row.local_address or "",
        local_port=row.local_port,
        remote_address=row.remote_address or "",
        remote_port=row.remote_port,
        created_at=row.created_at,
        row_version=row.row_version,
    )


def file_activity_to_model(
    activity: RuntimeFileActivity, existing: RuntimeFileActivityModel | None = None
) -> RuntimeFileActivityModel:
    row = existing or RuntimeFileActivityModel(id=activity.id.value)
    row.organization_id = str(activity.organization_id)
    row.runtime_event_id = activity.runtime_event_id.value
    row.operation = activity.operation
    row.path = activity.path
    row.file_hash = activity.file_hash
    row.created_at = activity.created_at
    row.row_version = activity.row_version
    return row


def file_activity_from_model(row: RuntimeFileActivityModel) -> RuntimeFileActivity:
    return RuntimeFileActivity(
        id=RuntimeFileActivityId(row.id),
        organization_id=OrganizationId(row.organization_id),
        runtime_event_id=CloudRuntimeEventId(row.runtime_event_id),
        operation=row.operation,
        path=row.path,
        file_hash=row.file_hash or "",
        created_at=row.created_at,
        row_version=row.row_version,
    )


def session_to_model(
    session: RuntimeIdentitySession, existing: RuntimeIdentitySessionModel | None = None
) -> RuntimeIdentitySessionModel:
    row = existing or RuntimeIdentitySessionModel(id=session.id.value)
    row.organization_id = str(session.organization_id)
    row.runtime_event_id = session.runtime_event_id.value
    row.identity = session.identity.to_dict()
    row.session_id = session.session_id
    row.mfa_used = session.mfa_used
    row.source_ip = session.source_ip
    row.user_agent = session.user_agent
    row.created_at = session.created_at
    row.row_version = session.row_version
    return row


def session_from_model(row: RuntimeIdentitySessionModel) -> RuntimeIdentitySession:
    return RuntimeIdentitySession(
        id=RuntimeIdentitySessionId(row.id),
        organization_id=OrganizationId(row.organization_id),
        runtime_event_id=CloudRuntimeEventId(row.runtime_event_id),
        identity=RuntimeIdentity.from_dict(row.identity),
        session_id=row.session_id or "",
        mfa_used=bool(row.mfa_used),
        source_ip=row.source_ip or "",
        user_agent=row.user_agent or "",
        created_at=row.created_at,
        row_version=row.row_version,
    )


def context_to_model(
    context: RuntimeExecutionContext, existing: RuntimeExecutionContextModel | None = None
) -> RuntimeExecutionContextModel:
    row = existing or RuntimeExecutionContextModel(id=context.id.value)
    row.organization_id = str(context.organization_id)
    row.runtime_event_id = context.runtime_event_id.value
    row.process_id = context.process_id
    row.container_id = context.container_id
    row.host_id = context.host_id
    row.workload_ref = context.workload_ref
    row.environment = dict(context.environment)
    row.created_at = context.created_at
    row.row_version = context.row_version
    return row


def context_from_model(row: RuntimeExecutionContextModel) -> RuntimeExecutionContext:
    return RuntimeExecutionContext(
        id=RuntimeExecutionContextId(row.id),
        organization_id=OrganizationId(row.organization_id),
        runtime_event_id=CloudRuntimeEventId(row.runtime_event_id),
        process_id=row.process_id,
        container_id=row.container_id or "",
        host_id=row.host_id or "",
        workload_ref=row.workload_ref or "",
        environment={str(k): str(v) for k, v in (row.environment or {}).items()},
        created_at=row.created_at,
        row_version=row.row_version,
    )


def artifact_to_model(
    *,
    organization_id: OrganizationId,
    runtime_event_id: UUID | str,
    artifact: RuntimeArtifact,
    existing: RuntimeArtifactModel | None = None,
) -> RuntimeArtifactModel:
    if isinstance(runtime_event_id, UUID):
        event_uuid = runtime_event_id
    else:
        event_uuid = UUID(str(runtime_event_id))
    row = existing or RuntimeArtifactModel(id=uuid4())
    row.organization_id = str(organization_id)
    row.runtime_event_id = event_uuid
    row.artifact_id = artifact.artifact_id
    row.artifact_type = artifact.artifact_type
    row.name = artifact.name
    row.digest = artifact.digest
    row.path = artifact.path
    row.size_bytes = artifact.size_bytes
    row.payload = artifact.to_dict()
    row.created_at = datetime.now(UTC)
    row.row_version = 1
    return row


def artifact_from_model(row: RuntimeArtifactModel) -> RuntimeArtifact:
    return RuntimeArtifact(
        artifact_id=row.artifact_id,
        artifact_type=row.artifact_type,
        name=row.name,
        digest=row.digest or "",
        path=row.path or "",
        size_bytes=row.size_bytes or 0,
    )
