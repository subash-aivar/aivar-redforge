"""RuntimeIdentitySession and RuntimeExecutionContext aggregates."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from redforge.domain.cloud_security.runtime.exceptions import InvalidRuntimeArgumentError
from redforge.domain.cloud_security.runtime.value_objects import (
    CloudRuntimeEventId,
    RuntimeIdentity,
)
from redforge.domain.cloud_security.value_objects import OrganizationId


@dataclass(frozen=True, slots=True)
class RuntimeIdentitySessionId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> RuntimeIdentitySessionId:
        return cls(uuid4())


@dataclass
class RuntimeIdentitySession:
    id: RuntimeIdentitySessionId
    organization_id: OrganizationId
    runtime_event_id: CloudRuntimeEventId
    identity: RuntimeIdentity
    session_id: str
    mfa_used: bool
    source_ip: str
    user_agent: str
    created_at: datetime
    row_version: int = 1

    @classmethod
    def observe(
        cls,
        *,
        organization_id: OrganizationId,
        runtime_event_id: CloudRuntimeEventId,
        identity: RuntimeIdentity,
        session_id: str = "",
        mfa_used: bool = False,
        source_ip: str = "",
        user_agent: str = "",
        now: datetime | None = None,
        session_record_id: RuntimeIdentitySessionId | None = None,
    ) -> RuntimeIdentitySession:
        if not identity.principal_id and not identity.principal_name:
            raise InvalidRuntimeArgumentError("identity", "principal required")
        ts = now or datetime.now(UTC)
        return cls(
            id=session_record_id or RuntimeIdentitySessionId.new(),
            organization_id=organization_id,
            runtime_event_id=runtime_event_id,
            identity=identity,
            session_id=(session_id or "")[:256],
            mfa_used=mfa_used,
            source_ip=(source_ip or "")[:128],
            user_agent=(user_agent or "")[:512],
            created_at=ts,
            row_version=1,
        )


@dataclass(frozen=True, slots=True)
class RuntimeExecutionContextId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> RuntimeExecutionContextId:
        return cls(uuid4())


@dataclass
class RuntimeExecutionContext:
    """Execution context linking process/container/host for a runtime event."""

    id: RuntimeExecutionContextId
    organization_id: OrganizationId
    runtime_event_id: CloudRuntimeEventId
    process_id: UUID | None
    container_id: str
    host_id: str
    workload_ref: str
    environment: dict[str, str]
    created_at: datetime
    row_version: int = 1

    @classmethod
    def create(
        cls,
        *,
        organization_id: OrganizationId,
        runtime_event_id: CloudRuntimeEventId,
        process_id: UUID | None = None,
        container_id: str = "",
        host_id: str = "",
        workload_ref: str = "",
        environment: dict[str, str] | None = None,
        now: datetime | None = None,
        context_id: RuntimeExecutionContextId | None = None,
    ) -> RuntimeExecutionContext:
        ts = now or datetime.now(UTC)
        return cls(
            id=context_id or RuntimeExecutionContextId.new(),
            organization_id=organization_id,
            runtime_event_id=runtime_event_id,
            process_id=process_id,
            container_id=(container_id or "")[:128],
            host_id=(host_id or "")[:128],
            workload_ref=(workload_ref or "")[:256],
            environment=dict(environment or {}),
            created_at=ts,
            row_version=1,
        )
