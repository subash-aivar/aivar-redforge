"""RuntimeProcess, RuntimeNetworkConnection, RuntimeFileActivity aggregates."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from redforge.domain.cloud_security.runtime.events import (
    RuntimeConnectionObserved,
    RuntimeDomainEvent,
    RuntimeExecutionObserved,
)
from redforge.domain.cloud_security.runtime.exceptions import InvalidRuntimeArgumentError
from redforge.domain.cloud_security.runtime.value_objects import (
    CloudRuntimeEventId,
    RuntimeDirection,
    RuntimeProtocol,
)
from redforge.domain.cloud_security.value_objects import OrganizationId


@dataclass(frozen=True, slots=True)
class RuntimeProcessId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> RuntimeProcessId:
        return cls(uuid4())


@dataclass
class RuntimeProcess:
    id: RuntimeProcessId
    organization_id: OrganizationId
    runtime_event_id: CloudRuntimeEventId
    process_name: str
    executable_path: str
    pid: int | None
    parent_pid: int | None
    command_line: str
    user_name: str
    created_at: datetime
    row_version: int = 1
    _pending_events: list[RuntimeDomainEvent] = field(default_factory=list, repr=False)

    @classmethod
    def observe(
        cls,
        *,
        organization_id: OrganizationId,
        runtime_event_id: CloudRuntimeEventId,
        process_name: str,
        executable_path: str = "",
        pid: int | None = None,
        parent_pid: int | None = None,
        command_line: str = "",
        user_name: str = "",
        now: datetime | None = None,
        process_id: RuntimeProcessId | None = None,
    ) -> RuntimeProcess:
        name = (process_name or "").strip()
        if not name:
            raise InvalidRuntimeArgumentError("process_name", "required")
        ts = now or datetime.now(UTC)
        pid_vo = process_id or RuntimeProcessId.new()
        proc = cls(
            id=pid_vo,
            organization_id=organization_id,
            runtime_event_id=runtime_event_id,
            process_name=name[:256],
            executable_path=(executable_path or "")[:1024],
            pid=pid,
            parent_pid=parent_pid,
            command_line=(command_line or "")[:4096],
            user_name=(user_name or "")[:256],
            created_at=ts,
            row_version=1,
        )
        proc._pending_events.append(
            RuntimeExecutionObserved(
                occurred_at=ts,
                organization_id=str(organization_id),
                event_id=runtime_event_id.value,
                process_name=proc.process_name,
                executable_path=proc.executable_path,
            )
        )
        return proc

    def pop_events(self) -> list[RuntimeDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events


@dataclass(frozen=True, slots=True)
class RuntimeNetworkConnectionId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> RuntimeNetworkConnectionId:
        return cls(uuid4())


@dataclass
class RuntimeNetworkConnection:
    id: RuntimeNetworkConnectionId
    organization_id: OrganizationId
    runtime_event_id: CloudRuntimeEventId
    direction: RuntimeDirection
    protocol: RuntimeProtocol
    local_address: str
    local_port: int | None
    remote_address: str
    remote_port: int | None
    created_at: datetime
    row_version: int = 1
    _pending_events: list[RuntimeDomainEvent] = field(default_factory=list, repr=False)

    @classmethod
    def observe(
        cls,
        *,
        organization_id: OrganizationId,
        runtime_event_id: CloudRuntimeEventId,
        direction: RuntimeDirection | str = RuntimeDirection.UNKNOWN,
        protocol: RuntimeProtocol | str = RuntimeProtocol.UNKNOWN,
        local_address: str = "",
        local_port: int | None = None,
        remote_address: str = "",
        remote_port: int | None = None,
        now: datetime | None = None,
        connection_id: RuntimeNetworkConnectionId | None = None,
    ) -> RuntimeNetworkConnection:
        direction_vo = (
            direction
            if isinstance(direction, RuntimeDirection)
            else RuntimeDirection(str(direction).upper())
        )
        protocol_vo = (
            protocol
            if isinstance(protocol, RuntimeProtocol)
            else RuntimeProtocol(str(protocol).upper())
        )
        ts = now or datetime.now(UTC)
        cid = connection_id or RuntimeNetworkConnectionId.new()
        conn = cls(
            id=cid,
            organization_id=organization_id,
            runtime_event_id=runtime_event_id,
            direction=direction_vo,
            protocol=protocol_vo,
            local_address=(local_address or "")[:128],
            local_port=local_port,
            remote_address=(remote_address or "")[:128],
            remote_port=remote_port,
            created_at=ts,
            row_version=1,
        )
        conn._pending_events.append(
            RuntimeConnectionObserved(
                occurred_at=ts,
                organization_id=str(organization_id),
                event_id=runtime_event_id.value,
                direction=direction_vo.value,
                protocol=protocol_vo.value,
                remote_address=conn.remote_address,
            )
        )
        return conn

    def pop_events(self) -> list[RuntimeDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events


@dataclass(frozen=True, slots=True)
class RuntimeFileActivityId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> RuntimeFileActivityId:
        return cls(uuid4())


@dataclass
class RuntimeFileActivity:
    id: RuntimeFileActivityId
    organization_id: OrganizationId
    runtime_event_id: CloudRuntimeEventId
    operation: str
    path: str
    file_hash: str
    created_at: datetime
    row_version: int = 1

    @classmethod
    def observe(
        cls,
        *,
        organization_id: OrganizationId,
        runtime_event_id: CloudRuntimeEventId,
        operation: str,
        path: str,
        file_hash: str = "",
        now: datetime | None = None,
        activity_id: RuntimeFileActivityId | None = None,
    ) -> RuntimeFileActivity:
        op = (operation or "").strip()
        fpath = (path or "").strip()
        if not op or not fpath:
            raise InvalidRuntimeArgumentError("operation/path", "required")
        ts = now or datetime.now(UTC)
        return cls(
            id=activity_id or RuntimeFileActivityId.new(),
            organization_id=organization_id,
            runtime_event_id=runtime_event_id,
            operation=op[:64],
            path=fpath[:2048],
            file_hash=(file_hash or "")[:128],
            created_at=ts,
            row_version=1,
        )
