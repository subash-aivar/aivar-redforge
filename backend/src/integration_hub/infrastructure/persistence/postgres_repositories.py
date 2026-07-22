"""PostgreSQL repositories for integration_hub.

Session-per-call from an injected async_sessionmaker, matching the pattern
used across incident/posture_forecasting/threat_hunt/exposure_reporting.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from integration_hub.domain.aggregates.connector_health_record import ConnectorHealthRecord
from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.repositories.i_connector_repositories import (
    IConnectorHealthRecordRepository,
    IConnectorRegistrationRepository,
)
from integration_hub.domain.value_objects.credentials import CredentialRef
from integration_hub.domain.value_objects.enums import (
    CircuitState,
    ConnectorHealthStatus,
    ConnectorStatus,
    ConnectorType,
)
from integration_hub.domain.value_objects.identifiers import (
    ConnectorHealthRecordId,
    ConnectorId,
    TenantId,
)
from integration_hub.infrastructure.persistence.models import (
    ConnectorHealthRecordModel,
    ConnectorRegistrationModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def _registration_to_row(reg: ConnectorRegistration) -> ConnectorRegistrationModel:
    return ConnectorRegistrationModel(
        id=reg.connector_id.value,
        tenant_id=reg.tenant_id.value,
        connector_type=reg.connector_type.value,
        display_name=reg.display_name,
        status=reg.status.value,
        credential_vault_key=reg.credential_ref.vault_key,
        credential_type=reg.credential_ref.credential_type,
        base_url=reg.base_url,
        configuration=dict(reg.configuration) if reg.configuration else None,
        circuit_state=reg.circuit_state.value,
        circuit_failure_count=reg.circuit_failure_count,
        circuit_opened_at=reg.circuit_opened_at,
        created_at=reg.created_at,
        updated_at=reg.updated_at,
        last_health_check_at=reg.last_health_check_at,
    )


def _row_to_registration(row: ConnectorRegistrationModel) -> ConnectorRegistration:
    return ConnectorRegistration(
        connector_id=ConnectorId(row.id),
        tenant_id=TenantId(row.tenant_id),
        connector_type=ConnectorType(row.connector_type),
        display_name=row.display_name,
        status=ConnectorStatus(row.status),
        credential_ref=CredentialRef(
            vault_key=row.credential_vault_key,
            tenant_id=str(row.tenant_id),
            credential_type=row.credential_type,
        ),
        base_url=row.base_url,
        configuration=dict(row.configuration) if row.configuration else None,
        created_at=row.created_at,
        last_health_check_at=row.last_health_check_at,
        circuit_state=CircuitState(row.circuit_state),
        circuit_failure_count=row.circuit_failure_count,
        circuit_opened_at=row.circuit_opened_at,
        updated_at=row.updated_at,
    )


class PgConnectorRegistrationRepository(IConnectorRegistrationRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, registration: ConnectorRegistration, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            await session.merge(_registration_to_row(registration))
            await session.commit()

    async def get(
        self, connector_id: ConnectorId, tenant_id: TenantId
    ) -> ConnectorRegistration | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ConnectorRegistrationModel).where(
                        ConnectorRegistrationModel.tenant_id == tenant_id.value,
                        ConnectorRegistrationModel.id == connector_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_registration(row) if row is not None else None

    async def find_healthy_for_action_type(
        self, tenant_id: TenantId, connector_type: ConnectorType
    ) -> list[ConnectorRegistration]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(ConnectorRegistrationModel).where(
                        ConnectorRegistrationModel.tenant_id == tenant_id.value,
                        ConnectorRegistrationModel.connector_type == connector_type.value,
                        ConnectorRegistrationModel.status.in_(
                            [ConnectorStatus.HEALTHY.value, ConnectorStatus.REGISTERED.value]
                        ),
                    )
                )
            ).scalars().all()
            return [_row_to_registration(r) for r in rows]

    async def find_all_for_tenant(self, tenant_id: TenantId) -> list[ConnectorRegistration]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(ConnectorRegistrationModel).where(
                        ConnectorRegistrationModel.tenant_id == tenant_id.value
                    )
                )
            ).scalars().all()
            return [_row_to_registration(r) for r in rows]


class PgConnectorHealthRecordRepository(IConnectorHealthRecordRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def append(self, record: ConnectorHealthRecord, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            session.add(
                ConnectorHealthRecordModel(
                    id=record.record_id.value,
                    tenant_id=tenant_id.value,
                    connector_id=record.connector_id.value,
                    status=record.status.value,
                    response_time_ms=record.response_time_ms,
                    error_detail=record.error_detail,
                    checked_at=record.checked_at,
                )
            )
            await session.commit()

    async def find_latest_for_connector(
        self, connector_id: ConnectorId, tenant_id: TenantId, limit: int
    ) -> list[ConnectorHealthRecord]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(ConnectorHealthRecordModel)
                    .where(
                        ConnectorHealthRecordModel.tenant_id == tenant_id.value,
                        ConnectorHealthRecordModel.connector_id == connector_id.value,
                    )
                    .order_by(ConnectorHealthRecordModel.checked_at.desc())
                    .limit(limit)
                )
            ).scalars().all()
            return [
                ConnectorHealthRecord(
                    record_id=ConnectorHealthRecordId(r.id),
                    tenant_id=TenantId(r.tenant_id),
                    connector_id=ConnectorId(r.connector_id),
                    status=ConnectorHealthStatus(r.status),
                    response_time_ms=r.response_time_ms,
                    error_detail=r.error_detail,
                    checked_at=r.checked_at,
                )
                for r in rows
            ]
