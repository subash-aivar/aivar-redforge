"""Integration boundary status service — M18.

The six external-telemetry integrations (firewall, network/bandwidth
telemetry, connectivity/ISP, backup/DR, threat intelligence,
geolocation) have NO data source inside the platform. This service is
the provider-neutral BOUNDARY: it reports each integration's status
(NOT_CONFIGURED by default) and lets an org admin register or remove a
provider DESCRIPTOR. It NEVER fabricates telemetry — a registered
provider with no telemetry received is honestly reported as
AWAITING_TELEMETRY, and no metric values are ever synthesized.

Config is allowlisted to non-secret reference fields only; any other
key (and anything resembling a credential) is dropped before persistence
so a secret can never land in this table.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from redforge.core.exceptions import ValidationError
from redforge.domain.command_center.value_objects import IntegrationStatus, IntegrationType
from redforge.infrastructure.audit.contracts import AuditAction
from redforge.infrastructure.audit.organization_admin_audit_log import (
    PostgresOrganizationAdminAuditLog,
)
from redforge.infrastructure.database.models.command_center import IntegrationProviderModel
from redforge.infrastructure.database.repositories.command_center_repository import (
    SqlAlchemyIntegrationProviderRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

# Only these non-secret reference fields survive into a stored config.
# Everything else — and anything resembling a credential — is dropped.
_ALLOWED_CONFIG_KEYS = frozenset(
    {"endpoint", "region", "account_ref", "collector_id", "description", "link_name"}
)
_SECRET_MARKERS = ("secret", "token", "password", "key", "credential", "authorization", "cookie")


class UnknownIntegrationTypeError(ValidationError):
    def __init__(self, integration_type: str) -> None:
        super().__init__(f"Unknown integration type: {integration_type!r}")
        self.integration_type = integration_type


@dataclass(frozen=True, slots=True)
class IntegrationStatusDTO:
    integration_type: str
    provider_name: str | None
    status: str
    last_telemetry_at: str | None
    detail: str


def _sanitize_config(raw: dict[str, Any] | None) -> dict[str, str]:
    if not raw:
        return {}
    clean: dict[str, str] = {}
    for key, value in raw.items():
        key_l = str(key).lower()
        if key_l not in _ALLOWED_CONFIG_KEYS:
            continue
        if any(marker in key_l for marker in _SECRET_MARKERS):
            continue
        clean[key_l] = str(value)[:200]
    return clean


def _detail_for(status: IntegrationStatus) -> str:
    if status is IntegrationStatus.NOT_CONFIGURED:
        return "No provider configured for this integration."
    if status is IntegrationStatus.AWAITING_TELEMETRY:
        return "Provider registered; no telemetry received yet."
    if status is IntegrationStatus.ACTIVE:
        return "Provider registered and telemetry received."
    return "Provider reported an error state."


def _status_of(model: IntegrationProviderModel | None) -> IntegrationStatus:
    if model is None:
        return IntegrationStatus.NOT_CONFIGURED
    if model.status == IntegrationStatus.ERROR.value:
        return IntegrationStatus.ERROR
    if model.last_telemetry_at is None:
        return IntegrationStatus.AWAITING_TELEMETRY
    return IntegrationStatus.ACTIVE


class IntegrationStatusService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_status(self, organization_id: str) -> list[IntegrationStatusDTO]:
        """Returns exactly one status row per known IntegrationType — the
        full closed set — so the UI always renders all six panels, each
        NOT_CONFIGURED unless a real descriptor exists."""
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyIntegrationProviderRepository(uow.session)
            existing = {m.integration_type: m for m in await repo.list_for_org(organization_id)}
        out: list[IntegrationStatusDTO] = []
        for integration_type in IntegrationType:
            model = existing.get(integration_type.value)
            status = _status_of(model)
            out.append(
                IntegrationStatusDTO(
                    integration_type=integration_type.value,
                    provider_name=model.provider_name if model else None,
                    status=status.value,
                    last_telemetry_at=(
                        model.last_telemetry_at.isoformat()
                        if model and model.last_telemetry_at
                        else None
                    ),
                    detail=_detail_for(status),
                )
            )
        return out

    async def register_provider(
        self,
        *,
        organization_id: str,
        actor_id: str,
        integration_type: str,
        provider_name: str,
        config: dict[str, Any] | None = None,
    ) -> IntegrationStatusDTO:
        try:
            typed = IntegrationType(integration_type)
        except ValueError as exc:
            raise UnknownIntegrationTypeError(integration_type) from exc

        now = utc_now()
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyIntegrationProviderRepository(uow.session)
            existing = await repo.get_by_type(organization_id, typed.value)
            model = IntegrationProviderModel(
                id=str(existing.id) if existing else str(EntityId.generate()),
                organization_id=organization_id,
                integration_type=typed.value,
                provider_name=provider_name[:100],
                # Never ACTIVE on registration — no telemetry has arrived.
                status=IntegrationStatus.AWAITING_TELEMETRY.value,
                config=_sanitize_config(config),
                last_telemetry_at=None,
                registered_by=actor_id,
                created_at=existing.created_at if existing else now,
                updated_at=now,
            )
            await repo.upsert(model)
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id,
                actor_id=actor_id,
                action=AuditAction.PROVIDER_REGISTERED,
                target_type="integration_provider",
                target_id=typed.value,
                metadata={"provider_name": provider_name[:100]},
            )
            await uow.commit()

        status = IntegrationStatus.AWAITING_TELEMETRY
        return IntegrationStatusDTO(
            integration_type=typed.value, provider_name=provider_name[:100],
            status=status.value, last_telemetry_at=None, detail=_detail_for(status),
        )

    async def disable_provider(
        self, *, organization_id: str, actor_id: str, integration_type: str,
    ) -> bool:
        try:
            typed = IntegrationType(integration_type)
        except ValueError as exc:
            raise UnknownIntegrationTypeError(integration_type) from exc
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyIntegrationProviderRepository(uow.session)
            removed = await repo.delete_by_type(organization_id, typed.value)
            if removed:
                await PostgresOrganizationAdminAuditLog(uow.session).record(
                    organization_id=organization_id,
                    actor_id=actor_id,
                    action=AuditAction.PROVIDER_DISABLED,
                    target_type="integration_provider",
                    target_id=typed.value,
                    metadata={},
                )
                await uow.commit()
        return removed
