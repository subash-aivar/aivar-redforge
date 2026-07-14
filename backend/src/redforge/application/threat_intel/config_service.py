"""Threat Intelligence provider admin configuration — Priority 11 (privacy
and data-egress controls). Mirrors `IntegrationStatusService`'s exact
pattern: config is allowlisted to non-secret reference fields, a
credential is stored only as a REFERENCE (an env var name), and every
enable/disable/update is audited via the same
`PostgresOrganizationAdminAuditLog` used elsewhere in this codebase.

Zero rows = every provider disabled = zero external egress for that
organization. This is the enforcement point an admin uses to answer
"which external providers receive which indicator types".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from redforge.core.exceptions import ValidationError
from redforge.domain.threat_intel.value_objects import IndicatorType, ProviderName
from redforge.infrastructure.audit.contracts import AuditAction
from redforge.infrastructure.audit.organization_admin_audit_log import (
    PostgresOrganizationAdminAuditLog,
)
from redforge.infrastructure.database.models.threat_intel import ThreatIntelProviderModel
from redforge.infrastructure.database.repositories.threat_intel_repository import (
    SqlAlchemyThreatIntelProviderRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

# Same non-secret allowlist idiom as command_center/integration_service.py.
_ALLOWED_CONFIG_KEYS = frozenset({"mmdb_path", "description", "notes"})
_SECRET_MARKERS = ("secret", "token", "password", "key", "credential", "authorization", "cookie")

# Providers that ship disabled by default and carry a compliance
# disclaimer even when an admin does enable them — see
# docs/M18_INTELLIGENCE_PROVIDER_DECISION_MATRIX.md.
OPTIONAL_PROVIDERS = frozenset({ProviderName.GREYNOISE_COMMUNITY.value, ProviderName.ABUSECH.value})


class UnknownProviderError(ValidationError):
    def __init__(self, provider_name: str) -> None:
        super().__init__(f"Unknown threat-intel provider: {provider_name!r}")


class InvalidIndicatorTypeError(ValidationError):
    def __init__(self, indicator_type: str) -> None:
        super().__init__(f"Unknown indicator type: {indicator_type!r}")


@dataclass(frozen=True, slots=True)
class ProviderConfigDTO:
    provider_name: str
    enabled: bool
    allowed_indicator_types: list[str]
    credential_ref: str | None
    config: dict[str, str]
    is_optional_disclaimer_required: bool
    updated_at: str


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
        clean[key_l] = str(value)[:500]
    return clean


def _to_dto(model: ThreatIntelProviderModel) -> ProviderConfigDTO:
    return ProviderConfigDTO(
        provider_name=model.provider_name,
        enabled=model.enabled,
        allowed_indicator_types=list(model.allowed_indicator_types),
        credential_ref=model.credential_ref,
        config=model.config,
        is_optional_disclaimer_required=model.provider_name in OPTIONAL_PROVIDERS,
        updated_at=model.updated_at.isoformat(),
    )


class ThreatIntelProviderConfigService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_status(self, organization_id: str) -> list[ProviderConfigDTO]:
        """Returns one row per known ProviderName — the full closed set —
        so the admin UI always shows every provider, disabled by default."""
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyThreatIntelProviderRepository(uow.session)
            existing = {m.provider_name: m for m in await repo.list_for_org(organization_id)}
        out: list[ProviderConfigDTO] = []
        for provider in ProviderName:
            model = existing.get(provider.value)
            if model is not None:
                out.append(_to_dto(model))
            else:
                out.append(
                    ProviderConfigDTO(
                        provider_name=provider.value,
                        enabled=False,
                        allowed_indicator_types=[],
                        credential_ref=None,
                        config={},
                        is_optional_disclaimer_required=provider.value in OPTIONAL_PROVIDERS,
                        updated_at="",
                    )
                )
        return out

    async def configure(
        self,
        *,
        organization_id: str,
        actor_id: str,
        provider_name: str,
        enabled: bool,
        allowed_indicator_types: list[str],
        credential_ref: str | None,
        config: dict[str, Any] | None = None,
    ) -> ProviderConfigDTO:
        try:
            typed = ProviderName(provider_name)
        except ValueError as exc:
            raise UnknownProviderError(provider_name) from exc

        for indicator_type in allowed_indicator_types:
            try:
                IndicatorType(indicator_type)
            except ValueError as exc:
                raise InvalidIndicatorTypeError(indicator_type) from exc

        now = utc_now()
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyThreatIntelProviderRepository(uow.session)
            existing = await repo.get_by_name(organization_id, typed.value)
            model = ThreatIntelProviderModel(
                id=str(existing.id) if existing else str(EntityId.generate()),
                organization_id=organization_id,
                provider_name=typed.value,
                enabled=enabled,
                allowed_indicator_types=allowed_indicator_types,
                credential_ref=credential_ref[:200] if credential_ref else None,
                config=_sanitize_config(config),
                updated_by=actor_id,
                created_at=existing.created_at if existing else now,
                updated_at=now,
            )
            await repo.upsert(model)
            await PostgresOrganizationAdminAuditLog(uow.session).record(
                organization_id=organization_id,
                actor_id=actor_id,
                action=AuditAction.PROVIDER_ENABLED if enabled else AuditAction.PROVIDER_DISABLED,
                target_type="threat_intel_provider",
                target_id=typed.value,
                metadata={
                    "allowed_indicator_types": ",".join(allowed_indicator_types),
                    "has_credential": str(bool(credential_ref)),
                },
            )
            await uow.commit()

        return _to_dto(model)
