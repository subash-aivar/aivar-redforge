"""NetworkAuthorizationScopeChecker — M16.

Adds CIDR-containment resolution ON TOP OF the unchanged M10
SecurityAuthorization aggregate/scope model (ScopeEntityType.AI_ASSET,
ActionClass.ACTIVE_VALIDATION, SecurityAuthorization.is_active_now()) —
M10's own `covers()` is exact (entity_type, entity_id) set membership
only and has no concept of "this concrete IP falls inside that
authorized NETWORK asset's CIDR" (see that aggregate's own docstring).
No M10 domain code is modified.

Every concrete resolved IP is re-checked FRESH here — this service
caches nothing across calls, so a DNS re-resolution mid-run, or an
authorization revoked/expired between two calls, is always reflected
immediately (see application/network_security/orchestrator.py, which
calls this once per address at plan time AND again immediately before
each probe)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redforge.domain.authorization.value_objects import ActionClass, ScopeEntityType
from redforge.domain.inventory.value_objects import AssetType
from redforge.domain.network_security.address import NormalizedNetwork, normalize_and_classify
from redforge.domain.network_security.value_objects import NetworkScopeReasonCode

if TYPE_CHECKING:
    from redforge.infrastructure.database.repositories.asset_repository import (
        SqlAlchemyAssetRepository,
    )
    from redforge.infrastructure.database.repositories.authorization.repository import (
        SqlAlchemySecurityAuthorizationRepository,
    )


@dataclass(frozen=True, slots=True)
class NetworkScopeDecision:
    allowed: bool
    reason_code: NetworkScopeReasonCode
    authorization_id: str | None = None
    matched_asset_id: str | None = None


def _strip_external_id_value(external_id: str) -> str:
    """`external_id` is `"{scheme}:{normalized_value}"` (see
    domain/inventory/identity.py) — this returns just the
    normalized_value half."""
    _scheme, _sep, value = external_id.partition(":")
    return value


class NetworkAuthorizationScopeChecker:
    def __init__(
        self,
        authorization_repo: SqlAlchemySecurityAuthorizationRepository,
        asset_repo: SqlAlchemyAssetRepository,
    ) -> None:
        self._authorization_repo = authorization_repo
        self._asset_repo = asset_repo

    async def check_ip_authorized(
        self,
        organization_id: str,
        ip: str,
        now: datetime | None = None,
    ) -> NetworkScopeDecision:
        """Fresh, uncached authorization decision for one concrete IP.
        Address classification is checked first and unconditionally —
        no authorization can ever cover a hard-denied class (see
        domain/network_security/address.py's module docstring)."""
        evaluated_at = now or datetime.now(UTC)

        normalized = normalize_and_classify(ip)
        if normalized.is_hard_denied:
            return NetworkScopeDecision(
                allowed=False, reason_code=NetworkScopeReasonCode.ADDRESS_CLASS_HARD_DENIED,
            )

        from redforge.shared.identifiers import EntityId

        active_authorizations = await self._authorization_repo.find_active_covering(
            EntityId.from_string(organization_id)
        )

        saw_time_expired = False
        for authorization in active_authorizations:
            if ActionClass.ACTIVE_VALIDATION not in authorization.action_classes:
                continue
            if not authorization.is_active_now(evaluated_at):
                # Status is still ACTIVE in the DB (find_active_covering
                # only returns AuthorizationStatus.ACTIVE rows) but the
                # time-of-use check fails — the validity window has
                # elapsed even though a background sweep hasn't yet
                # flipped the stored status to EXPIRED. Never trust the
                # stored status alone (see is_active_now()'s docstring).
                saw_time_expired = True
                continue

            for scope_entry in authorization.scope:
                if scope_entry.entity_type != ScopeEntityType.AI_ASSET:
                    continue
                asset = await self._asset_repo.get_by_id_for_org(
                    scope_entry.entity_id, organization_id,
                )
                if asset is None:
                    continue

                if asset.asset_type == AssetType.IP_ADDRESS:
                    scoped_ip = _strip_external_id_value(asset.external_id)
                    if scoped_ip == normalized.value:
                        return NetworkScopeDecision(
                            allowed=True,
                            reason_code=NetworkScopeReasonCode.ALLOWED_BY_ACTIVE_AUTHORIZATION,
                            authorization_id=str(authorization.id),
                            matched_asset_id=str(asset.id),
                        )
                elif asset.asset_type == AssetType.NETWORK:
                    scoped_cidr = _strip_external_id_value(asset.external_id)
                    try:
                        network = NormalizedNetwork.parse(scoped_cidr)
                    except ValueError:
                        continue
                    if network.contains(normalized.value):
                        return NetworkScopeDecision(
                            allowed=True,
                            reason_code=NetworkScopeReasonCode.ALLOWED_BY_ACTIVE_AUTHORIZATION,
                            authorization_id=str(authorization.id),
                            matched_asset_id=str(asset.id),
                        )

        if saw_time_expired:
            return NetworkScopeDecision(
                allowed=False, reason_code=NetworkScopeReasonCode.AUTHORIZATION_EXPIRED,
            )
        return NetworkScopeDecision(
            allowed=False, reason_code=NetworkScopeReasonCode.NO_MATCHING_AUTHORIZATION,
        )
