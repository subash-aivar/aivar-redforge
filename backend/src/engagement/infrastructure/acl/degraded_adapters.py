"""ACL adapters for engagement — degraded by default."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import TYPE_CHECKING

from engagement.domain.ports.i_asset_query_port import IAssetQueryPort
from engagement.domain.ports.i_digital_signature_port import IDigitalSignaturePort
from engagement.domain.value_objects.engagement_vos import TargetRef

if TYPE_CHECKING:
    from uuid import UUID

    from engagement.domain.value_objects.identifiers import TenantId


class DegradedAssetQueryAdapter(IAssetQueryPort):
    """Inventory ACL degraded stub — returns bare TargetRef without display name.

    Real InventoryContextAdapter (M22) is wired when inventory is available.
    """

    async def resolve_target_ref(
        self,
        asset_id: UUID,
        tenant_id: TenantId,
    ) -> TargetRef | None:
        _ = tenant_id
        return TargetRef(asset_id=asset_id, display_name=None)


class InventoryContextAdapter(DegradedAssetQueryAdapter):
    """Named ACL adapter for M22 inventory → TargetRef (degraded by default)."""


class HmacDigitalSignatureAdapter(IDigitalSignaturePort):
    """HMAC-SHA256 signatures with configurable secret (test/dev ready)."""

    def __init__(self, secret: str | bytes | None = None) -> None:
        if secret is None:
            secret = secrets.token_hex(32)
        self._secret = secret.encode("utf-8") if isinstance(secret, str) else secret

    def sign(self, payload: str) -> str:
        return hmac.new(
            self._secret,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, payload: str, signature: str, identity: str) -> bool:
        _ = identity
        expected = self.sign(payload)
        return hmac.compare_digest(expected, signature)
