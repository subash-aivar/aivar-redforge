from __future__ import annotations

from datetime import UTC, datetime, timedelta

from integration_hub.domain.value_objects.credentials import CredentialRef, ResolvedCredential


class InMemoryCredentialVault:
    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}
        self._cache: dict[str, tuple[ResolvedCredential, datetime]] = {}
        self.ttl = timedelta(minutes=5)

    def put(self, vault_key: str, secret_value: str) -> None:
        self._secrets[vault_key] = secret_value

    async def resolve(self, ref: CredentialRef, tenant_id: str) -> ResolvedCredential:
        if ref.tenant_id != tenant_id:
            raise ValueError("tenant mismatch")
        now = datetime.now(UTC)
        cached = self._cache.get(ref.vault_key)
        if cached and now - cached[1] < self.ttl:
            return cached[0]
        secret = self._secrets.get(ref.vault_key, f"resolved:{ref.vault_key}")
        resolved = ResolvedCredential(ref.credential_type, secret, now + timedelta(minutes=10))
        self._cache[ref.vault_key] = (resolved, now)
        return resolved
