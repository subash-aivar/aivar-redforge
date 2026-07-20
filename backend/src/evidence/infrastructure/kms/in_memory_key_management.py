
"""In-memory KMS with key_version support for evidence encryption."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from cryptography.fernet import Fernet, InvalidToken

from evidence.domain.ports.i_key_management_port import IKeyManagementPort
from evidence.domain.value_objects.evidence_vos import EvidenceEncryptionKeyRef

if TYPE_CHECKING:
    from evidence.domain.value_objects.identifiers import TenantId


class InMemoryKeyManagementPort(IKeyManagementPort):
    """Per-tenant Fernet DEKs keyed by (key_id, key_version)."""

    def __init__(self) -> None:
        # tenant_id -> (key_id, current_version)
        self._current: dict[str, tuple[str, int]] = {}
        # (tenant_id, key_id, version) -> Fernet
        self._keys: dict[tuple[str, str, int], Fernet] = {}

    def _ensure_current(self, tenant_id: TenantId) -> EvidenceEncryptionKeyRef:
        tid = str(tenant_id)
        if tid not in self._current:
            key_id = f"evk-{uuid7()}"
            version = 1
            self._current[tid] = (key_id, version)
            self._keys[(tid, key_id, version)] = Fernet(Fernet.generate_key())
        key_id, version = self._current[tid]
        return EvidenceEncryptionKeyRef(key_id=key_id, key_version=version)

    def rotate(self, tenant_id: TenantId) -> EvidenceEncryptionKeyRef:
        """Bump key_version for tests / rotation drills."""
        tid = str(tenant_id)
        current = self._ensure_current(tenant_id)
        new_version = current.key_version + 1
        self._current[tid] = (current.key_id, new_version)
        self._keys[(tid, current.key_id, new_version)] = Fernet(Fernet.generate_key())
        return EvidenceEncryptionKeyRef(key_id=current.key_id, key_version=new_version)

    def _fernet(self, tenant_id: TenantId, key_ref: EvidenceEncryptionKeyRef) -> Fernet:
        tid = str(tenant_id)
        key = self._keys.get((tid, key_ref.key_id, key_ref.key_version))
        if key is None:
            raise ValueError(
                f"Unknown key {key_ref.key_id} v{key_ref.key_version} for tenant {tid}"
            )
        return key

    async def generate_key_ref(self, tenant_id: TenantId) -> EvidenceEncryptionKeyRef:
        return self._ensure_current(tenant_id)

    async def encrypt(
        self,
        tenant_id: TenantId,
        key_ref: EvidenceEncryptionKeyRef,
        plaintext: bytes,
    ) -> bytes:
        return self._fernet(tenant_id, key_ref).encrypt(plaintext)

    async def decrypt(
        self,
        tenant_id: TenantId,
        key_ref: EvidenceEncryptionKeyRef,
        ciphertext: bytes,
    ) -> bytes:
        try:
            return self._fernet(tenant_id, key_ref).decrypt(ciphertext)
        except InvalidToken as exc:
            raise ValueError("Decryption failed — invalid token or wrong key") from exc

    async def rewrap(
        self,
        tenant_id: TenantId,
        old_key_ref: EvidenceEncryptionKeyRef,
        ciphertext: bytes,
    ) -> tuple[bytes, EvidenceEncryptionKeyRef]:
        plaintext = await self.decrypt(tenant_id, old_key_ref, ciphertext)
        new_ref = await self.generate_key_ref(tenant_id)
        new_ciphertext = await self.encrypt(tenant_id, new_ref, plaintext)
        # Best-effort wipe
        del plaintext
        return new_ciphertext, new_ref
