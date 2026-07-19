"""AWS KMS adapter."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort
from credential_vault.domain.value_objects.payloads import KeyEnvelope


class AwsKmsAdapter(IKeyManagementPort):
    """IKeyManagementPort backed by AWS KMS via boto3 (thread-pool offload)."""

    def __init__(self, kms_client: Any, master_key_arn: str) -> None:
        self._kms = kms_client
        self._master_key_arn = master_key_arn

    async def generate_dek(self) -> tuple[bytes, KeyEnvelope]:
        loop = asyncio.get_running_loop()

        def _call() -> Any:
            return self._kms.generate_data_key(KeyId=self._master_key_arn, KeySpec="AES_256")

        response = await loop.run_in_executor(None, _call)
        dek = bytearray(response["Plaintext"])
        wrapped = response["CiphertextBlob"]
        envelope = KeyEnvelope(
            wrapped_dek=wrapped,
            master_key_id=self._master_key_arn,
            wrapping_algorithm="AWS_KMS_AES_256",
            created_at=datetime.now(UTC),
        )
        return bytes(dek), envelope

    async def unwrap_dek(self, envelope: KeyEnvelope) -> bytes:
        loop = asyncio.get_running_loop()

        def _call() -> Any:
            return self._kms.decrypt(
                CiphertextBlob=envelope.wrapped_dek,
                KeyId=self._master_key_arn,
            )

        response = await loop.run_in_executor(None, _call)
        return bytearray(response["Plaintext"])  # type: ignore[return-value]

    async def rewrap_dek(self, old_envelope: KeyEnvelope, new_master_key_id: str) -> KeyEnvelope:
        dek = await self.unwrap_dek(old_envelope)
        loop = asyncio.get_running_loop()

        def _call() -> Any:
            return self._kms.encrypt(KeyId=new_master_key_id, Plaintext=bytes(dek))

        try:
            new_response = await loop.run_in_executor(None, _call)
        finally:
            if isinstance(dek, bytearray):
                for i in range(len(dek)):
                    dek[i] = 0
        return KeyEnvelope(
            wrapped_dek=new_response["CiphertextBlob"],
            master_key_id=new_master_key_id,
            wrapping_algorithm="AWS_KMS_AES_256",
            created_at=datetime.now(UTC),
        )
