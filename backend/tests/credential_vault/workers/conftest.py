"""Fixtures for credential vault worker integration tests."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
import pytest_asyncio
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
from sqlalchemy import text
from tests.credential_vault.infrastructure.conftest import run_alembic

from credential_vault.application.ports.i_event_publisher import IEventPublisher
from credential_vault.domain.events.base import BaseDomainEvent
from credential_vault.domain.exceptions.domain_exceptions import KmsKeyNotFound
from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort
from credential_vault.domain.services.policy_evaluator import PolicyEvaluatorService
from credential_vault.domain.services.rotation_planner import RotationPlannerService
from credential_vault.domain.value_objects.payloads import KeyEnvelope
from credential_vault.infrastructure.container import CredentialVaultContainer
from credential_vault.infrastructure.encryption.aes_gcm_encryption_adapter import (
    AesGcmEncryptionAdapter,
)
from credential_vault.infrastructure.encryption.local_kms_adapter import LocalAesKwKmsAdapter
from credential_vault.workers.dek_rewrap.dek_rewrap_progress_repository import (
    DekRewrapProgressRepository,
)
from credential_vault.workers.dek_rewrap.dek_rewrap_worker import DekRewrapWorker
from credential_vault.workers.expiration_scanner.expiration_scanner_worker import (
    ExpirationScannerWorker,
)
from credential_vault.workers.expiration_scanner.expiration_schedule_repository import (
    ExpirationScheduleRepository,
)
from credential_vault.workers.rotation_scheduler.rotation_schedule_repository import (
    RotationScheduleRepository,
)
from credential_vault.workers.rotation_scheduler.rotation_scheduler_worker import (
    RotationSchedulerWorker,
)
from credential_vault.workers.version_pruner.version_pruner_worker import VersionPrunerWorker
from credential_vault.workers.worker_host import CredentialVaultWorkerHost
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from credential_vault.application.services.credential_application_service import (
        CredentialApplicationService,
    )


SYSTEM_PRINCIPAL_ID = UUID("00000000-0000-4000-8000-000000000099")
OLD_MASTER_KEY_ID = "local-master-v1"
NEW_MASTER_KEY_ID = "local-master-v2"

pytestmark = pytest.mark.integration

CREDENTIAL_VAULT_TABLES = (
    "credential_vault_dek_rewrap_progress",
    "credential_vault_expiration_schedule_state",
    "credential_vault_rotation_schedule_state",
    "credential_vault_approval_requests",
    "credential_vault_audit_entries",
    "credential_vault_audit_logs",
    "credential_vault_versions",
    "credential_vault_credentials",
    "credential_vault_rotation_policies",
    "credential_vault_expiration_policies",
    "credential_vault_vault_backends",
)


@pytest.fixture(scope="session", autouse=True)
def apply_worker_migrations() -> None:
    if not os.environ.get("TEST_DATABASE_URL"):
        yield
        return
    run_alembic("downgrade:0044", "0045")
    yield


@pytest_asyncio.fixture(autouse=True)
async def clean_credential_vault_data(
    pg_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[None]:
    """Isolate worker tests from stale rows left by other integration suites."""
    table_list = ", ".join(CREDENTIAL_VAULT_TABLES)
    async with pg_session_factory() as session:
        await session.execute(text(f"TRUNCATE {table_list} RESTART IDENTITY CASCADE"))
        await session.commit()
    yield


@pytest.fixture(autouse=True)
def open_permission_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CREDENTIAL_VAULT_PERMISSION_MODE", "open")
    monkeypatch.setenv(
        "CREDENTIAL_VAULT_LOCAL_MASTER_KEY",
        __import__("base64").b64encode(b"\x11" * 32).decode(),
    )
    monkeypatch.setenv("CREDENTIAL_VAULT_LOCAL_MASTER_KEY_ID", OLD_MASTER_KEY_ID)


class RecordingEventPublisher(IEventPublisher):
    def __init__(self) -> None:
        self.events: list[BaseDomainEvent] = []

    async def publish_batch(self, events: list[BaseDomainEvent]) -> None:
        self.events.extend(events)


class FakeKms(IKeyManagementPort):
    """KMS stub with multi-key rewrap support for DEK rewrap worker tests."""

    def __init__(self) -> None:
        self._keys = {
            OLD_MASTER_KEY_ID: b"\x11" * 32,
            NEW_MASTER_KEY_ID: b"\x22" * 32,
        }
        self._default = LocalAesKwKmsAdapter(
            master_key=self._keys[OLD_MASTER_KEY_ID],
            master_key_id=OLD_MASTER_KEY_ID,
        )

    async def generate_dek(self) -> tuple[bytes, KeyEnvelope]:
        return await self._default.generate_dek()

    async def unwrap_dek(self, envelope: KeyEnvelope) -> bytes:
        key = self._keys.get(envelope.master_key_id)
        if key is None:
            raise KmsKeyNotFound(envelope.master_key_id)
        dek = aes_key_unwrap(
            wrapping_key=key,
            wrapped_key=envelope.wrapped_dek,
            backend=default_backend(),
        )
        return bytearray(dek)  # type: ignore[return-value]

    async def rewrap_dek(self, old_envelope: KeyEnvelope, new_master_key_id: str) -> KeyEnvelope:
        new_key = self._keys.get(new_master_key_id)
        if new_key is None:
            raise KmsKeyNotFound(new_master_key_id)
        dek = await self.unwrap_dek(old_envelope)
        wrapped = aes_key_wrap(
            wrapping_key=new_key,
            key_to_wrap=bytes(dek),
            backend=default_backend(),
        )
        return KeyEnvelope(
            wrapped_dek=wrapped,
            master_key_id=new_master_key_id,
            wrapping_algorithm="AES-KW-256",
            created_at=datetime.now(UTC),
        )


@pytest.fixture
def tenant_id() -> EntityId:
    return EntityId.generate()


@pytest.fixture
def principal_id() -> UUID:
    return SYSTEM_PRINCIPAL_ID


@pytest.fixture
def event_publisher() -> RecordingEventPublisher:
    return RecordingEventPublisher()


@pytest.fixture
def fake_kms() -> FakeKms:
    return FakeKms()


@pytest.fixture
def encryption_port() -> AesGcmEncryptionAdapter:
    return AesGcmEncryptionAdapter()


@pytest.fixture
def cv_container(
    pg_session_factory: async_sessionmaker[AsyncSession],
    fake_kms: FakeKms,
    encryption_port: AesGcmEncryptionAdapter,
    event_publisher: RecordingEventPublisher,
) -> CredentialVaultContainer:
    return CredentialVaultContainer(
        session_factory=pg_session_factory,
        encryption_adapter=encryption_port,
        kms_adapter=fake_kms,
        event_publisher=event_publisher,
    )


@pytest.fixture
def credential_service(cv_container: CredentialVaultContainer) -> CredentialApplicationService:
    return cv_container._inner_credential_service


@pytest.fixture
def rotation_schedule_repo(
    pg_session_factory: async_sessionmaker[AsyncSession],
) -> RotationScheduleRepository:
    return RotationScheduleRepository(pg_session_factory)


@pytest.fixture
def expiration_schedule_repo(
    pg_session_factory: async_sessionmaker[AsyncSession],
) -> ExpirationScheduleRepository:
    return ExpirationScheduleRepository(pg_session_factory)


@pytest.fixture
def rotation_scheduler_worker(
    credential_service: CredentialApplicationService,
    rotation_schedule_repo: RotationScheduleRepository,
    pg_session_factory: async_sessionmaker[AsyncSession],
    principal_id: UUID,
) -> RotationSchedulerWorker:
    return RotationSchedulerWorker(
        credential_service=credential_service,
        schedule_repo=rotation_schedule_repo,
        rotation_planner=RotationPlannerService(),
        credential_repo_factory=pg_session_factory,
        worker_id="rotation-test",
        poll_interval_s=0.1,
        batch_size=5,
        max_concurrent=1,
        system_principal_id=principal_id,
    )


@pytest.fixture
def expiration_scanner_worker(
    credential_service: CredentialApplicationService,
    expiration_schedule_repo: ExpirationScheduleRepository,
    pg_session_factory: async_sessionmaker[AsyncSession],
    event_publisher: RecordingEventPublisher,
    principal_id: UUID,
) -> ExpirationScannerWorker:
    return ExpirationScannerWorker(
        credential_service=credential_service,
        schedule_repo=expiration_schedule_repo,
        policy_evaluator=PolicyEvaluatorService(),
        session_factory=pg_session_factory,
        event_publisher=event_publisher,
        worker_id="expiration-test",
        poll_interval_s=0.1,
        batch_size=5,
        max_concurrent=1,
        system_principal_id=principal_id,
    )


@pytest.fixture
def version_pruner_worker(
    pg_session_factory: async_sessionmaker[AsyncSession],
) -> VersionPrunerWorker:
    return VersionPrunerWorker(
        session_factory=pg_session_factory,
        worker_id="pruner-test",
        poll_interval_s=0.1,
        batch_size=50,
    )


@pytest.fixture
def dek_rewrap_worker(
    fake_kms: FakeKms,
    pg_session_factory: async_sessionmaker[AsyncSession],
) -> DekRewrapWorker:
    return DekRewrapWorker(
        kms_adapter=fake_kms,
        rewrap_repo=DekRewrapProgressRepository(pg_session_factory),
        session_factory=pg_session_factory,
        target_master_key_id=NEW_MASTER_KEY_ID,
        worker_id="rewrap-test",
        batch_size=10,
        rate_limit_delay_ms=1,
    )


def build_worker_host(
    rotation_worker: RotationSchedulerWorker,
    expiration_worker: ExpirationScannerWorker,
    pruner_worker: VersionPrunerWorker,
    rewrap_worker: DekRewrapWorker | None = None,
) -> CredentialVaultWorkerHost:
    return CredentialVaultWorkerHost(
        rotation_worker=rotation_worker,
        expiration_worker=expiration_worker,
        pruner_worker=pruner_worker,
        rewrap_worker=rewrap_worker,
    )
