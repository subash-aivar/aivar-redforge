
"""EvidenceContainer — wires application services and adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from evidence.application.services.evidence_application_service import (
    EvidenceApplicationService,
)
from evidence.infrastructure.blob.in_memory_evidence_blob_store import (
    InMemoryEvidenceBlobStore,
)
from evidence.infrastructure.events.structlog_event_publisher import StructlogEventPublisher
from evidence.infrastructure.kms.in_memory_key_management import InMemoryKeyManagementPort
from evidence.infrastructure.persistence.unit_of_work import make_evidence_uow_factory

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from evidence.application.ports.i_unit_of_work import IEventPublisher
    from evidence.domain.ports.i_evidence_blob_store import IEvidenceBlobStore
    from evidence.domain.ports.i_key_management_port import IKeyManagementPort


class EvidenceContainer:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: IEventPublisher | None = None,
        *,
        blob_store: IEvidenceBlobStore | None = None,
        kms: IKeyManagementPort | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.event_publisher: IEventPublisher = event_publisher or StructlogEventPublisher()
        self.blob_store = blob_store or InMemoryEvidenceBlobStore()
        self.kms = kms or InMemoryKeyManagementPort()
        uow_factory = make_evidence_uow_factory(session_factory)
        self.evidence_service = EvidenceApplicationService(
            uow_factory,
            self.event_publisher,
            self.blob_store,
            self.kms,
        )
