"""CatalogPublishingService — loads framework adapters and seeds the catalog.

Idempotent: safe to call on every startup when
COMPLIANCE_CATALOG_AUTO_SEED=true.  Already-persisted frameworks are
skipped unless they have been retired.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from redforge.domain.compliance.entity import ControlRequirement
from redforge.domain.compliance.services import CatalogIntegrityValidator
from redforge.domain.compliance.value_objects import (
    ControlDomain,
    ControlSeverity,
    FrameworkKey,
    FrameworkMetadata,
    FrameworkStatus,
    PolicyThreshold,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.compliance.dtos import (
        PublishFrameworkCommand,
        RetireFrameworkCommand,
        SeedCatalogCommand,
    )
    from redforge.infrastructure.compliance.adapters.port import FrameworkDefinitionPort
    from redforge.infrastructure.database.repositories.compliance.catalog_repository import (
        SqlAlchemyControlCatalogRepository,
    )


class CatalogPublishingService:
    """Orchestrates framework registration and catalog seeding.

    Accepts a list of FrameworkDefinitionPort implementations at
    construction time; adapters are injected by the DI layer so the
    service is test-friendly without file I/O.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        adapters: Sequence[FrameworkDefinitionPort],
    ) -> None:
        self._session_factory = session_factory
        self._adapters: dict[FrameworkKey, FrameworkDefinitionPort] = {
            a.framework_key: a for a in adapters
        }
        self._validator = CatalogIntegrityValidator()

    def _repo(self, session: AsyncSession) -> SqlAlchemyControlCatalogRepository:
        from redforge.infrastructure.database.repositories.compliance.catalog_repository import (
            SqlAlchemyControlCatalogRepository,
        )
        return SqlAlchemyControlCatalogRepository(session)

    async def seed_catalog(self, command: SeedCatalogCommand) -> dict[str, str]:
        """Idempotent seed: load all adapters, skip already-published frameworks.

        Returns a summary dict mapping framework_key → outcome:
        "seeded_and_published" | "already_published" | "skipped_retired" | "error:<msg>"
        """
        summary: dict[str, str] = {}

        async with self._session_factory() as session, session.begin():
            repo = self._repo(session)

            for key, adapter in self._adapters.items():
                try:
                    existing = await repo.get_framework(key)
                    if existing is not None:
                        if existing.status == FrameworkStatus.PUBLISHED:
                            summary[key.value] = "already_published"
                            continue
                        if existing.status == FrameworkStatus.RETIRED:
                            summary[key.value] = "skipped_retired"
                            continue

                    # Load from adapter
                    meta_dict = adapter.load_metadata()
                    metadata = FrameworkMetadata.from_dict(meta_dict)

                    catalog = await repo.get_catalog()
                    framework = catalog.register_framework(
                        key=key,
                        metadata=metadata,
                    )

                    req_dicts = adapter.load_requirements()
                    for rd in req_dicts:
                        req = ControlRequirement.create(
                            framework_key=key,
                            requirement_ref=rd["requirement_ref"],
                            title=rd["title"],
                            description=rd["description"],
                            domain=ControlDomain(rd["domain"]),
                            severity=ControlSeverity(rd["severity"]),
                            guidance=rd.get("guidance", ""),
                            policy_threshold=PolicyThreshold(
                                rd.get("policy_threshold", 80)
                            ),
                            tags=tuple(rd.get("tags", [])),
                            external_ref=rd.get("external_ref", ""),
                        )
                        catalog.add_requirement(key, req)

                    if command.auto_publish:
                        self._validator.validate_publishable(catalog, key)
                        catalog.publish_framework(
                            key, published_by=command.published_by
                        )

                    await repo.save_framework(framework)
                    outcome = "seeded_and_published" if command.auto_publish else "seeded_draft"
                    summary[key.value] = outcome

                except Exception as exc:
                    summary[key.value] = f"error:{exc}"

        return summary

    async def publish_framework(self, command: PublishFrameworkCommand) -> None:
        async with self._session_factory() as session, session.begin():
            repo = self._repo(session)
            catalog = await repo.get_catalog()
            self._validator.validate_publishable(catalog, command.framework_key)
            catalog.publish_framework(
                command.framework_key,
                published_by=command.published_by,
            )
            framework = catalog.get_framework(command.framework_key)
            await repo.save_framework(framework)

    async def retire_framework(self, command: RetireFrameworkCommand) -> None:
        async with self._session_factory() as session, session.begin():
            repo = self._repo(session)
            catalog = await repo.get_catalog()
            catalog.retire_framework(
                command.framework_key,
                reason=command.reason,
                retired_by=command.retired_by,
            )
            framework = catalog.get_framework(command.framework_key)
            await repo.save_framework(framework)
