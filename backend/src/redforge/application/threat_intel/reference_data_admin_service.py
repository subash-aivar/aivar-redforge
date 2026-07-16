"""Reference Data admin loading service — M22 Phase 1.

CRUD-level application service for loading and re-loading global
threat-intelligence reference data (MITRE ATT&CK tactics/techniques/
relationships, CVE/CVSS/EPSS/CISA-KEV records). Deliberately contains
NO orchestration: it never fetches from MITRE's GitHub, NVD, EPSS, or
CISA KEV itself, never parses a STIX bundle, and never schedules
anything. The caller (an internal administrator, via the API layer)
supplies already-fetched, already-parsed records; this service's only
job is idempotent, race-safe upsert into the global catalog plus the
ingestion-log idempotency gate, mirroring the exact
`ThreatIntelProviderConfigService` (M18) / `InvestigationCaseService`
(M21) shape: build domain entities, hand them to repositories inside a
single `SessionUnitOfWork` transaction, audit, commit.

Fetching from MITRE ATT&CK's public STIX bundle, NVD's CVE API, the
EPSS CSV, and the CISA KEV JSON feed — and the STIX 2.1 parsing that
goes with the ATT&CK bundle specifically — are M22 Phase 2+ concerns
(`AttackTechniqueSyncService`, `VulnerabilitySyncService`,
`StixIngestionService` per the architecture freeze) and are
intentionally NOT implemented here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.core.exceptions import ValidationError
from redforge.domain.threat_intel.attack_technique_entity import (
    AttackTactic,
    AttackTechnique,
    AttackTechniqueRelationship,
)
from redforge.domain.threat_intel.reference_data_exceptions import (
    DuplicateIngestionError,
    UnknownTacticReferenceError,
    UnknownTechniqueReferenceError,
)
from redforge.domain.threat_intel.reference_data_ingestion import ReferenceDataIngestionRecord
from redforge.domain.threat_intel.reference_data_value_objects import (
    AttackRelationshipType,
    CveId,
    CvssScore,
    EpssScore,
    IngestionScope,
    ReferenceDataSource,
    TacticId,
    TechniqueId,
)
from redforge.domain.threat_intel.vulnerability_entity import Vulnerability
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.threat_intel_reference_data_repository import (
    SqlAlchemyAttackTacticRepository,
    SqlAlchemyAttackTechniqueRepository,
    SqlAlchemyReferenceDataIngestionRepository,
    SqlAlchemyVulnerabilityRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


# ─── Input DTOs (already-parsed, already-fetched by the caller) ────────────


@dataclass(frozen=True, slots=True)
class TacticInput:
    tactic_id: str
    name: str
    shortname: str
    stix_id: str
    description: str = ""
    url: str | None = None


@dataclass(frozen=True, slots=True)
class TechniqueInput:
    technique_id: str
    name: str
    stix_id: str
    description: str = ""
    is_sub_technique: bool = False
    parent_technique_id: str | None = None
    tactic_ids: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    is_deprecated: bool = False
    is_revoked: bool = False
    framework_version: str | None = None


@dataclass(frozen=True, slots=True)
class RelationshipInput:
    stix_id: str
    relationship_type: str
    source_ref: str
    target_ref: str
    source_technique_id: str | None = None
    target_technique_id: str | None = None
    description: str = ""


@dataclass(frozen=True, slots=True)
class VulnerabilityInput:
    cve_id: str
    description: str = ""
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    cvss_v3_version: str | None = None
    cvss_v2_score: float | None = None
    epss_probability: float | None = None
    epss_percentile: float | None = None
    epss_model_date: str | None = None  # ISO date, e.g. "2026-07-01"
    is_kev: bool = False
    kev_date_added: str | None = None  # ISO datetime
    kev_due_date: str | None = None
    kev_vulnerability_name: str | None = None
    kev_short_description: str | None = None
    kev_required_action: str | None = None
    kev_known_ransomware_use: bool = False
    published_at: str | None = None
    last_modified_at: str | None = None


@dataclass(frozen=True, slots=True)
class ItemError:
    index: int
    identifier: str
    message: str


@dataclass(frozen=True, slots=True)
class BatchUpsertResult:
    source_system: str
    object_type: str
    batch_id: str
    total: int
    created: int
    updated: int
    unchanged: int
    failed: int
    errors: list[ItemError]


def _content_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _parse_iso_date(value: str | None) -> Any:
    if not value:
        return None
    from datetime import date

    return date.fromisoformat(value)


class ReferenceDataAdminService:
    """Commands: idempotent bulk-upsert of global reference data."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def upsert_tactics(
        self,
        *,
        actor_id: str,
        tactics: list[TacticInput],
        batch_id: str | None = None,
    ) -> BatchUpsertResult:
        batch_id = batch_id or str(EntityId.generate())
        created = updated = unchanged = 0
        errors: list[ItemError] = []
        seen_hashes: dict[str, str] = {}

        async with SessionUnitOfWork(self._session_factory) as uow:
            tactic_repo = SqlAlchemyAttackTacticRepository(uow.session)
            ingestion_repo = SqlAlchemyReferenceDataIngestionRepository(uow.session)

            for index, item in enumerate(tactics):
                try:
                    payload = {
                        "tactic_id": item.tactic_id,
                        "name": item.name,
                        "shortname": item.shortname,
                        "description": item.description,
                        "stix_id": item.stix_id,
                        "url": item.url,
                    }
                    content_hash, is_unchanged = await self._check_unchanged(
                        ingestion_repo,
                        source_system=ReferenceDataSource.MITRE_ATTACK,
                        external_id=item.stix_id,
                        payload=payload,
                    )
                    self._check_duplicate_in_batch(
                        seen_hashes,
                        source_system=ReferenceDataSource.MITRE_ATTACK,
                        external_id=item.stix_id,
                        content_hash=content_hash,
                    )
                    if is_unchanged:
                        unchanged += 1
                        continue

                    now = datetime.now(UTC)
                    tactic = AttackTactic(
                        tactic_id=TacticId(item.tactic_id),
                        name=item.name,
                        shortname=item.shortname,
                        description=item.description,
                        stix_id=item.stix_id,
                        url=item.url,
                        created_at=now,
                        updated_at=now,
                    )
                    await tactic_repo.upsert(tactic)
                    record_created = await self._record_ingestion(
                        ingestion_repo,
                        source_system=ReferenceDataSource.MITRE_ATTACK,
                        object_type="attack_tactic",
                        external_id=item.stix_id,
                        content_hash=content_hash,
                        batch_id=batch_id,
                    )
                    if record_created:
                        created += 1
                    else:
                        updated += 1
                except ValidationError as exc:
                    errors.append(
                        ItemError(index=index, identifier=item.tactic_id, message=str(exc))
                    )

            await self._audit(
                uow.session,
                actor_id=actor_id,
                object_type="attack_tactic",
                batch_id=batch_id,
                total=len(tactics),
                created=created,
                updated=updated,
            )
            await uow.commit()

        return BatchUpsertResult(
            source_system=ReferenceDataSource.MITRE_ATTACK.value,
            object_type="attack_tactic",
            batch_id=batch_id,
            total=len(tactics),
            created=created,
            updated=updated,
            unchanged=unchanged,
            failed=len(errors),
            errors=errors,
        )

    async def upsert_techniques(
        self,
        *,
        actor_id: str,
        techniques: list[TechniqueInput],
        batch_id: str | None = None,
    ) -> BatchUpsertResult:
        batch_id = batch_id or str(EntityId.generate())
        created = updated = unchanged = 0
        errors: list[ItemError] = []
        seen_hashes: dict[str, str] = {}

        async with SessionUnitOfWork(self._session_factory) as uow:
            technique_repo = SqlAlchemyAttackTechniqueRepository(uow.session)
            tactic_repo = SqlAlchemyAttackTacticRepository(uow.session)
            ingestion_repo = SqlAlchemyReferenceDataIngestionRepository(uow.session)

            # `parent_technique_id` is a DEFERRABLE self-referencing FK
            # (by design, so a batch may insert children before their
            # parent) — its violation is only checked at COMMIT, well
            # after this loop's per-item try/except has already exited.
            # Pre-validating against "already stored OR present
            # elsewhere in this same batch" here catches a genuinely
            # dangling reference as an isolated per-item error instead
            # of letting an unhandled IntegrityError abort the entire
            # batch (including every otherwise-valid item) at commit
            # time. Likewise `tactic_ids` has no DB-level FK at all (a
            # JSON array cannot carry one), so this is the only place
            # a fabricated tactic reference is ever caught.
            known_technique_ids = await technique_repo.list_all_ids()
            known_technique_ids.update(item.technique_id for item in techniques)
            known_tactic_ids = await tactic_repo.list_all_ids()

            for index, item in enumerate(techniques):
                try:
                    if item.parent_technique_id and (
                        item.parent_technique_id not in known_technique_ids
                    ):
                        raise UnknownTechniqueReferenceError(item.parent_technique_id)
                    for tactic_id in item.tactic_ids:
                        if tactic_id not in known_tactic_ids:
                            raise UnknownTacticReferenceError(tactic_id)

                    payload = {
                        "technique_id": item.technique_id,
                        "name": item.name,
                        "description": item.description,
                        "stix_id": item.stix_id,
                        "is_sub_technique": item.is_sub_technique,
                        "parent_technique_id": item.parent_technique_id,
                        "tactic_ids": sorted(item.tactic_ids),
                        "platforms": sorted(item.platforms),
                        "data_sources": sorted(item.data_sources),
                        "is_deprecated": item.is_deprecated,
                        "is_revoked": item.is_revoked,
                        "framework_version": item.framework_version,
                    }
                    content_hash, is_unchanged = await self._check_unchanged(
                        ingestion_repo,
                        source_system=ReferenceDataSource.MITRE_ATTACK,
                        external_id=item.stix_id,
                        payload=payload,
                    )
                    self._check_duplicate_in_batch(
                        seen_hashes,
                        source_system=ReferenceDataSource.MITRE_ATTACK,
                        external_id=item.stix_id,
                        content_hash=content_hash,
                    )
                    if is_unchanged:
                        unchanged += 1
                        continue

                    now = datetime.now(UTC)
                    technique = AttackTechnique(
                        technique_id=TechniqueId(item.technique_id),
                        name=item.name,
                        description=item.description,
                        stix_id=item.stix_id,
                        is_sub_technique=item.is_sub_technique,
                        parent_technique_id=(
                            TechniqueId(item.parent_technique_id)
                            if item.parent_technique_id
                            else None
                        ),
                        tactic_ids=tuple(TacticId(t) for t in item.tactic_ids),
                        platforms=tuple(item.platforms),
                        data_sources=tuple(item.data_sources),
                        is_deprecated=item.is_deprecated,
                        is_revoked=item.is_revoked,
                        framework_version=item.framework_version,
                        created_at=now,
                        updated_at=now,
                    )
                    await technique_repo.upsert(technique)
                    record_created = await self._record_ingestion(
                        ingestion_repo,
                        source_system=ReferenceDataSource.MITRE_ATTACK,
                        object_type="attack_technique",
                        external_id=item.stix_id,
                        content_hash=content_hash,
                        batch_id=batch_id,
                    )
                    if record_created:
                        created += 1
                    else:
                        updated += 1
                except ValidationError as exc:
                    errors.append(
                        ItemError(index=index, identifier=item.technique_id, message=str(exc))
                    )

            await self._audit(
                uow.session,
                actor_id=actor_id,
                object_type="attack_technique",
                batch_id=batch_id,
                total=len(techniques),
                created=created,
                updated=updated,
            )
            await uow.commit()

        return BatchUpsertResult(
            source_system=ReferenceDataSource.MITRE_ATTACK.value,
            object_type="attack_technique",
            batch_id=batch_id,
            total=len(techniques),
            created=created,
            updated=updated,
            unchanged=unchanged,
            failed=len(errors),
            errors=errors,
        )

    async def upsert_technique_relationships(
        self,
        *,
        actor_id: str,
        relationships: list[RelationshipInput],
        batch_id: str | None = None,
    ) -> BatchUpsertResult:
        batch_id = batch_id or str(EntityId.generate())
        created = updated = unchanged = 0
        errors: list[ItemError] = []
        seen_hashes: dict[str, str] = {}

        async with SessionUnitOfWork(self._session_factory) as uow:
            technique_repo = SqlAlchemyAttackTechniqueRepository(uow.session)
            ingestion_repo = SqlAlchemyReferenceDataIngestionRepository(uow.session)

            # See the identical comment in `upsert_techniques`: both
            # relationship technique-side FKs are DEFERRABLE, so a
            # dangling reference must be caught here, before the loop,
            # or it silently aborts the entire batch at COMMIT instead
            # of being reported as one isolated failed item. Techniques
            # are ingested via a separate prior call (`upsert_techniques`),
            # so — unlike that method — there is no "current batch" set
            # to union in here; only already-stored techniques qualify.
            known_technique_ids = await technique_repo.list_all_ids()

            for index, item in enumerate(relationships):
                try:
                    if (
                        item.source_technique_id
                        and item.source_technique_id not in known_technique_ids
                    ):
                        raise UnknownTechniqueReferenceError(item.source_technique_id)
                    if (
                        item.target_technique_id
                        and item.target_technique_id not in known_technique_ids
                    ):
                        raise UnknownTechniqueReferenceError(item.target_technique_id)

                    payload = {
                        "relationship_type": item.relationship_type,
                        "source_ref": item.source_ref,
                        "target_ref": item.target_ref,
                        "source_technique_id": item.source_technique_id,
                        "target_technique_id": item.target_technique_id,
                        "description": item.description,
                    }
                    content_hash, is_unchanged = await self._check_unchanged(
                        ingestion_repo,
                        source_system=ReferenceDataSource.MITRE_ATTACK,
                        external_id=item.stix_id,
                        payload=payload,
                    )
                    self._check_duplicate_in_batch(
                        seen_hashes,
                        source_system=ReferenceDataSource.MITRE_ATTACK,
                        external_id=item.stix_id,
                        content_hash=content_hash,
                    )
                    if is_unchanged:
                        unchanged += 1
                        continue

                    now = datetime.now(UTC)
                    relationship = AttackTechniqueRelationship(
                        stix_id=item.stix_id,
                        relationship_type=AttackRelationshipType(item.relationship_type),
                        source_ref=item.source_ref,
                        target_ref=item.target_ref,
                        source_technique_id=(
                            TechniqueId(item.source_technique_id)
                            if item.source_technique_id
                            else None
                        ),
                        target_technique_id=(
                            TechniqueId(item.target_technique_id)
                            if item.target_technique_id
                            else None
                        ),
                        description=item.description,
                        created_at=now,
                        updated_at=now,
                    )
                    await technique_repo.upsert_relationship(relationship)
                    record_created = await self._record_ingestion(
                        ingestion_repo,
                        source_system=ReferenceDataSource.MITRE_ATTACK,
                        object_type="attack_technique_relationship",
                        external_id=item.stix_id,
                        content_hash=content_hash,
                        batch_id=batch_id,
                    )
                    if record_created:
                        created += 1
                    else:
                        updated += 1
                except ValidationError as exc:
                    errors.append(ItemError(index=index, identifier=item.stix_id, message=str(exc)))

            await self._audit(
                uow.session,
                actor_id=actor_id,
                object_type="attack_technique_relationship",
                batch_id=batch_id,
                total=len(relationships),
                created=created,
                updated=updated,
            )
            await uow.commit()

        return BatchUpsertResult(
            source_system=ReferenceDataSource.MITRE_ATTACK.value,
            object_type="attack_technique_relationship",
            batch_id=batch_id,
            total=len(relationships),
            created=created,
            updated=updated,
            unchanged=unchanged,
            failed=len(errors),
            errors=errors,
        )

    async def upsert_vulnerabilities(
        self,
        *,
        actor_id: str,
        vulnerabilities: list[VulnerabilityInput],
        source_system: ReferenceDataSource = ReferenceDataSource.NVD_CVE,
        batch_id: str | None = None,
    ) -> BatchUpsertResult:
        batch_id = batch_id or str(EntityId.generate())
        created = updated = unchanged = 0
        errors: list[ItemError] = []
        seen_hashes: dict[str, str] = {}

        async with SessionUnitOfWork(self._session_factory) as uow:
            vuln_repo = SqlAlchemyVulnerabilityRepository(uow.session)
            ingestion_repo = SqlAlchemyReferenceDataIngestionRepository(uow.session)

            for index, item in enumerate(vulnerabilities):
                try:
                    payload = {
                        "description": item.description,
                        "cvss_v3_score": item.cvss_v3_score,
                        "cvss_v3_vector": item.cvss_v3_vector,
                        "cvss_v3_version": item.cvss_v3_version,
                        "cvss_v2_score": item.cvss_v2_score,
                        "epss_probability": item.epss_probability,
                        "epss_percentile": item.epss_percentile,
                        "epss_model_date": item.epss_model_date,
                        "is_kev": item.is_kev,
                        "kev_date_added": item.kev_date_added,
                        "kev_due_date": item.kev_due_date,
                        "kev_vulnerability_name": item.kev_vulnerability_name,
                        "kev_known_ransomware_use": item.kev_known_ransomware_use,
                        "published_at": item.published_at,
                        "last_modified_at": item.last_modified_at,
                    }
                    content_hash, is_unchanged = await self._check_unchanged(
                        ingestion_repo,
                        source_system=source_system,
                        external_id=item.cve_id,
                        payload=payload,
                    )
                    self._check_duplicate_in_batch(
                        seen_hashes,
                        source_system=source_system,
                        external_id=item.cve_id,
                        content_hash=content_hash,
                    )
                    if is_unchanged:
                        unchanged += 1
                        continue

                    now = datetime.now(UTC)
                    cvss_v3 = None
                    v3_score, v3_vector, v3_version = (
                        item.cvss_v3_score,
                        item.cvss_v3_vector,
                        item.cvss_v3_version,
                    )
                    if v3_score is not None and v3_vector and v3_version:
                        cvss_v3 = CvssScore(
                            version=v3_version,
                            base_score=v3_score,
                            vector=v3_vector,
                        )
                    epss = None
                    if item.epss_probability is not None and item.epss_percentile is not None:
                        epss = EpssScore(
                            probability=item.epss_probability,
                            percentile=item.epss_percentile,
                            model_date=_parse_iso_date(item.epss_model_date) or now.date(),
                        )
                    vulnerability = Vulnerability(
                        cve_id=CveId(item.cve_id),
                        description=item.description,
                        cvss_v3=cvss_v3,
                        cvss_v2_score=item.cvss_v2_score,
                        epss=epss,
                        is_kev=item.is_kev,
                        kev_date_added=_parse_iso_datetime(item.kev_date_added),
                        kev_due_date=_parse_iso_datetime(item.kev_due_date),
                        kev_vulnerability_name=item.kev_vulnerability_name,
                        kev_short_description=item.kev_short_description,
                        kev_required_action=item.kev_required_action,
                        kev_known_ransomware_use=item.kev_known_ransomware_use,
                        published_at=_parse_iso_datetime(item.published_at),
                        last_modified_at=_parse_iso_datetime(item.last_modified_at),
                        source_last_synced_at=now,
                        created_at=now,
                        updated_at=now,
                    )
                    await vuln_repo.upsert(vulnerability)
                    record_created = await self._record_ingestion(
                        ingestion_repo,
                        source_system=source_system,
                        object_type="vulnerability",
                        external_id=item.cve_id,
                        content_hash=content_hash,
                        batch_id=batch_id,
                    )
                    if record_created:
                        created += 1
                    else:
                        updated += 1
                except ValidationError as exc:
                    errors.append(ItemError(index=index, identifier=item.cve_id, message=str(exc)))

            await self._audit(
                uow.session,
                actor_id=actor_id,
                object_type="vulnerability",
                batch_id=batch_id,
                total=len(vulnerabilities),
                created=created,
                updated=updated,
            )
            await uow.commit()

        return BatchUpsertResult(
            source_system=source_system.value,
            object_type="vulnerability",
            batch_id=batch_id,
            total=len(vulnerabilities),
            created=created,
            updated=updated,
            unchanged=unchanged,
            failed=len(errors),
            errors=errors,
        )

    # ── Internal helpers ─────────────────────────────────────────────────

    @staticmethod
    def _check_duplicate_in_batch(
        seen_hashes: dict[str, str],
        *,
        source_system: ReferenceDataSource,
        external_id: str,
        content_hash: str,
    ) -> None:
        """Guard against two items in the *same* batch call sharing an
        `external_id` with conflicting content. Without this, the
        second occurrence would silently overwrite the first's write
        (last-write-wins) with no signal that the caller submitted a
        non-idempotent, self-contradictory batch — exactly the defect
        `DuplicateIngestionError` exists to name. A repeated occurrence
        with the *same* content is not an error: it naturally resolves
        to `unchanged` once the first occurrence's ingestion record is
        visible to this same transaction."""
        existing_hash = seen_hashes.get(external_id)
        if existing_hash is not None and existing_hash != content_hash:
            raise DuplicateIngestionError(source_system.value, external_id)
        seen_hashes.setdefault(external_id, content_hash)

    async def _check_unchanged(
        self,
        ingestion_repo: SqlAlchemyReferenceDataIngestionRepository,
        *,
        source_system: ReferenceDataSource,
        external_id: str,
        payload: dict[str, Any],
    ) -> tuple[str, bool]:
        """Read-only idempotency pre-check. Returns `(content_hash,
        is_unchanged)` and never writes to the ingestion log.

        This must stay read-only and run *before* the item's domain
        entity is constructed/validated. If it wrote the ingestion
        record eagerly (as an earlier version of this service did), a
        batch item that fails domain validation (e.g. a malformed
        `TechniqueId`) would still leave a "successfully ingested"
        ledger row for its `external_id` — permanently poisoning that
        id, since any later retry submitting the exact same (still
        invalid) payload would hash-match the poisoned record and be
        silently reported as `unchanged` instead of `failed`, with the
        referenced global-catalog row never actually existing. See
        `_record_ingestion` for the write half, which is only ever
        called after the corresponding repository upsert has already
        succeeded.
        """
        new_hash = _content_hash(payload)
        existing = await ingestion_repo.find(
            source_system, external_id, scope=IngestionScope.GLOBAL
        )
        is_unchanged = existing is not None and existing.content_hash == new_hash
        return new_hash, is_unchanged

    async def _record_ingestion(
        self,
        ingestion_repo: SqlAlchemyReferenceDataIngestionRepository,
        *,
        source_system: ReferenceDataSource,
        object_type: str,
        external_id: str,
        content_hash: str,
        batch_id: str,
    ) -> bool:
        """Persist the ingestion-log idempotency record for an item
        whose domain entity has *already* been successfully upserted
        into its own repository this call. Returns True if this was a
        new ingestion record, False if it updated an existing one."""
        record = ReferenceDataIngestionRecord.record(
            id=str(EntityId.generate()),
            source_system=source_system,
            object_type=object_type,
            external_id=external_id,
            content_hash=content_hash,
            scope=IngestionScope.GLOBAL,
            organization_id=None,
            batch_id=batch_id,
        )
        _, created = await ingestion_repo.upsert_record(record)
        # Domain events are collected but not yet dispatched anywhere in
        # Phase 1 (no event bus exists in this codebase — same honest
        # limitation M21's InvestigationCase events have); collecting
        # them here still exercises and documents the aggregate's event
        # contract for future wiring.
        record.collect_events()
        return created

    async def _audit(
        self,
        session: AsyncSession,
        *,
        actor_id: str,
        object_type: str,
        batch_id: str,
        total: int,
        created: int,
        updated: int,
    ) -> None:
        if total == 0:
            return
        await PostgresPlatformAuditLog(session).record(
            AuditEntry(
                action=AuditAction.REFERENCE_DATA_INGESTED,
                actor_id=actor_id,
                resource_type=object_type,
                resource_id=batch_id,
                metadata={
                    "object_type": object_type,
                    "total": str(total),
                    "created": str(created),
                    "updated": str(updated),
                },
            )
        )
