"""Repository protocols for the Threat Intelligence Reference Data
sub-context — M22 Phase 1.

All I/O goes through these protocols. Infrastructure implementations
provide the real PostgreSQL behavior. Mirrors the exact
`@runtime_checkable Protocol` shape of
`domain/investigations/repository.py` (M21).

Every method here operates on GLOBAL reference data — none of these
protocols accept or filter by `organization_id`, because the tables
they front (`attack_tactics`, `attack_techniques`,
`attack_technique_relationships`, `vulnerabilities`) carry no
`organization_id` column at all. `ReferenceDataIngestionRepository` is
the sole exception: it fronts `stix_ingestion_log`, which does carry an
(nullable) `organization_id` to support the future TENANT scope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.threat_intel.attack_technique_entity import (
        AttackTactic,
        AttackTechnique,
        AttackTechniqueRelationship,
    )
    from redforge.domain.threat_intel.reference_data_ingestion import (
        ReferenceDataIngestionRecord,
    )
    from redforge.domain.threat_intel.reference_data_value_objects import (
        AttackRelationshipType,
        IngestionScope,
        ReferenceDataSource,
    )
    from redforge.domain.threat_intel.vulnerability_entity import Vulnerability


@runtime_checkable
class AttackTacticRepository(Protocol):
    """Port for MITRE ATT&CK tactic persistence."""

    async def upsert(self, tactic: AttackTactic) -> AttackTactic:
        """Idempotent upsert keyed on `tactic_id`. Returns the stored
        (post-upsert) entity."""
        ...

    async def get_by_id(self, tactic_id: str) -> AttackTactic | None:
        ...

    async def list_all(self, *, limit: int = 200, offset: int = 0) -> list[AttackTactic]:
        ...

    async def count(self) -> int:
        ...

    async def list_all_ids(self) -> set[str]:
        """All currently-stored `tactic_id` values, for reference
        validation by callers — not a paginated read model."""
        ...


@runtime_checkable
class AttackTechniqueRepository(Protocol):
    """Port for MITRE ATT&CK technique persistence, including the
    technique-to-technique relationship graph."""

    async def upsert(self, technique: AttackTechnique) -> AttackTechnique:
        """Idempotent upsert keyed on `technique_id`. Returns the stored
        (post-upsert) entity."""
        ...

    async def get_by_id(self, technique_id: str) -> AttackTechnique | None:
        ...

    async def list_by_tactic(
        self, tactic_id: str, *, limit: int = 200, offset: int = 0
    ) -> list[AttackTechnique]:
        ...

    async def list_sub_techniques(self, parent_technique_id: str) -> list[AttackTechnique]:
        ...

    async def search_by_name(
        self, query: str, *, limit: int = 50, offset: int = 0
    ) -> list[AttackTechnique]:
        """Full-text search over technique names (backed by a GIN index
        — see migration 0035). Never a full-table LIKE scan."""
        ...

    async def count(self) -> int:
        ...

    async def list_all_ids(self) -> set[str]:
        """All currently-stored `technique_id` values, for reference
        validation by callers — not a paginated read model."""
        ...

    async def upsert_relationship(
        self, relationship: AttackTechniqueRelationship
    ) -> AttackTechniqueRelationship:
        """Idempotent upsert keyed on the relationship's own `stix_id`."""
        ...

    async def list_relationships_for_technique(
        self,
        technique_id: str,
        *,
        relationship_type: AttackRelationshipType | None = None,
    ) -> list[AttackTechniqueRelationship]:
        """Relationships where `technique_id` is on either the source or
        target side."""
        ...


@runtime_checkable
class VulnerabilityRepository(Protocol):
    """Port for CVE / CVSS / EPSS / CISA KEV persistence."""

    async def upsert(self, vulnerability: Vulnerability) -> Vulnerability:
        """Idempotent upsert keyed on `cve_id`. Returns the stored
        (post-upsert) entity."""
        ...

    async def get_by_cve_id(self, cve_id: str) -> Vulnerability | None:
        ...

    async def list_by_kev_flag(
        self, is_kev: bool = True, *, limit: int = 200, offset: int = 0
    ) -> list[Vulnerability]:
        ...

    async def list_by_epss_threshold(
        self, min_probability: float, *, limit: int = 200, offset: int = 0
    ) -> list[Vulnerability]:
        ...

    async def count(self) -> int:
        ...


@runtime_checkable
class ReferenceDataIngestionRepository(Protocol):
    """Port for the `stix_ingestion_log` idempotency gate."""

    async def upsert_record(
        self, record: ReferenceDataIngestionRecord
    ) -> tuple[ReferenceDataIngestionRecord, bool]:
        """Insert the ingestion record, or update the existing row for
        this idempotency key (source_system, external_id, scope[, org])
        in place when one already exists. Returns `(record, created)`
        where `created` is True only when no prior row existed.

        This table tracks the CURRENT ingestion fact for each external
        object, not a full history — the caller (the reference-data
        admin loading service) is responsible for skipping this call
        entirely when the incoming `content_hash` matches the existing
        row's hash, so an unchanged re-submission never touches this
        table and never fires a domain event.
        """
        ...

    async def find(
        self,
        source_system: ReferenceDataSource,
        external_id: str,
        *,
        scope: IngestionScope,
        organization_id: str | None = None,
    ) -> ReferenceDataIngestionRecord | None:
        ...

    async def list_recent(
        self,
        *,
        source_system: ReferenceDataSource | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ReferenceDataIngestionRecord]:
        ...

    async def count_by_source(self, source_system: ReferenceDataSource) -> int:
        ...
