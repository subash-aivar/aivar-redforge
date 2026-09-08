"""Domain exceptions for ioc_intelligence (M51.2 Phase A).

Independent of `redforge.domain.threat_intel`, `threat_actor_intel`,
and every other bounded context's exception hierarchy — ioc_intelligence
is its own bounded context and must not import domain objects from
any of them."""

from __future__ import annotations


class IocIntelDomainError(Exception):
    """Base domain error for ioc_intelligence."""


class TenantMismatchError(IocIntelDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyIdentifierError(IocIntelDomainError):
    def __init__(self, identifier_name: str) -> None:
        super().__init__(f"{identifier_name} must be a non-empty string")


class InvalidIndicatorValueError(IocIntelDomainError):
    def __init__(self, ioc_type: str, raw_value: str, reason: str) -> None:
        self.ioc_type = ioc_type
        self.raw_value = raw_value
        super().__init__(f"Invalid {ioc_type} value {raw_value!r}: {reason}")


class InvalidIndicatorCanonicalKeyError(IocIntelDomainError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"Invalid IndicatorCanonicalKey: {key!r}")


class UnsourcedIocError(IocIntelDomainError):
    """An IOC must carry at least one real `SourceAttribution` or
    `EvidenceCitation` at construction — never fabricated, never
    sourceless (ADR-M51.2-01's provenance rule)."""

    def __init__(self) -> None:
        super().__init__(
            "IOC requires at least one SourceAttribution or EvidenceCitation — "
            "no unsourced IOC may be created"
        )


class DuplicateSourceAttributionError(IocIntelDomainError):
    def __init__(self, source_system: str, external_id: str) -> None:
        self.source_system = source_system
        self.external_id = external_id
        super().__init__(
            f"Source attribution from {source_system!r} (external_id={external_id!r}) "
            "is already recorded on this IOC"
        )


class InvalidLifecycleTransitionError(IocIntelDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(f"Invalid lifecycle transition {from_state} -> {to_state}")


class InvalidEpistemicStateTransitionError(IocIntelDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(f"Invalid epistemic-state transition {from_state} -> {to_state}")


class UnrecognizedSourceSystemError(IocIntelDomainError):
    """`SourceAttribution.source_system` must be either a real, closed
    `ProviderName` value or the one explicit internal-source sentinel
    (`IOC_INTERNAL_SOURCE_SYSTEM`) — never an arbitrary string
    (M51.2 Phase A.1 R1)."""

    def __init__(self, source_system: str) -> None:
        self.source_system = source_system
        super().__init__(
            f"Unrecognized source_system {source_system!r} — must be a known "
            "ProviderName value or the internal-source sentinel"
        )


class GlobalEvidenceCitationNotSupportedError(IocIntelDomainError):
    """Global (platform-curated, `tenant_id IS NULL`) IOCs cannot carry
    evidence citations — a deliberate, formalized product/domain policy
    (M51.2 Slice 2.1), not a temporary gap:

    An evidence citation references an existing tenant-owned
    `SecurityCondition` or `InvestigationCase` (see
    `IIocEvidenceValidationPort`); the canonical `evidence` bounded
    context itself requires a real, non-nullable `tenant_id` on every
    aggregate, with no platform/global-owned variant anywhere in that
    domain model today. A global IOC, by construction, has no tenant to
    validate a citation against — there is no safe way to check
    existence, ownership, or revocation status for an "evidence"
    reference on a record every tenant can see. Rather than invent a
    fictitious global evidence-ownership concept (which would require
    new, currently-nonexistent cross-context modeling — platform-owned
    `SecurityCondition`/`InvestigationCase` records, or a parallel
    global evidence system) to make an unverifiable claim look
    verified, this policy rejects the citation outright: global
    provenance is expressed through `source_attributions` only.

    See `GlobalEvidencePolicy` (this rejection's single home) and
    `docs/RUNBOOK_IOC_INTELLIGENCE.md` §4/§12 for the full rationale and
    the specific future architectural dependency (platform-scoped
    Evidence ownership) that would be required to lift this."""

    def __init__(self) -> None:
        super().__init__(
            "Evidence citations are not supported on global IOCs — they reference "
            "tenant-owned entities (SecurityCondition/InvestigationCase) that cannot "
            "be verified at global scope, since the canonical Evidence model has no "
            "platform/global ownership concept. Use source_attributions for global "
            "provenance instead."
        )


class MissingTenantForObservationError(IocIntelDomainError):
    """A tenant-scoped IOC observation must carry a real `tenant_id` —
    never `None` masquerading as a tenant, and never a reserved
    sentinel (ADR-M51.1-02's global-record precedent, generalized)."""

    def __init__(self) -> None:
        super().__init__(
            "A tenant-scoped IOC observation requires a real tenant_id — "
            "use tenant_id=None only for genuine global reference data"
        )
