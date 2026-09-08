"""GlobalEvidencePolicy — the single, formalized home for M51.2 Slice
2.1's "global IOCs cannot carry evidence citations" product/domain
policy (see `GlobalEvidenceCitationNotSupportedError` for the full
architectural rationale).

Before this slice, the rejection was duplicated inline across
`observe_global_ioc` and `add_evidence_citation` in
`IOCApplicationService` — same rule, same reasoning, written twice.
This policy exists so there is exactly one place that decides whether a
global evidence citation is ever allowed, mirroring
`IocLifecyclePolicy`/`EpistemicStatePolicy`'s "one policy object per
closed business rule" shape."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ioc_intelligence.domain.exceptions.domain_exceptions import (
    GlobalEvidenceCitationNotSupportedError,
)

if TYPE_CHECKING:
    from collections.abc import Collection

    from ioc_intelligence.domain.value_objects.identifiers import TenantId


class GlobalEvidencePolicy:
    @staticmethod
    def assert_evidence_citations_supported(
        tenant_id: TenantId | None, evidence_citations: Collection[object]
    ) -> None:
        """Raises `GlobalEvidenceCitationNotSupportedError` if this is a
        global scope (`tenant_id is None`) AND at least one evidence
        citation was supplied. A tenant-scoped call (real `TenantId`),
        or a global call with zero citations, is always legal — this
        policy only ever closes the one specific combination that
        cannot be safely verified."""
        if tenant_id is None and evidence_citations:
            raise GlobalEvidenceCitationNotSupportedError()
