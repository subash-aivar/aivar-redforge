"""IEventNormalizer — the one open extension point this framework
exists to support (M37 §17: "new normalizers register against
siem_normalization's registry, same open/closed shape as Integration
Hub's NormalizerRegistry").

No concrete implementation lives in this milestone — a provider-
specific normalizer (AWS, Okta, Syslog, ...) is explicitly out of scope
per M43D. This is the contract a future one must satisfy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from redforge.shared.identifiers import EntityId
    from siem_normalization.application.ports.normalized_event_draft import NormalizedEventDraft
    from siem_shared.domain.value_objects.event_source import EventSourceType
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class IEventNormalizer(Protocol):
    """`provider` + `schema_version` together are the registry key
    (M43D §4/§5) — `schema_version` is the CEM schema version *this
    normalizer emits*, per M37 §2.3's "normalizers declare which CEM
    major version they emit"."""

    @property
    def provider(self) -> str: ...

    @property
    def source_type(self) -> EventSourceType: ...

    @property
    def schema_version(self) -> SchemaVersion: ...

    def normalize(
        self, raw_payload: Mapping[str, object], tenant_id: EntityId
    ) -> NormalizedEventDraft:
        """Map a provider-native payload to CEM-shaped semantic fields.
        Implementations should raise on a payload they cannot map — the
        framework translates that into a `FAILED_NORMALIZATION` result
        and a `NormalizationFailed` domain event (M37 §2.4: failures are
        first-class, never silent drops), it does not swallow it."""
        ...
