"""InMemoryEventNormalizerRegistry — the one concrete registry this
milestone implements (M43D §4).

Keyed by `(provider, exact schema_version)` for registration (so two
normalizers may coexist for the same provider at different declared
versions — e.g. a v1 and a v2 normalizer during a migration window),
and resolved by `(provider, major-version compatibility)` for lookup
(M37 §2.3: minor bumps are additive, so a request for `1.0` should find
a normalizer registered at `1.0` *or* `1.3`). If more than one
registered version is compatible with a requested version, that is a
genuine ambiguity the framework cannot resolve on its own — it is
surfaced as `AmbiguousNormalizerSelectionError`, not guessed at.

No persistence, no DI container wiring — a plain in-process dict, per
this milestone's explicit scope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_normalization.application.exceptions import (
    AmbiguousNormalizerSelectionError,
    DuplicateNormalizerRegistrationError,
    UnsupportedProviderError,
    UnsupportedVersionError,
)

if TYPE_CHECKING:
    from siem_normalization.application.ports.i_event_normalizer import IEventNormalizer
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class InMemoryEventNormalizerRegistry:
    def __init__(self) -> None:
        self._by_provider: dict[str, dict[SchemaVersion, IEventNormalizer]] = {}

    def register(self, normalizer: IEventNormalizer) -> None:
        by_version = self._by_provider.setdefault(normalizer.provider, {})
        if normalizer.schema_version in by_version:
            raise DuplicateNormalizerRegistrationError(
                normalizer.provider, normalizer.schema_version
            )
        by_version[normalizer.schema_version] = normalizer

    def resolve(self, provider: str, requested_version: SchemaVersion) -> IEventNormalizer:
        by_version = self._by_provider.get(provider)
        if not by_version:
            raise UnsupportedProviderError(provider)

        compatible = [
            (version, normalizer)
            for version, normalizer in by_version.items()
            if version.is_compatible_with(requested_version)
        ]
        if not compatible:
            raise UnsupportedVersionError(provider, requested_version)
        if len(compatible) > 1:
            raise AmbiguousNormalizerSelectionError(
                provider,
                requested_version,
                tuple(version for version, _ in compatible),
            )
        return compatible[0][1]

    def is_registered(self, provider: str, schema_version: SchemaVersion) -> bool:
        return schema_version in self._by_provider.get(provider, {})
