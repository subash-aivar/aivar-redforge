"""Default asset normalizer — validates and cleans raw discovered asset inputs.

Responsibilities:
- Strip and validate required fields (name, asset_type, external_id).
- Normalize asset_type to a valid AssetType enum value.
- Deduplicate inputs by (organization_id, external_id).
- Ensure metadata keys/values are clean strings.
- Produce NormalizedAssetInput records ready for fingerprinting.

No switch statements. Asset type validation uses a frozenset.
"""

from __future__ import annotations

from redforge.application.inventory.contracts import (
    DiscoveredAssetInput,
    NormalizedAssetInput,
)
from redforge.domain.inventory.value_objects import AssetType

_VALID_ASSET_TYPES: frozenset[str] = frozenset(t.value for t in AssetType)


class DefaultAssetNormalizer:
    """Stateless default normalizer.

    Implements AssetNormalizerPort.
    - Skips inputs with missing/invalid required fields (logs warning).
    - Deduplicates by (organization_id, external_id) — last wins.
    - Truncates metadata values to 1024 chars.
    """

    _MAX_META_VALUE_LEN = 1024
    _MAX_NAME_LEN = 512

    def normalize(
        self, inputs: list[DiscoveredAssetInput]
    ) -> list[NormalizedAssetInput]:
        """Normalize and deduplicate a list of discovered asset inputs."""
        seen: dict[tuple[str, str], NormalizedAssetInput] = {}

        for raw in inputs:
            normalized = self._normalize_one(raw)
            if normalized is None:
                continue
            key = (normalized.organization_id, normalized.external_id)
            seen[key] = normalized  # last-wins deduplication

        return list(seen.values())

    def _normalize_one(
        self, raw: DiscoveredAssetInput
    ) -> NormalizedAssetInput | None:
        name = raw.name.strip()
        if not name:
            return None

        asset_type = raw.asset_type.strip().lower()
        if asset_type not in _VALID_ASSET_TYPES:
            return None

        org_id = raw.organization_id.strip()
        if not org_id:
            return None

        external_id = raw.external_id.strip() or f"manual:{name.lower().replace(' ', '_')}"
        description = raw.description.strip()[:2048]

        # Sanitize metadata
        clean_meta: dict[str, str] = {}
        for k, v in raw.metadata.items():
            k_clean = k.strip()[:128]
            if k_clean:
                clean_meta[k_clean] = str(v).strip()[:self._MAX_META_VALUE_LEN]

        # Sanitize fingerprint_fields (subset of metadata with stable keys)
        clean_fp: dict[str, str] = {}
        for k, v in raw.fingerprint_fields.items():
            k_clean = k.strip()[:128]
            if k_clean:
                clean_fp[k_clean] = str(v).strip()[:self._MAX_META_VALUE_LEN]

        # If no explicit fingerprint_fields, derive from metadata
        if not clean_fp:
            from redforge.application.inventory.fingerprint_engine import (
                extract_fingerprint_fields,
            )
            clean_fp = extract_fingerprint_fields(asset_type, clean_meta)

        return NormalizedAssetInput(
            name=name[:self._MAX_NAME_LEN],
            asset_type=asset_type,
            external_id=external_id,
            discovery_source=raw.discovery_source.strip() or "manual",
            organization_id=org_id,
            description=description,
            fingerprint_fields=clean_fp,
            metadata=clean_meta,
            dependency_external_ids=tuple(
                d.strip() for d in raw.dependency_external_ids if d.strip()
            ),
            relationship_hints=tuple(
                (t.strip(), r.strip())
                for t, r in raw.relationship_hints
                if t.strip() and r.strip()
            ),
        )
