"""Local MaxMind GeoLite2 `.mmdb` reader — the preferred geolocation
path (Priority 2): zero per-IP network egress, because the database is
read entirely offline once the operator has downloaded it.

We deliberately do NOT bundle, auto-download, or redistribute the
database file itself — the GeoLite2 EULA (maxmind.com/en/geolite/eula)
requires the operator's own account + signed EULA + license key to
obtain it, and forbids third parties (us) from redistributing it. The
operator configures a filesystem path to their own copy; if that path
is unset or the file is missing, this provider reports NOT_CONFIGURED
rather than failing loudly or fabricating a fallback location.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redforge.domain.threat_intel.results import GeoEnrichment

logger = logging.getLogger(__name__)

_PROVIDER = "maxmind_geolite_local"


class GeoLiteDatabaseUnavailableError(Exception):
    """Raised when no valid `.mmdb` file is configured/reachable — this
    is an expected, honest condition (NOT_CONFIGURED), not a bug."""


def _dict_field(record: dict[str, Any], key: str) -> dict[str, Any]:
    """The `maxminddb` reader returns a loosely-typed `Record` union per
    field; every nested field we read here is documented by MaxMind as
    an object, so we narrow to `dict` defensively rather than trusting
    the library's own type stub."""
    value = record.get(key)
    return value if isinstance(value, dict) else {}


def _str_field(d: dict[str, Any], key: str) -> str | None:
    value = d.get(key)
    return value if isinstance(value, str) else None


def _float_field(d: dict[str, Any], key: str) -> float | None:
    value = d.get(key)
    return float(value) if isinstance(value, (int, float)) else None


def lookup_ip(mmdb_path: str, ip: str) -> GeoEnrichment | None:
    """Pure, local, offline lookup. Returns None if the IP has no entry
    in the database (a real negative result) or the file itself is
    unusable (logged, never raised as a user-facing error — callers
    treat this the same as "not found")."""
    path = Path(mmdb_path)
    if not path.is_file():
        raise GeoLiteDatabaseUnavailableError(f"no GeoLite2 database at {mmdb_path}")

    import maxminddb

    now = datetime.now(UTC).isoformat()
    try:
        with maxminddb.open_database(str(path)) as reader:
            raw_record = reader.get(ip)
            build_epoch = getattr(reader.metadata(), "build_epoch", None)
    except (OSError, ValueError) as exc:
        raise GeoLiteDatabaseUnavailableError(f"failed to read GeoLite2 database: {exc}") from exc

    if not isinstance(raw_record, dict):
        return None
    record: dict[str, Any] = raw_record

    country = _dict_field(record, "country")
    city = _dict_field(record, "city")
    subdivisions = record.get("subdivisions")
    first_subdivision = (
        subdivisions[0]
        if isinstance(subdivisions, list) and subdivisions and isinstance(subdivisions[0], dict)
        else {}
    )
    location = _dict_field(record, "location")
    traits = _dict_field(record, "traits")
    asn_number = traits.get("autonomous_system_number")

    return GeoEnrichment(
        provider=_PROVIDER,
        indicator=ip,
        country=_str_field(_dict_field(country, "names"), "en"),
        country_code=_str_field(country, "iso_code"),
        region=_str_field(_dict_field(first_subdivision, "names"), "en"),
        city=_str_field(_dict_field(city, "names"), "en"),
        latitude=_float_field(location, "latitude"),
        longitude=_float_field(location, "longitude"),
        asn=str(asn_number) if isinstance(asn_number, int) else None,
        organization=_str_field(traits, "autonomous_system_organization"),
        timezone=_str_field(location, "time_zone"),
        is_approximate=True,
        database_version_or_fetched_at=str(build_epoch) if build_epoch is not None else now,
        fetched_at=now,
    )
