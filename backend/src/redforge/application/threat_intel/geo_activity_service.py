"""Geo Security Activity Service — M18 real geographic map.

Aggregates real enriched IP indicators into per-IP geographic events for
the Command Center geographic activity map. Only public IPs with at least
one successful geolocation or ASN/RDAP enrichment appear — never invented
points.

Geolocation is approximate enrichment. Country attribution is based on
registry data / coarse geo databases; it is NOT proof of attack origin.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class GeoActivityPoint:
    """One enriched public IP observed for this organization. Fields only
    populated when the underlying provider actually returned that data."""

    ip: str
    country: str | None
    country_code: str | None
    region: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    asn: str | None
    network_prefix: str | None
    organization: str | None
    rir_source: str | None
    geo_provider: str | None
    asn_provider: str | None
    first_seen_at: str
    last_seen_at: str
    # Reputation evidence summary (provider names that flagged this IP)
    reputation_providers: list[str]


class GeoActivityService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_geo_activity(
        self,
        organization_id: str,
        limit: int = 500,
    ) -> list[GeoActivityPoint]:
        from redforge.infrastructure.database.repositories.threat_intel_repository import (
            SqlAlchemyThreatIntelEnrichmentRepository,
        )

        enrichment_repo = SqlAlchemyThreatIntelEnrichmentRepository(self._session)

        pairs = await enrichment_repo.list_geo_enrichments_for_org(organization_id, limit)

        # Group by indicator, collecting all enrichment rows
        by_indicator: dict[str, dict[str, Any]] = {}
        for indicator_model, enrichment_model in pairs:
            iid = indicator_model.id
            if iid not in by_indicator:
                by_indicator[iid] = {
                    "ip": indicator_model.indicator,
                    "first_seen_at": indicator_model.first_seen_at.isoformat(),
                    "last_seen_at": indicator_model.last_seen_at.isoformat(),
                    "geo": None,
                    "asn": None,
                }
            rec = by_indicator[iid]
            data = enrichment_model.data or {}
            if enrichment_model.kind == "geolocation" and rec["geo"] is None:
                rec["geo"] = (data, enrichment_model.provider_name)
            elif enrichment_model.kind == "asn_rdap" and rec["asn"] is None:
                rec["asn"] = (data, enrichment_model.provider_name)

        # Load reputation summaries for the same indicators
        rep_enrichments = await enrichment_repo.list_recent_for_org(organization_id, limit * 3)
        rep_by_indicator: dict[str, list[str]] = {}
        for e in rep_enrichments:
            if e.kind == "reputation" and e.success:
                rep_by_indicator.setdefault(e.indicator_id, [])
                if e.provider_name not in rep_by_indicator[e.indicator_id]:
                    rep_by_indicator[e.indicator_id].append(e.provider_name)

        points: list[GeoActivityPoint] = []
        for iid, rec in by_indicator.items():
            geo_data, geo_provider = rec["geo"] if rec["geo"] else ({}, None)
            asn_data, asn_provider = rec["asn"] if rec["asn"] else ({}, None)

            # Prefer geolocation for lat/lon/city; fall back to asn_rdap for country
            lat = _float(geo_data.get("latitude"))
            lon = _float(geo_data.get("longitude"))
            country = geo_data.get("country") or asn_data.get("country")
            country_code = geo_data.get("country_code")
            region = geo_data.get("region")
            city = geo_data.get("city")
            asn = geo_data.get("asn") or asn_data.get("asn")
            network_prefix = asn_data.get("network_prefix")
            org_name = geo_data.get("organization") or asn_data.get("organization")
            rir_source = asn_data.get("rir_source")

            points.append(
                GeoActivityPoint(
                    ip=rec["ip"],
                    country=country,
                    country_code=country_code,
                    region=region,
                    city=city,
                    latitude=lat,
                    longitude=lon,
                    asn=asn,
                    network_prefix=network_prefix,
                    organization=org_name,
                    rir_source=rir_source,
                    geo_provider=geo_provider,
                    asn_provider=asn_provider,
                    first_seen_at=rec["first_seen_at"],
                    last_seen_at=rec["last_seen_at"],
                    reputation_providers=rep_by_indicator.get(iid, []),
                )
            )
        return points


def _float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None
