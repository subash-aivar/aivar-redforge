from __future__ import annotations

from regulatory_notification.domain.value_objects.enums import RegulatoryRegime

_DEFAULT = {
    "EU": [
        RegulatoryRegime.GDPR_ART33,
        RegulatoryRegime.NIS2_EARLY_WARNING,
        RegulatoryRegime.NIS2_NOTIFICATION,
    ],
    "US": [RegulatoryRegime.HIPAA_BREACH, RegulatoryRegime.SEC_CYBER, RegulatoryRegime.NY_DFS_500],
    "UK": [RegulatoryRegime.UK_GDPR],
    "CA": [RegulatoryRegime.PIPEDA],
}


class JurisdictionMappingService:
    def regimes_for(self, jurisdictions: set[str]) -> list[RegulatoryRegime]:
        out: list[RegulatoryRegime] = []
        for j in jurisdictions:
            out.extend(_DEFAULT.get(j.upper(), []))
        # unique preserve order
        seen: set[RegulatoryRegime] = set()
        unique: list[RegulatoryRegime] = []
        for r in out:
            if r not in seen:
                seen.add(r)
                unique.append(r)
        return unique
