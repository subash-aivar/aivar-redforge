"""IocTTLPolicy — generalizes `redforge.domain.threat_intel.
fusion_policies.IndicatorTTLPolicy`'s exact shape for ioc_intelligence
(M51.2 Phase A): a per-`IocType` default TTL table, `valid_until()`/
`is_expired()` computed from `valid_from`. Default hours are
deliberately conservative and documented so a fresh deployment never
has undefined expiry behavior (mirrors that module's own Hardening-
Review-P1 precedent) — IP/domain/URL indicators (infrastructure that
attackers rotate) expire sooner than hash indicators (content-addressed,
so a hash observation stays operationally relevant far longer)."""

from __future__ import annotations

from datetime import datetime, timedelta

from ioc_intelligence.domain.value_objects.enums import IocType

_DEFAULT_TTL_HOURS: dict[IocType, int] = {
    IocType.IP: 24 * 7,
    IocType.DOMAIN: 24 * 14,
    IocType.URL: 24 * 7,
    IocType.HASH: 24 * 90,
}


class IocTTLPolicy:
    def __init__(self, ttl_hours: dict[IocType, int] | None = None) -> None:
        self._ttl_hours = dict(_DEFAULT_TTL_HOURS)
        if ttl_hours:
            self._ttl_hours.update(ttl_hours)

    def valid_until(self, ioc_type: IocType, *, valid_from: datetime) -> datetime | None:
        hours = self._ttl_hours.get(ioc_type)
        if hours is None:
            return None
        return valid_from + timedelta(hours=hours)

    def is_expired(self, ioc_type: IocType, *, valid_from: datetime, now: datetime) -> bool:
        until = self.valid_until(ioc_type, valid_from=valid_from)
        if until is None:
            return False
        return now > until
