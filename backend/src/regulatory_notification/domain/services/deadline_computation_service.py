from __future__ import annotations

from datetime import UTC, datetime, timedelta

from regulatory_notification.domain.value_objects.enums import RegulatoryRegime
from regulatory_notification.domain.value_objects.vos import NotificationDeadline

_HOURS: dict[RegulatoryRegime, int] = {
    RegulatoryRegime.GDPR_ART33: 72,
    RegulatoryRegime.GDPR_ART34: 72,  # advisory
    RegulatoryRegime.HIPAA_BREACH: 60 * 24,
    RegulatoryRegime.NIS2_EARLY_WARNING: 24,
    RegulatoryRegime.NIS2_NOTIFICATION: 72,
    RegulatoryRegime.NY_DFS_500: 72,
    RegulatoryRegime.UK_GDPR: 72,
    RegulatoryRegime.PIPEDA: 72,
}


class RegulatoryDeadlineComputationService:
    """NotificationDeadlineService — frozen regime windows."""

    def compute(
        self,
        regime: RegulatoryRegime,
        clock_started_at: datetime,
        *,
        first_containment_authorized_at: datetime | None = None,
    ) -> NotificationDeadline:
        start = (
            clock_started_at if clock_started_at.tzinfo else clock_started_at.replace(tzinfo=UTC)
        )
        if regime == RegulatoryRegime.SEC_CYBER:
            base = first_containment_authorized_at or start
            if base.tzinfo is None:
                base = base.replace(tzinfo=UTC)
            deadline_at = self._add_business_days(base, 4)
            hours = int((deadline_at - base).total_seconds() // 3600)
            return NotificationDeadline(deadline_at, hours, regime.value, base, advisory=False)
        hours = _HOURS[regime]
        deadline_at = start + timedelta(hours=hours)
        advisory = regime == RegulatoryRegime.GDPR_ART34
        return NotificationDeadline(deadline_at, hours, regime.value, start, advisory=advisory)

    def _add_business_days(self, start: datetime, days: int) -> datetime:
        cur = start
        added = 0
        while added < days:
            cur += timedelta(days=1)
            if cur.weekday() < 5:
                added += 1
        return cur
