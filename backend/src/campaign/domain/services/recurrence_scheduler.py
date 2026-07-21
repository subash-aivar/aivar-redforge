"""RecurrenceScheduler — domain service for recurring campaign scheduling.

Translates RecurrencePolicy to ISchedulerPort registrations.
Enforces blackout periods, consecutive failure detection, and overlap prevention.
"""

from __future__ import annotations

from datetime import UTC
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from campaign.domain.aggregates.campaign import Campaign
    from campaign.domain.aggregates.campaign_instance import CampaignInstance
    from campaign.domain.ports.i_scheduler_port import ISchedulerPort
    from campaign.domain.value_objects.campaign_vos import RecurrencePolicy


class RecurrenceScheduler:
    """Translates RecurrencePolicy to scheduled execution events.

    Registers with ISchedulerPort. Fires CampaignScheduleFired at scheduled time.

    Hardening rules enforced:
    - Overlap prevention: skip fire if previous instance still running
    - Blackout enforcement: skip fire if within a blackout period
    - Consecutive failure: pause campaign after max_consecutive_failures
    - Scheduler recovery: query Starting instances on restart to avoid duplicates
    """

    _MAX_SKIP_COUNT: int = 3  # Configurable; default 3 as per architecture spec

    async def register(
        self,
        campaign: Campaign,
        port: ISchedulerPort,
    ) -> str:
        """Register the campaign's recurrence policy with the scheduler."""
        schedule = campaign.campaign_schedule
        if schedule is None:
            raise ValueError(
                f"Campaign '{campaign.campaign_id}' has no RecurrencePolicy to register"
            )
        return await port.register_schedule(
            campaign_id=campaign.campaign_id,
            tenant_id=campaign.tenant_id,
            policy=schedule.to_recurrence_policy(),
        )

    async def cancel(
        self,
        campaign: Campaign,
        job_id: str,
        port: ISchedulerPort,
    ) -> None:
        """Cancel the campaign's registered schedule."""
        await port.cancel_schedule(
            campaign_id=campaign.campaign_id,
            tenant_id=campaign.tenant_id,
            job_id=job_id,
        )

    def is_in_blackout(
        self,
        policy: RecurrencePolicy,
        fire_time: datetime,
    ) -> bool:
        """Check if the given fire_time falls within any blackout period.

        Blackout periods are stored as strings in one of these formats:
        - "HH:MM-HH:MM" (daily window)
        - "YYYY-MM-DDTHH:MM/YYYY-MM-DDTHH:MM" (absolute ISO-8601 interval)
        - "weekday:0,6" (day-of-week specification: 0=Mon, 6=Sun)
        """

        ft = fire_time.astimezone(UTC)

        return any(self._matches_blackout_period(period, ft) for period in policy.blackout_periods)

    def _matches_blackout_period(self, period: str, ft: object) -> bool:
        from datetime import datetime

        if not isinstance(ft, datetime):
            return False

        period = period.strip()

        # Daily HH:MM-HH:MM format
        if len(period) == 11 and period[2] == ":" and period[5] == "-":
            try:
                start_str, end_str = period.split("-", 1)
                start_h, start_m = int(start_str[:2]), int(start_str[3:])
                end_h, end_m = int(end_str[:2]), int(end_str[3:])
                fire_minutes = ft.hour * 60 + ft.minute
                start_minutes = start_h * 60 + start_m
                end_minutes = end_h * 60 + end_m
                if start_minutes <= end_minutes:
                    return start_minutes <= fire_minutes < end_minutes
                # Overnight window
                return fire_minutes >= start_minutes or fire_minutes < end_minutes
            except (ValueError, IndexError):
                return False

        # ISO-8601 interval: "YYYY-MM-DDTHH:MM/YYYY-MM-DDTHH:MM"
        if "/" in period and "T" in period:
            try:
                start_str, end_str = period.split("/", 1)
                start_dt = datetime.fromisoformat(start_str).replace(tzinfo=UTC)
                end_dt = datetime.fromisoformat(end_str).replace(tzinfo=UTC)
                return start_dt <= ft <= end_dt
            except ValueError:
                return False

        # Weekday specification: "weekday:0,6"
        if period.startswith("weekday:"):
            try:
                days_str = period[len("weekday:") :]
                days = {int(d.strip()) for d in days_str.split(",")}
                return ft.weekday() in days
            except ValueError:
                return False

        return False

    def should_skip_due_to_running_instance(
        self,
        running_instances: list[CampaignInstance],
    ) -> bool:
        """Return True if there is already a running instance (overlap prevention)."""
        from campaign.domain.value_objects.enums import InstanceState

        return any(
            inst.state in {InstanceState.STARTING, InstanceState.RUNNING, InstanceState.PAUSED}
            for inst in running_instances
        )

    def check_consecutive_failures(
        self,
        campaign: Campaign,
        recent_instances: list[CampaignInstance],
        now: datetime,
    ) -> bool:
        """Return True if campaign should be paused due to consecutive failures.

        Examines the most recent N instances (where N = max_consecutive_failures).
        If all N are failed, pauses the campaign and emits RecurringCampaignPaused.
        """
        from campaign.domain.value_objects.enums import InstanceState

        policy = campaign.campaign_schedule
        if policy is None:
            return False

        max_fail = policy.max_consecutive_failures
        if not recent_instances:
            return False

        last_n = recent_instances[-max_fail:]
        if len(last_n) < max_fail:
            return False

        all_failed = all(
            inst.state in {InstanceState.FAILED, InstanceState.ABORTED} for inst in last_n
        )
        if all_failed:
            campaign.pause_recurring_due_to_failures(
                consecutive_failure_count=max_fail,
                now=now,
            )
            return True
        return False

    async def compute_next_fire_time(
        self,
        cron_expression: str,
        after: datetime,
        port: ISchedulerPort,
    ) -> datetime:
        """Compute the next fire time using the scheduler port."""
        return await port.get_next_fire_time(cron_expression, after)

    def compute_next_fire_time_local(
        self,
        cron_expression: str,
        after: datetime,
    ) -> datetime:
        """Compute next fire time locally using croniter (no port required).

        Used in unit tests and places where the port is unavailable.
        """
        from datetime import datetime

        from croniter import croniter

        it = croniter(cron_expression, after)
        result: datetime = it.get_next(datetime)
        return result

    async def recover_after_restart(
        self,
        port: ISchedulerPort,
        tenant_id: object,
        campaigns_with_starting_instances: set[str],
    ) -> list[dict[str, str]]:
        """List active schedules safe to keep after restart (no duplicate fires).

        Schedules whose campaign already has a Starting instance are excluded so
        restart mid-window does not create duplicate instances.
        """
        active = await port.list_active_schedules(tenant_id)  # type: ignore[arg-type]
        return [
            entry
            for entry in active
            if entry.get("campaign_id") not in campaigns_with_starting_instances
        ]

    async def register_one_shot(
        self,
        campaign: Campaign,
        fire_at: datetime,
        port: ISchedulerPort,
    ) -> str:
        """Register a one-shot absolute fire time with the scheduler port."""
        return await port.register_one_shot(
            campaign_id=campaign.campaign_id,
            tenant_id=campaign.tenant_id,
            fire_at=fire_at,
        )
