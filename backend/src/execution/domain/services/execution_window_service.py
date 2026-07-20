"""ExecutionWindowService — current time must fall in authorized window."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


class ExecutionWindowService:
    @staticmethod
    def is_within_window(
        now: datetime,
        window_start: datetime | None,
        window_end: datetime | None,
    ) -> bool:
        if window_start is not None and now < window_start:
            return False
        return not (window_end is not None and now > window_end)
