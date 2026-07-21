from __future__ import annotations

from typing import Any

from lessons_learned.domain.events.lessons_events import CampaignRetargetingSuggested


class CampaignRetargetingAdvisoryService:
    def extract_events(self, events: list[Any]) -> list[CampaignRetargetingSuggested]:
        return [e for e in events if isinstance(e, CampaignRetargetingSuggested)]
