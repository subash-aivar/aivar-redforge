from __future__ import annotations

from lessons_learned.domain.events.lessons_events import KnowledgeFeedbackPublished


class KnowledgeFeedbackService:
    def from_events(self, events: list[object]) -> list[KnowledgeFeedbackPublished]:
        return [e for e in events if isinstance(e, KnowledgeFeedbackPublished)]
