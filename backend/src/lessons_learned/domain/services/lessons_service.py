from __future__ import annotations


class LessonsLearnedService:
    def quality_score(self, lesson_count: int, action_count: int) -> float:
        return float(min(100, lesson_count * 10 + action_count * 5))
