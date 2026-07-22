from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True, slots=True)
class HuntLLMPrompt:
    tenant_id: UUID
    task: str
    context: str


@dataclass(frozen=True, slots=True)
class HuntLLMResponse:
    detection_logic: str
    confidence: float


class ILLMInferencePort(Protocol):
    async def generate(self, prompt: HuntLLMPrompt, tenant_id: UUID) -> HuntLLMResponse: ...
