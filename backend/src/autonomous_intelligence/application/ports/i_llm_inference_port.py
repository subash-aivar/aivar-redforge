from __future__ import annotations

from typing import Protocol

from autonomous_intelligence.domain.value_objects.evidence import LLMPrompt, LLMResponse
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class ILLMInferencePort(Protocol):
    async def generate(self, prompt: LLMPrompt, tenant_id: TenantId) -> LLMResponse: ...
