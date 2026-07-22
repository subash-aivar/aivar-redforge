from __future__ import annotations

from uuid import UUID

from threat_hunt.application.ports.i_llm_inference_port import HuntLLMPrompt, HuntLLMResponse
from threat_hunt.domain.exceptions.domain_exceptions import TenantIsolationViolation


class InMemoryHuntLLMAdapter:
    async def generate(self, prompt: HuntLLMPrompt, tenant_id: UUID) -> HuntLLMResponse:
        if prompt.tenant_id != tenant_id:
            raise TenantIsolationViolation("hunt llm tenant mismatch")
        return HuntLLMResponse(detection_logic="selection: true", confidence=0.8)
