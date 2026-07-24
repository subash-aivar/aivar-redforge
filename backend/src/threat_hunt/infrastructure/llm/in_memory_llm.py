from __future__ import annotations

from threat_hunt.application.ports.i_llm_inference_port import HuntLLMPrompt, HuntLLMResponse
from threat_hunt.domain.exceptions.domain_exceptions import TenantIsolationViolation
from threat_hunt.domain.value_objects.identifiers import TenantId


class InMemoryHuntLLMAdapter:
    async def generate(self, prompt: HuntLLMPrompt, tenant_id: TenantId) -> HuntLLMResponse:
        if prompt.tenant_id != tenant_id:
            raise TenantIsolationViolation("hunt llm tenant mismatch")
        return HuntLLMResponse(detection_logic="selection: true", confidence=0.8)
