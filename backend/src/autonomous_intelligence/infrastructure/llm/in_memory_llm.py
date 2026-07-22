from __future__ import annotations

from autonomous_intelligence.domain.exceptions.domain_exceptions import TenantIsolationViolation
from autonomous_intelligence.domain.value_objects.evidence import LLMPrompt, LLMResponse
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class InMemoryLLMInferenceAdapter:
    """Single-tenant LLM adapter — never batches across tenants."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def generate(self, prompt: LLMPrompt, tenant_id: TenantId) -> LLMResponse:
        if prompt.tenant_id.value != tenant_id.value:
            raise TenantIsolationViolation("prompt tenant mismatch at port")
        for doc in prompt.context_documents:
            if doc.tenant_id.value != tenant_id.value:
                raise TenantIsolationViolation("document tenant mismatch at port")
        self.calls.append(str(tenant_id))
        return LLMResponse(
            content='{"suggestion":"ok"}',
            model_id="in-memory-llm",
            prompt_token_count=len(prompt.task_instruction.split()),
            completion_token_count=5,
            latency_ms=12,
        )
