from __future__ import annotations

import pytest

from autonomous_intelligence.domain.exceptions.domain_exceptions import TenantIsolationViolation
from autonomous_intelligence.domain.value_objects.evidence import LLMPrompt, TenantScopedDocument
from autonomous_intelligence.domain.value_objects.identifiers import TenantId
from autonomous_intelligence.infrastructure.llm.in_memory_llm import InMemoryLLMInferenceAdapter


def test_llm_prompt_tenant_isolation_enforced() -> None:
    t1 = TenantId.generate()
    t2 = TenantId.generate()
    with pytest.raises(TenantIsolationViolation):
        LLMPrompt(
            tenant_id=t1,
            system_instruction="sys",
            context_documents=(TenantScopedDocument(tenant_id=t2, content="x", source_ref="s"),),
            task_instruction="task",
            max_tokens=100,
        )


@pytest.mark.asyncio
async def test_port_rejects_mismatched_tenant() -> None:
    adapter = InMemoryLLMInferenceAdapter()
    t1 = TenantId.generate()
    prompt = LLMPrompt(
        tenant_id=t1,
        system_instruction="sys",
        context_documents=(),
        task_instruction="task",
        max_tokens=50,
    )
    with pytest.raises(TenantIsolationViolation):
        await adapter.generate(prompt, TenantId.generate())
