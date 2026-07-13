"""Payload generator implementations.

StaticPayloadGenerator: uses pre-defined templates/content.
Future: DynamicPayloadGenerator, LLMPayloadGenerator.
"""

from __future__ import annotations

from redforge.application.runtime.attacks.context import AttackExecutionContext
from redforge.application.runtime.attacks.contracts import GeneratedPayload


class StaticPayloadGenerator:
    """Generates payloads from static template content.

    The simplest generator: takes a fixed template string and
    merges context metadata into variables.

    Suitable for:
    - Known prompt injection patterns
    - Standard jailbreak prompts
    - Fixed probe payloads
    """

    def __init__(self, template_content: str) -> None:
        self._template = template_content

    async def generate(self, context: AttackExecutionContext) -> GeneratedPayload:
        """Return the static template with context-derived variables."""
        variables = {
            "target_name": context.target.name,
            "target_type": context.target.target_type,
            "attack_name": context.attack.attack_name,
            "attack_category": context.attack.category,
            **context.attack.extra,
        }
        return GeneratedPayload(
            template_content=self._template,
            variables=variables,
            metadata={"generator": "static"},
        )


class TemplateLibraryGenerator:
    """Generates payloads from a library of templates.

    Selects a template based on attack category and context.
    Templates are provided at construction time — no infrastructure deps.
    """

    def __init__(self, templates: dict[str, list[str]]) -> None:
        """Initialize with templates keyed by category.

        Args:
            templates: {"prompt_injection": ["template1", "template2"], ...}
        """
        self._templates = templates
        self._index: dict[str, int] = {}

    async def generate(self, context: AttackExecutionContext) -> GeneratedPayload:
        """Select next template for the attack's category."""
        category = context.attack.category
        available = self._templates.get(category, [])
        if not available:
            # Fallback: use a generic probe
            return GeneratedPayload(
                template_content="{{payload}}",
                variables={"payload": f"Test probe for {context.attack.attack_name}"},
            )

        # Round-robin through templates
        idx = self._index.get(category, 0)
        template = available[idx % len(available)]
        self._index[category] = idx + 1

        variables = {
            "target_name": context.target.name,
            "attack_name": context.attack.attack_name,
        }
        return GeneratedPayload(
            template_content=template,
            variables=variables,
            metadata={"generator": "template_library", "template_index": str(idx)},
        )
