"""Prompt & Payload Engine bounded context.

Creates executable payloads from reusable templates. Attack definitions
describe intent; payload templates describe implementation. The execution
engine receives only rendered payloads.

Payload Intelligence Engine (added on top of PayloadTemplate): converts
an AttackPlan into PayloadBundle — versioned, capability/provider-aware,
optionally-mutated ExecutionArtifacts. See payload_pipeline.py's
PayloadIntelligenceEngine and protocols.py for the pipeline; bundle.py
for the PayloadBundle aggregate.
"""

from redforge.domain.payloads.bundle import PayloadBundle
from redforge.domain.payloads.bundle_repository import PayloadBundleRepository
from redforge.domain.payloads.entity import PayloadTemplate
from redforge.domain.payloads.mutations import MUTATION_REGISTRY
from redforge.domain.payloads.payload_pipeline import PayloadIntelligenceEngine
from redforge.domain.payloads.payload_value_objects import (
    BundleStatus,
    ExecutionArtifacts,
    MutationType,
    PayloadMutationPlan,
    PayloadVariant,
    ProviderProfile,
)
from redforge.domain.payloads.repository import PayloadTemplateRepository
from redforge.domain.payloads.value_objects import (
    RenderContext,
    RenderedPayload,
    TemplateStatus,
    TemplateType,
    TemplateVariable,
    TemplateVersion,
    VariableType,
)

__all__ = [
    "MUTATION_REGISTRY",
    "BundleStatus",
    "ExecutionArtifacts",
    "MutationType",
    "PayloadBundle",
    "PayloadBundleRepository",
    "PayloadIntelligenceEngine",
    "PayloadMutationPlan",
    "PayloadTemplate",
    "PayloadTemplateRepository",
    "PayloadVariant",
    "ProviderProfile",
    "RenderContext",
    "RenderedPayload",
    "TemplateStatus",
    "TemplateType",
    "TemplateVariable",
    "TemplateVersion",
    "VariableType",
]
