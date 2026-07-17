"""HIPAA Security Rule framework adapter."""

from redforge.domain.compliance.value_objects import FrameworkKey
from redforge.infrastructure.compliance.adapters.base import JsonFrameworkAdapter


class HIPAAFrameworkAdapter(JsonFrameworkAdapter):
    _FRAMEWORK_KEY = FrameworkKey.HIPAA
    _FIXTURE_NAME = "hipaa_security_rule.json"
