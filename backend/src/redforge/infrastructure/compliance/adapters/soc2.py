"""SOC 2 Type II framework adapter."""

from redforge.domain.compliance.value_objects import FrameworkKey
from redforge.infrastructure.compliance.adapters.base import JsonFrameworkAdapter


class SOC2FrameworkAdapter(JsonFrameworkAdapter):
    _FRAMEWORK_KEY = FrameworkKey.SOC2
    _FIXTURE_NAME = "soc2_type2.json"
