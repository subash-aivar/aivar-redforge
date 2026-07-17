"""ISO 27001:2022 framework adapter."""

from redforge.domain.compliance.value_objects import FrameworkKey
from redforge.infrastructure.compliance.adapters.base import JsonFrameworkAdapter


class ISO27001FrameworkAdapter(JsonFrameworkAdapter):
    _FRAMEWORK_KEY = FrameworkKey.ISO27001
    _FIXTURE_NAME = "iso27001_2022.json"
