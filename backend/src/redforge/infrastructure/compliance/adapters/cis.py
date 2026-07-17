"""CIS Benchmarks v8 framework adapter."""

from redforge.domain.compliance.value_objects import FrameworkKey
from redforge.infrastructure.compliance.adapters.base import JsonFrameworkAdapter


class CISFrameworkAdapter(JsonFrameworkAdapter):
    _FRAMEWORK_KEY = FrameworkKey.CIS
    _FIXTURE_NAME = "cis_benchmarks_v8.json"
