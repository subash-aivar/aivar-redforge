"""NIST CSF 2.0 framework adapter."""

from redforge.domain.compliance.value_objects import FrameworkKey
from redforge.infrastructure.compliance.adapters.base import JsonFrameworkAdapter


class NistCsfFrameworkAdapter(JsonFrameworkAdapter):
    _FRAMEWORK_KEY = FrameworkKey.NIST_CSF
    _FIXTURE_NAME = "nist_csf_2_0.json"
