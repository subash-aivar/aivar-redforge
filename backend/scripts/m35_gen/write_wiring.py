"""Wire M35 packages into API + pyproject."""

from __future__ import annotations

from pathlib import Path

from .common import ROOT


def write() -> None:
    api_init = ROOT / "src" / "redforge" / "api" / "v1" / "__init__.py"
    text = api_init.read_text()
    if "playbook.api.v1" not in text:
        text = text.replace(
            "from incident.api.v1 import router as incident_router\n",
            "from automated_action.api.v1 import router as automated_action_router\n"
            "from incident.api.v1 import router as incident_router\n"
            "from integration_hub.api.v1 import router as integration_hub_router\n"
            "from playbook.api.v1 import router as playbook_router\n",
        )
        text = text.replace(
            "router.include_router(incident_router, tags=[\"incident\"])\n",
            "router.include_router(incident_router, tags=[\"incident\"])\n"
            "router.include_router(playbook_router, tags=[\"playbook\"])\n"
            "router.include_router(automated_action_router, tags=[\"automated-action\"])\n"
            "router.include_router(integration_hub_router, tags=[\"integration-hub\"])\n",
        )
        api_init.write_text(text)

    pyproject = ROOT / "pyproject.toml"
    pt = pyproject.read_text()
    if '"playbook"' not in pt:
        pt = pt.replace(
            '"incident" = ["py.typed"]\n',
            '"incident" = ["py.typed"]\n'
            '"playbook" = ["py.typed"]\n'
            '"automated_action" = ["py.typed"]\n'
            '"integration_hub" = ["py.typed"]\n',
        )
        pt = pt.replace(
            '"incident", "regulatory_notification", "lessons_learned"]',
            '"incident", "regulatory_notification", "lessons_learned", '
            '"playbook", "automated_action", "integration_hub"]',
        )
        # ruff per-file ignores for M35
        ignore_block = '''
"src/playbook/api/**" = ["B008", "TC001", "TC003"]
"src/playbook/application/**" = ["TC001", "TC003", "TC004"]
"src/playbook/infrastructure/**" = ["TC001", "TC003"]
"src/playbook/domain/exceptions/**" = ["N818"]
"src/playbook/domain/**" = ["TC001", "TC003"]
"src/automated_action/api/**" = ["B008", "TC001", "TC003"]
"src/automated_action/application/**" = ["TC001", "TC003", "TC004"]
"src/automated_action/infrastructure/**" = ["TC001", "TC003"]
"src/automated_action/domain/exceptions/**" = ["N818"]
"src/automated_action/domain/**" = ["TC001", "TC003"]
"src/integration_hub/api/**" = ["B008", "TC001", "TC003"]
"src/integration_hub/application/**" = ["TC001", "TC003", "TC004"]
"src/integration_hub/infrastructure/**" = ["TC001", "TC003"]
"src/integration_hub/domain/exceptions/**" = ["N818"]
"src/integration_hub/domain/**" = ["TC001", "TC003"]
'''
        if "src/playbook/api/**" not in pt:
            # append before end of per-file-ignores section — insert after incident ignores
            marker = '"src/incident/domain/**" = ["TC001", "TC003"]\n'
            if marker in pt:
                pt = pt.replace(marker, marker + ignore_block)
        pyproject.write_text(pt)
