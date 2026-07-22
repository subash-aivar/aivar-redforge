"""python -m scripts.m35_gen  (run from backend/)"""

from __future__ import annotations

from . import write_automated_action, write_automated_action_app, write_integration_hub
from . import write_migrations, write_playbook, write_playbook_app
from .write_wiring import write as write_wiring


def main() -> None:
    write_playbook.write()
    write_playbook_app.write_app()
    write_playbook_app.write_infra_api_tests()
    write_integration_hub.write()
    write_automated_action.write()
    write_automated_action_app.write()
    write_migrations.write()
    write_wiring()
    print("M35 packages, migrations, wiring, and tests generated.")


if __name__ == "__main__":
    main()
