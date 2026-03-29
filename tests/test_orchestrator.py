from __future__ import annotations

import unittest

from devsec_platform.orchestrator import Orchestrator
from devsec_platform.schemas import ScanRequest, ScanTarget


class OrchestratorSelectionTests(unittest.TestCase):
    def test_plugin_selection_for_pr(self) -> None:
        request = ScanRequest(
            event_type="pr",
            target=ScanTarget(repo_url="/tmp"),
            context={"changed_files": ["infra/main.tf", "pnpm-lock.yaml"]},
        )
        selected = Orchestrator().select_plugins(request)
        self.assertIn("sast", selected)
        self.assertIn("sca", selected)
        self.assertIn("iac", selected)

    def test_plugin_selection_for_runtime(self) -> None:
        request = ScanRequest(
            event_type="runtime",
            target=ScanTarget(repo_url="/tmp", runtime_url="http://localhost:3000"),
            context={"internet_exposed": True},
        )
        selected = Orchestrator().select_plugins(request)
        self.assertIn("dast", selected)
        self.assertIn("iast", selected)
        self.assertIn("easm", selected)


if __name__ == "__main__":
    unittest.main()
