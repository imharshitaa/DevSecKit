from __future__ import annotations

import unittest
from pathlib import Path

from devsec_platform.orchestrator import Orchestrator
from devsec_platform.plugins.base import SecurityPlugin
from devsec_platform.schemas import Finding, ScanRequest, ScanTarget


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


class TargetResolutionTests(unittest.TestCase):
    def test_rejects_local_path_when_disallowed(self) -> None:
        orchestrator = Orchestrator()
        request = ScanRequest(event_type="pr", target=ScanTarget(repo_url="."), actor="tester", roles=["developer"])
        with self.assertRaises(ValueError):
            orchestrator._resolve_target_path(request, allow_local_path=False)

    def test_allows_local_path_when_permitted(self) -> None:
        orchestrator = Orchestrator()
        request = ScanRequest(event_type="pr", target=ScanTarget(repo_url="."), actor="tester", roles=["developer"])
        resolved_path, cleanup_dir = orchestrator._resolve_target_path(request, allow_local_path=True)
        self.assertTrue(Path(resolved_path).exists())
        self.assertIsNone(cleanup_dir)

    def test_rejects_nonexistent_path_and_non_url(self) -> None:
        orchestrator = Orchestrator()
        request = ScanRequest(event_type="pr", target=ScanTarget(repo_url="not-a-real-path-or-url"), actor="tester", roles=["developer"])
        with self.assertRaises(ValueError):
            orchestrator._resolve_target_path(request, allow_local_path=True)


class _OkPlugin(SecurityPlugin):
    plugin_type = "sast"
    tool_name = "fake-ok"

    def run(self, request: ScanRequest) -> list[Finding]:
        return [
            Finding(
                plugin_type="sast",
                tool="fake-ok",
                rule_id="fake.rule",
                title="Fake finding",
                severity="LOW",
                confidence="LOW",
                file_path="app.py",
                line=1,
                evidence="evidence",
                remediation="remediation",
            )
        ]


class _FailPlugin(SecurityPlugin):
    plugin_type = "sca"
    tool_name = "fake-fail"

    def run(self, request: ScanRequest) -> list[Finding]:
        raise RuntimeError("simulated plugin failure")


class OrchestratorRunIsolationTests(unittest.TestCase):
    def test_parallel_run_isolates_plugin_failures(self) -> None:
        orchestrator = Orchestrator()
        orchestrator.registry.register(_OkPlugin())
        orchestrator.registry.register(_FailPlugin())
        request = ScanRequest(
            event_type="pr",
            target=ScanTarget(repo_url="."),
            requested_plugins=["sast", "sca"],
            actor="tester",
            roles=["developer"],
        )
        response = orchestrator.run(request, allow_local_path=True)
        statuses = {e["plugin"]: e["status"] for e in response.executed_plugins}
        self.assertEqual(statuses["sast"], "success")
        self.assertEqual(statuses["sca"], "failed")
        self.assertEqual(len(response.unified_risks), 1)

    def test_run_denies_actor_without_scan_permission(self) -> None:
        orchestrator = Orchestrator()
        request = ScanRequest(event_type="pr", target=ScanTarget(repo_url="."), actor="tester", roles=["viewer"])
        with self.assertRaises(PermissionError):
            orchestrator.run(request, allow_local_path=True)


if __name__ == "__main__":
    unittest.main()
