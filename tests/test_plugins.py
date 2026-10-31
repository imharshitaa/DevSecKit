from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from devsec_platform.plugins.base import SecurityPlugin
from devsec_platform.plugins.builtin import SASTPlugin
from devsec_platform.plugins.registry import PluginRegistry
from devsec_platform.schemas import ScanRequest, ScanTarget


class PluginRegistryTests(unittest.TestCase):
    def test_registry_registers_all_eight_builtin_plugin_types(self) -> None:
        registry = PluginRegistry()
        self.assertEqual(
            registry.list_plugins(),
            sorted(["sast", "sca", "secrets", "iac", "cspm", "easm", "dast", "iast"]),
        )

    def test_register_overrides_existing_plugin_for_its_type(self) -> None:
        registry = PluginRegistry()

        class _CustomSast(SecurityPlugin):
            plugin_type = "sast"
            tool_name = "custom-sast"

            def run(self, request: ScanRequest) -> list:
                return []

        registry.register(_CustomSast())
        self.assertEqual(registry.get("sast").tool_name, "custom-sast")

    def test_get_unknown_plugin_type_returns_none(self) -> None:
        registry = PluginRegistry()
        self.assertIsNone(registry.get("not-a-real-plugin"))


class ScriptBackedPluginTests(unittest.TestCase):
    def _request(self) -> ScanRequest:
        return ScanRequest(
            event_type="pr",
            target=ScanTarget(repo_url="."),
            actor="tester",
            roles=["developer"],
            context={"_resolved_target_path": "."},
        )

    @patch("devsec_platform.plugins.builtin.subprocess.run")
    def test_run_parses_successful_scan_report(self, mock_run) -> None:
        plugin = SASTPlugin()

        def fake_run(cmd, text=None, capture_output=None, timeout=None):
            Path(cmd[-1]).write_text('{"results": []}', encoding="utf-8")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run
        findings = plugin.run(self._request())
        self.assertEqual(findings, [])

    @patch("devsec_platform.plugins.builtin.subprocess.run")
    def test_run_raises_when_tool_fails_without_producing_report(self, mock_run) -> None:
        plugin = SASTPlugin()
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="semgrep crashed")
        with self.assertRaises(RuntimeError):
            plugin.run(self._request())

    @patch("devsec_platform.plugins.builtin.subprocess.run")
    def test_run_raises_runtime_error_on_timeout(self, mock_run) -> None:
        plugin = SASTPlugin()
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep.sh", timeout=1)
        with self.assertRaises(RuntimeError):
            plugin.run(self._request())

    def test_run_raises_when_scanner_script_is_missing(self) -> None:
        plugin = SASTPlugin()
        original_script = plugin.script
        plugin.script = Path("/nonexistent/scanner/script.sh")
        try:
            with self.assertRaises(RuntimeError):
                plugin.run(self._request())
        finally:
            plugin.script = original_script


if __name__ == "__main__":
    unittest.main()
