from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from devsec_platform.parsers import (
    parse_checkov_report,
    parse_gitleaks_report,
    parse_iast_report,
    parse_semgrep_report,
    parse_trivy_report,
    parse_trufflehog_report,
    parse_zap_report,
)
from devsec_platform.plugins.base import SecurityPlugin
from devsec_platform.schemas import Finding, ScanRequest, validate_finding

ROOT = Path(__file__).resolve().parents[2]


class ScriptBackedPlugin(SecurityPlugin):
    plugin_type: str
    tool_name: str
    report_name: str
    parser: Callable[[Path], list[Finding]]
    script: Path
    timeout_seconds: int = 300
    requires_runtime_url: bool = False

    def _build_cmd(self, request: ScanRequest, report_path: Path) -> list[str]:
        target_path = str(request.context.get("_resolved_target_path", ""))
        if self.requires_runtime_url:
            runtime = request.target.runtime_url
            if not runtime:
                raise RuntimeError(f"{self.plugin_type} requires target.runtime_url")
            return [str(self.script), runtime, str(report_path)]
        if not target_path:
            raise RuntimeError("resolved target path missing")
        return [str(self.script), target_path, str(report_path)]

    def run(self, request: ScanRequest) -> list[Finding]:
        if not self.script.exists():
            raise RuntimeError(f"scanner script missing: {self.script}")

        tmp_dir = Path(tempfile.mkdtemp(prefix=f"devsec-{self.plugin_type}-"))
        report_path = tmp_dir / self.report_name
        cmd = self._build_cmd(request, report_path)

        try:
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=self.timeout_seconds)
            if proc.returncode != 0 and not report_path.exists():
                stderr = (proc.stderr or "").strip()
                stdout = (proc.stdout or "").strip()
                raise RuntimeError(stderr or stdout or f"{self.tool_name} failed with exit {proc.returncode}")

            findings = self.parser(report_path)
            for f in findings:
                validate_finding(f)
            return findings
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{self.tool_name} timed out after {self.timeout_seconds}s") from exc
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


class SASTPlugin(ScriptBackedPlugin):
    plugin_type = "sast"
    tool_name = "semgrep"
    script = ROOT / "scanners/sast/semgrep.sh"
    report_name = "semgrep.json"
    parser = staticmethod(parse_semgrep_report)
    timeout_seconds = 420


class SCAPlugin(ScriptBackedPlugin):
    plugin_type = "sca"
    tool_name = "trivy"
    script = ROOT / "scanners/sca/trivy.sh"
    report_name = "trivy-sca.json"
    parser = staticmethod(parse_trivy_report)
    timeout_seconds = 420


class SecretsPlugin(SecurityPlugin):
    plugin_type = "secrets"
    tool_name = "gitleaks+trufflehog"

    def run(self, request: ScanRequest) -> list[Finding]:
        plugins: list[ScriptBackedPlugin] = [
            _GitleaksPlugin(),
            _TrufflehogPlugin(),
        ]
        findings: list[Finding] = []
        for plugin in plugins:
            findings.extend(plugin.run(request))
        return findings


class _GitleaksPlugin(ScriptBackedPlugin):
    plugin_type = "secrets"
    tool_name = "gitleaks"
    script = ROOT / "scanners/secrets/gitleaks.sh"
    report_name = "gitleaks.json"
    parser = staticmethod(parse_gitleaks_report)
    timeout_seconds = 180


class _TrufflehogPlugin(ScriptBackedPlugin):
    plugin_type = "secrets"
    tool_name = "trufflehog"
    script = ROOT / "scanners/secrets/trufflehog.sh"
    report_name = "trufflehog.json"
    parser = staticmethod(parse_trufflehog_report)
    timeout_seconds = 240


class IaCPlugin(ScriptBackedPlugin):
    plugin_type = "iac"
    tool_name = "checkov"
    script = ROOT / "scanners/iac/checkov.sh"
    report_name = "checkov.json"
    parser = staticmethod(parse_checkov_report)
    timeout_seconds = 300


class CSPMPlugin(SecurityPlugin):
    plugin_type = "cspm"
    tool_name = "cloud-cspm"

    def run(self, request: ScanRequest) -> list[Finding]:
        # Placeholder for cloud account API integration.
        return []


class EASMPlugin(SecurityPlugin):
    plugin_type = "easm"
    tool_name = "attack-surface-monitor"

    def run(self, request: ScanRequest) -> list[Finding]:
        # Placeholder for external attack surface integration.
        return []


class DASTPlugin(ScriptBackedPlugin):
    plugin_type = "dast"
    tool_name = "owasp-zap"
    script = ROOT / "scanners/dast/zap.sh"
    report_name = "zap.json"
    parser = staticmethod(parse_zap_report)
    timeout_seconds = 480
    requires_runtime_url = True


class IASTPlugin(ScriptBackedPlugin):
    plugin_type = "iast"
    tool_name = "iast-lite"
    script = ROOT / "scanners/iast/iast.sh"
    report_name = "iast-lite.json"
    parser = staticmethod(parse_iast_report)
    timeout_seconds = 120
    requires_runtime_url = True


def builtin_plugins() -> dict[str, SecurityPlugin]:
    plugins: list[SecurityPlugin] = [
        SASTPlugin(),
        SCAPlugin(),  # Dependency-Check intentionally excluded for now.
        SecretsPlugin(),
        IaCPlugin(),
        CSPMPlugin(),
        EASMPlugin(),
        DASTPlugin(),
        IASTPlugin(),
    ]
    return {p.plugin_type: p for p in plugins}
