from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from devsec_platform.parsers import parse_checkov_report, parse_semgrep_report, parse_trivy_report


class ParserTests(unittest.TestCase):
    def _write(self, content: dict) -> Path:
        fd, name = tempfile.mkstemp(prefix="devsec-parser-", suffix=".json")
        path = Path(name)
        path.write_text(json.dumps(content), encoding="utf-8")
        return path

    def test_parse_semgrep(self) -> None:
        path = self._write(
            {
                "results": [
                    {
                        "check_id": "python.lang.security.audit.subprocess-shell-true",
                        "path": "app.py",
                        "start": {"line": 12},
                        "extra": {"message": "Avoid shell=True", "severity": "HIGH", "metadata": {"confidence": "HIGH"}},
                    }
                ]
            }
        )
        findings = parse_semgrep_report(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].plugin_type, "sast")

    def test_parse_trivy(self) -> None:
        path = self._write(
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-11111",
                                "PkgName": "urllib3",
                                "InstalledVersion": "2.4.0",
                                "FixedVersion": "2.6.3",
                                "Severity": "HIGH",
                                "Title": "Test CVE",
                            }
                        ],
                    }
                ]
            }
        )
        findings = parse_trivy_report(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].plugin_type, "sca")

    def test_parse_checkov_list_output(self) -> None:
        path = self._write(
            [
                {
                    "results": {
                        "failed_checks": [
                            {
                                "check_id": "CKV_AWS_20",
                                "check_name": "S3 public",
                                "file_path": "main.tf",
                                "file_line_range": [10, 15],
                                "guideline": "set private",
                            }
                        ]
                    }
                }
            ]
        )
        findings = parse_checkov_report(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].plugin_type, "iac")


if __name__ == "__main__":
    unittest.main()
