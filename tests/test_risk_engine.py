from __future__ import annotations

import unittest

from devsec_platform.risk_engine import correlate_findings
from devsec_platform.schemas import Finding


class RiskEngineTests(unittest.TestCase):
    def test_risk_scoring_uses_context(self) -> None:
        finding = Finding(
            plugin_type="sast",
            tool="semgrep",
            rule_id="python.sqli",
            title="SQL injection",
            severity="HIGH",
            confidence="HIGH",
            file_path="app.py",
            line=10,
            evidence="query = f\"...\"",
            remediation="Use parameterized queries",
        )
        risks = correlate_findings(
            [finding],
            {
                "internet_exposed": True,
                "known_exploits": True,
                "data_classification": "confidential",
                "business_service": "payments",
            },
        )
        self.assertEqual(len(risks), 1)
        self.assertGreaterEqual(risks[0].composite_score, 7.0)
        self.assertEqual(risks[0].business_service, "payments")

    def test_duplicate_rule_id_findings_correlate_into_one_risk(self) -> None:
        shared_rule = Finding(
            plugin_type="sast",
            tool="semgrep",
            rule_id="python.sqli",
            title="SQL injection",
            severity="HIGH",
            confidence="HIGH",
            file_path="app.py",
            line=10,
            evidence="query = f\"...\"",
            remediation="Use parameterized queries",
        )
        same_rule_other_file = Finding(
            plugin_type="sast",
            tool="semgrep",
            rule_id="python.sqli",
            title="SQL injection",
            severity="MEDIUM",
            confidence="HIGH",
            file_path="other.py",
            line=22,
            evidence="query = f\"...\"",
            remediation="Use parameterized queries",
        )
        unrelated = Finding(
            plugin_type="secrets",
            tool="gitleaks",
            rule_id="generic-api-key",
            title="Hardcoded API key",
            severity="HIGH",
            confidence="HIGH",
            file_path="config.py",
            line=5,
            evidence="API_KEY = '...'",
            remediation="Rotate and move to a secret manager",
        )
        risks = correlate_findings([shared_rule, same_rule_other_file, unrelated], {})
        self.assertEqual(len(risks), 2)

        sqli_risk = next(r for r in risks if r.title == "SQL injection")
        self.assertEqual(len(sqli_risk.correlated_findings), 2)
        correlated_files = {f["file_path"] for f in sqli_risk.correlated_findings}
        self.assertEqual(correlated_files, {"app.py", "other.py"})


if __name__ == "__main__":
    unittest.main()
