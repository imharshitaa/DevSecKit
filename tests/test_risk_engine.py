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


if __name__ == "__main__":
    unittest.main()
