from __future__ import annotations

import unittest

from devsec_platform.ai_module import analyze_risks, suggest_plugins_for_event
from devsec_platform.schemas import UnifiedRisk


class AIModuleTests(unittest.TestCase):
    def _risk(self, title: str, severity: str) -> UnifiedRisk:
        return UnifiedRisk(
            risk_id="RISK-TEST",
            title=title,
            severity=severity,
            exploitability_score=8.0,
            exposure_score=7.0,
            business_impact_score=7.5,
            composite_score=7.6,
            business_service="payments",
            internet_exposed=True,
            correlated_findings=[],
            recommendation="Prioritize remediation.",
        )

    def test_empty_risk_list_produces_no_insights(self) -> None:
        self.assertEqual(analyze_risks([]), [])

    def test_insight_is_deterministic_and_tied_to_risk_id(self) -> None:
        risk = self._risk("SQL injection in login handler", "HIGH")
        insight_a = analyze_risks([risk])[0]
        insight_b = analyze_risks([risk])[0]
        self.assertEqual(insight_a, insight_b)
        self.assertEqual(insight_a.risk_id, risk.risk_id)
        self.assertIn("untrusted input", insight_a.probable_root_cause.lower())

    def test_critical_or_high_severity_prepends_urgent_fix(self) -> None:
        risk = self._risk("Hardcoded API key", "CRITICAL")
        insight = analyze_risks([risk])[0]
        self.assertIn("next release window", insight.fix_suggestions[0])
        self.assertIn("credential", insight.probable_root_cause.lower())

    def test_low_severity_does_not_prepend_urgent_fix(self) -> None:
        risk = self._risk("Minor misconfiguration", "LOW")
        insight = analyze_risks([risk])[0]
        self.assertNotIn("next release window", insight.fix_suggestions[0])

    def test_suggest_plugins_is_empty_for_minimal_context(self) -> None:
        self.assertEqual(suggest_plugins_for_event("pr", {}), [])

    def test_suggest_plugins_routes_iac_and_sca_from_changed_files(self) -> None:
        suggestions = suggest_plugins_for_event(
            "pr", {"changed_files": ["infra/main.tf", "app/requirements.txt"]}
        )
        self.assertIn("iac", suggestions)
        self.assertIn("sca", suggestions)

    def test_suggest_plugins_dedupes_overlapping_signals(self) -> None:
        suggestions = suggest_plugins_for_event(
            "runtime", {"internet_exposed": True}
        )
        self.assertEqual(len(suggestions), len(set(suggestions)))
        self.assertIn("easm", suggestions)
        self.assertIn("cspm", suggestions)


if __name__ == "__main__":
    unittest.main()
