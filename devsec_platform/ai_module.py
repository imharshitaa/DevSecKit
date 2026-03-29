from __future__ import annotations

from devsec_platform.schemas import AIInsight, UnifiedRisk


def analyze_risks(risks: list[UnifiedRisk]) -> list[AIInsight]:
    insights: list[AIInsight] = []
    for risk in risks:
        root = "Insecure configuration"
        if "injection" in risk.title.lower():
            root = "Untrusted input reaches execution/data layer without proper validation"
        elif "secret" in risk.title.lower() or "key" in risk.title.lower():
            root = "Credential handling violation in repository or configuration"

        fixes = [
            "Patch the vulnerable code/config and add regression tests.",
            "Add policy checks in CI to block recurrence.",
        ]
        if risk.severity in {"CRITICAL", "HIGH"}:
            fixes.insert(0, "Apply fix in the next release window and rotate affected credentials/tokens if applicable.")

        insights.append(
            AIInsight(
                risk_id=risk.risk_id,
                summary=f"{risk.title} is prioritized as {risk.severity} (score={risk.composite_score}).",
                probable_root_cause=root,
                fix_suggestions=fixes,
                confidence=0.82,
            )
        )
    return insights


def suggest_plugins_for_event(event_type: str, context: dict) -> list[str]:
    """
    AI-assisted augmentation over base rule routing.
    Deterministic heuristics are used here as a minimal working implementation.
    """
    suggestions: list[str] = []
    diff_files = context.get("changed_files", [])
    if isinstance(diff_files, list):
        lower_files = [str(f).lower() for f in diff_files]
        if any(f.endswith((".tf", ".yaml", ".yml", "dockerfile")) for f in lower_files):
            suggestions.append("iac")
        if any("package-lock" in f or "pnpm-lock" in f or "requirements" in f for f in lower_files):
            suggestions.append("sca")

    if event_type == "runtime":
        suggestions.extend(["dast", "iast", "easm"])
    if context.get("internet_exposed"):
        suggestions.extend(["easm", "cspm"])
    if context.get("contains_secrets"):
        suggestions.append("secrets")

    ordered = []
    for name in suggestions:
        if name not in ordered:
            ordered.append(name)
    return ordered
