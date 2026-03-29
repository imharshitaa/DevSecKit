from __future__ import annotations

from hashlib import sha1

from devsec_platform.schemas import Finding, UnifiedRisk


SEVERITY_WEIGHT = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 1,
}


def _normalize_severity(sev: str) -> str:
    return sev.upper() if sev else "MEDIUM"


def correlate_findings(findings: list[Finding], context: dict | None = None) -> list[UnifiedRisk]:
    context = context or {}
    business_service = str(context.get("business_service", "unknown"))
    internet_exposed = bool(context.get("internet_exposed", False))
    critical_data = str(context.get("data_classification", "internal")).lower() in {"restricted", "confidential"}
    known_exploits = bool(context.get("known_exploits", False))

    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        key = f.rule_id or f.title
        grouped.setdefault(key, []).append(f)

    risks: list[UnifiedRisk] = []
    for key, bucket in grouped.items():
        max_weight = max(SEVERITY_WEIGHT.get(_normalize_severity(f.severity), 5) for f in bucket)
        exploitability = min(10.0, (max_weight * 0.9) + (1.2 if known_exploits else 0))
        exposure_base = 4.0 + len({f.plugin_type for f in bucket}) * 2.0
        exposure = min(10.0, exposure_base + (1.2 if internet_exposed else 0))
        business_impact = min(10.0, (max_weight * 0.7) + (1.2 * len(bucket)) + (1.0 if critical_data else 0))
        composite = round((exploitability * 0.4) + (exposure * 0.25) + (business_impact * 0.35), 2)

        severity = "LOW"
        if composite >= 8.5:
            severity = "CRITICAL"
        elif composite >= 7.0:
            severity = "HIGH"
        elif composite >= 4.5:
            severity = "MEDIUM"

        title = bucket[0].title
        risk_id = "RISK-" + sha1((key + title).encode("utf-8")).hexdigest()[:10].upper()

        risks.append(
            UnifiedRisk(
                risk_id=risk_id,
                title=title,
                severity=severity,
                exploitability_score=round(exploitability, 2),
                exposure_score=round(exposure, 2),
                business_impact_score=round(business_impact, 2),
                composite_score=composite,
                business_service=business_service,
                internet_exposed=internet_exposed,
                correlated_findings=[
                    {
                        "plugin_type": f.plugin_type,
                        "tool": f.tool,
                        "file_path": f.file_path,
                        "line": f.line,
                        "severity": f.severity,
                    }
                    for f in bucket
                ],
                recommendation="Prioritize remediation in CI and enforce blocking policy for critical/high risks.",
            )
        )

    return sorted(risks, key=lambda r: r.composite_score, reverse=True)
