from __future__ import annotations

import json
from pathlib import Path

from devsec_platform.schemas import Finding, normalize_confidence, normalize_severity


def _safe_json(path: Path):
    if not path.exists() or path.stat().st_size == 0:
        return None
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def parse_semgrep_report(path: Path) -> list[Finding]:
    data = _safe_json(path) or {}
    findings: list[Finding] = []
    for item in data.get("results", []) or []:
        extra = item.get("extra", {}) or {}
        msg = str(extra.get("message", "Potential security issue detected by Semgrep."))
        findings.append(
            Finding(
                plugin_type="sast",
                tool="semgrep",
                rule_id=str(item.get("check_id", "semgrep.generic")),
                title=msg,
                severity=normalize_severity(str(extra.get("severity", "MEDIUM"))),
                confidence=normalize_confidence(str((extra.get("metadata", {}) or {}).get("confidence", "MEDIUM"))),
                file_path=str(item.get("path", "N/A")),
                line=(item.get("start", {}) or {}).get("line"),
                evidence=str(extra.get("lines", ""))[:500],
                remediation=str(((extra.get("metadata", {}) or {}).get("remediation") or "Use secure coding patterns and validate untrusted input.")),
                references=[str(x) for x in (((extra.get("metadata", {}) or {}).get("cwe") or [])[:3])],
            )
        )
    return findings


def parse_trivy_report(path: Path) -> list[Finding]:
    data = _safe_json(path) or {}
    findings: list[Finding] = []
    for result in data.get("Results", []) or []:
        target = str(result.get("Target", "N/A"))
        for vuln in result.get("Vulnerabilities", []) or []:
            installed = str(vuln.get("InstalledVersion", "unknown"))
            fixed = str(vuln.get("FixedVersion", "N/A"))
            pkg = str(vuln.get("PkgName", "package"))
            refs = [str(x) for x in (vuln.get("References", []) or [])[:5]]
            findings.append(
                Finding(
                    plugin_type="sca",
                    tool="trivy",
                    rule_id=str(vuln.get("VulnerabilityID", "trivy.vuln")),
                    title=str(vuln.get("Title", f"Vulnerability in {pkg}")),
                    severity=normalize_severity(str(vuln.get("Severity", "MEDIUM"))),
                    confidence="HIGH",
                    file_path=target,
                    line=None,
                    evidence=f"{pkg} {installed} (fixed: {fixed})",
                    remediation="Upgrade to fixed version and verify transitive dependency path.",
                    references=refs,
                )
            )
    return findings


def parse_gitleaks_report(path: Path) -> list[Finding]:
    data = _safe_json(path)
    rows = data if isinstance(data, list) else []
    findings: list[Finding] = []
    for item in rows:
        findings.append(
            Finding(
                plugin_type="secrets",
                tool="gitleaks",
                rule_id=str(item.get("RuleID", "gitleaks.secret")),
                title=str(item.get("Description", "Potential leaked secret")),
                severity="HIGH",
                confidence="HIGH",
                file_path=str(item.get("File", "N/A")),
                line=int(item.get("StartLine")) if str(item.get("StartLine", "")).isdigit() else None,
                evidence=str(item.get("Match", "redacted"))[:500],
                remediation="Rotate/revoke secret immediately and remove from source/history.",
                references=[str(item.get("RuleID", ""))] if item.get("RuleID") else [],
            )
        )
    return findings


def parse_trufflehog_report(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not path.exists():
        return findings

    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            item = json.loads(raw)
        except Exception:
            continue
        fs = ((((item.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}))
        detector = str(item.get("DetectorName", "TruffleHog"))
        findings.append(
            Finding(
                plugin_type="secrets",
                tool="trufflehog",
                rule_id=f"trufflehog.{detector.lower().replace(' ', '-')}",
                title=f"{detector} secret detected",
                severity="CRITICAL" if item.get("Verified") else "HIGH",
                confidence="HIGH" if item.get("Verified") else "MEDIUM",
                file_path=str(fs.get("file", "N/A")),
                line=fs.get("line") if isinstance(fs.get("line"), int) else None,
                evidence=str(item.get("Redacted") or item.get("Raw") or "redacted")[:500],
                remediation="Rotate exposed credential and migrate secret handling to vault/secret manager.",
                references=[f"verified={str(bool(item.get('Verified'))).lower()}"],
            )
        )
    return findings


def parse_checkov_report(path: Path) -> list[Finding]:
    data = _safe_json(path)
    if isinstance(data, list):
        # Some Checkov versions output a list of frameworks.
        checks = []
        for block in data:
            checks.extend((((block or {}).get("results") or {}).get("failed_checks") or []))
    else:
        checks = (((data or {}).get("results") or {}).get("failed_checks") or [])

    findings: list[Finding] = []
    for item in checks:
        guide = str(item.get("guideline", ""))
        references = [guide] if guide else []
        code_lines = item.get("code_block") or []
        snippet = "\n".join(str(x[1]) for x in code_lines[:8]) if code_lines else ""
        findings.append(
            Finding(
                plugin_type="iac",
                tool="checkov",
                rule_id=str(item.get("check_id", "checkov.rule")),
                title=str(item.get("check_name", "IaC policy violation")),
                severity=normalize_severity(str(item.get("severity", "MEDIUM"))),
                confidence="HIGH",
                file_path=str(item.get("file_path", "N/A")),
                line=int(item.get("file_line_range", [None])[0]) if item.get("file_line_range") else None,
                evidence=snippet,
                remediation=guide or "Update infrastructure configuration to satisfy policy requirements.",
                references=references,
            )
        )
    return findings


def parse_zap_report(path: Path) -> list[Finding]:
    data = _safe_json(path) or {}
    findings: list[Finding] = []
    for site in (data.get("site") or []):
        for alert in (site.get("alerts") or []):
            refs = []
            cwe = alert.get("cweid")
            if cwe and str(cwe) != "0":
                refs.append(f"CWE-{cwe}")
            findings.append(
                Finding(
                    plugin_type="dast",
                    tool="zap",
                    rule_id=str(alert.get("pluginid", "zap.alert")),
                    title=str(alert.get("name", "DAST finding")),
                    severity=normalize_severity(str(alert.get("riskdesc", "MEDIUM").split()[0])),
                    confidence=normalize_confidence(str(alert.get("confidence", "MEDIUM"))),
                    file_path=str(site.get("@name", "N/A")),
                    line=None,
                    evidence=str(alert.get("desc", ""))[:500],
                    remediation=str(alert.get("solution", "Patch the endpoint and sanitize inputs.")),
                    references=refs,
                )
            )
    return findings


def parse_iast_report(path: Path) -> list[Finding]:
    data = _safe_json(path) or {}
    findings: list[Finding] = []
    for item in data.get("findings", []) or []:
        findings.append(
            Finding(
                plugin_type="iast",
                tool="iast-lite",
                rule_id="iast-lite.runtime",
                title=str(item.get("title", "Runtime security observation")),
                severity=normalize_severity(str(item.get("severity", "MEDIUM"))),
                confidence="MEDIUM",
                file_path=str(data.get("url", "N/A")),
                line=None,
                evidence=str(item.get("evidence", ""))[:500],
                remediation=str(item.get("recommendation", "Harden runtime controls and headers.")),
                references=[],
            )
        )
    return findings
