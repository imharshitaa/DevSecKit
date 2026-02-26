#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse
import shutil

ROOT = Path(__file__).resolve().parent
REPORTS_DIR = ROOT / "reports"
TARGETS_DIR = ROOT / "targets"


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"


def c(text: str, color: str) -> str:
    return f"{color}{text}{Color.RESET}"


@dataclass
class Finding:
    scan_type: str
    rule_id: str
    rule_name: str
    message: str
    severity: str
    confidence: str
    target: str
    file_path: str
    line_number: str
    code_snippet: str
    why_risky: str
    remediation_guidance: str
    references: list[str]


@dataclass
class ScanDef:
    key: str
    name: str
    script: Path
    needs_url: bool
    report_hint: str
    parser: Callable[[Path], list[Finding]]
    required_cmds: list[str]
    install_hint: str


def print_banner() -> None:
    print(c("\nDevSecKit - Terminal DevSecOps Scanner", Color.BOLD + Color.CYAN))
    print(c("SAST | SCA | Secrets | IaC | DAST | IAST-lite\n", Color.DIM))


def run_command(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, text=True, capture_output=True, cwd=ROOT)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def severity_rank(level: str) -> int:
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return order.get(level.upper(), 0)


def normalize_severity(level: str) -> str:
    lvl = (level or "UNKNOWN").upper()
    alias = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "INFORMATIONAL": "INFO",
    }
    return alias.get(lvl, lvl)


def severity_color(level: str) -> str:
    lvl = normalize_severity(level)
    if lvl in {"CRITICAL", "HIGH"}:
        return Color.RED
    if lvl == "MEDIUM":
        return Color.YELLOW
    if lvl in {"LOW", "INFO"}:
        return Color.GREEN
    return Color.BLUE


def build_finding(
    scan_type: str,
    rule_id: str,
    rule_name: str,
    message: str,
    severity: str,
    confidence: str,
    target: str,
    file_path: str,
    line_number: str,
    code_snippet: str,
    why_risky: str,
    remediation_guidance: str,
    references: list[str] | None = None,
) -> Finding:
    return Finding(
        scan_type=scan_type,
        rule_id=rule_id.strip() or f"{scan_type.lower()}.generic",
        rule_name=rule_name.strip() or "Security issue",
        message=message.strip() or "A potential security issue was detected.",
        severity=normalize_severity(severity),
        confidence=confidence.strip().upper() or "MEDIUM",
        target=target,
        file_path=file_path.strip() or "N/A",
        line_number=line_number.strip() or "N/A",
        code_snippet=(code_snippet or "").strip(),
        why_risky=why_risky.strip() or "Potential security impact detected.",
        remediation_guidance=remediation_guidance.strip() or "Review and remediate based on secure coding standards.",
        references=references or [],
    )


def parse_semgrep(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        sev = normalize_severity(extra.get("severity", "MEDIUM"))
        metadata = extra.get("metadata", {})
        file_path = item.get("path", "")
        line_number = str(item.get("start", {}).get("line", "?"))
        refs: list[str] = []
        cwe = metadata.get("cwe")
        if isinstance(cwe, list):
            refs.extend([str(x) for x in cwe[:3]])
        owasp = metadata.get("owasp")
        if isinstance(owasp, list):
            refs.extend([str(x) for x in owasp[:2]])
        confidence = str(metadata.get("confidence", "MEDIUM")).upper()
        check_id = item.get("check_id", "semgrep.generic")
        rule_name = str(metadata.get("shortlink", "") or metadata.get("category", "") or check_id)
        snippet = (extra.get("lines") or "")[:500]
        findings.append(
            build_finding(
                scan_type="SAST",
                rule_id=check_id,
                rule_name=rule_name,
                message=extra.get("message", "Potentially insecure code pattern matched a Semgrep rule."),
                severity=sev,
                confidence=confidence,
                target=file_path,
                file_path=file_path,
                line_number=line_number,
                code_snippet=snippet,
                why_risky=extra.get("message", "Code pattern is known to introduce security weaknesses."),
                remediation_guidance=str(
                    extra.get("fix")
                    or metadata.get("remediation")
                    or "1) Replace unsafe API usage with secure alternatives. 2) Validate/sanitize untrusted input. 3) Add tests for the vulnerable path."
                ),
                references=refs,
            )
        )
    return findings


def parse_gitleaks(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for item in data if isinstance(data, list) else []:
        title = item.get("Description", "Potential secret exposed")
        file_name = item.get("File", "")
        evidence = item.get("Match", "") or (item.get("Secret", "")[:6] + "..." if item.get("Secret") else "Redacted")
        findings.append(
            build_finding(
                scan_type="SECRETS",
                rule_id=str(item.get("RuleID", "gitleaks.generic")),
                rule_name=title,
                message=title,
                severity="HIGH",
                confidence="HIGH",
                target=file_name,
                file_path=file_name,
                line_number=str(item.get("StartLine", "?")),
                code_snippet=evidence[:500],
                why_risky="Leaked secrets can lead to account takeover, data exposure, or infrastructure compromise.",
                remediation_guidance="1) Revoke/rotate the secret immediately. 2) Remove it from code and git history. 3) Move secrets to a vault/secret manager. 4) Add pre-commit secret scanning.",
                references=[item.get("RuleID", "")] if item.get("RuleID") else [],
            )
        )
    return findings


def parse_trufflehog(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    findings: list[Finding] = []
    with report_path.open(encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except Exception:
                continue

            detector = item.get("DetectorName", "TruffleHog")
            verified = bool(item.get("Verified", False))
            confidence = "HIGH" if verified else "MEDIUM"
            severity = "CRITICAL" if verified else "HIGH"

            file_path = "N/A"
            line_no = "N/A"
            source_meta = item.get("SourceMetadata", {}) or {}
            data = source_meta.get("Data", {}) if isinstance(source_meta, dict) else {}
            fs_meta = data.get("Filesystem", {}) if isinstance(data, dict) else {}
            if isinstance(fs_meta, dict):
                file_path = fs_meta.get("file", "N/A")
                line_no = str(fs_meta.get("line", "N/A"))

            redacted = str(item.get("Redacted", "") or item.get("Raw", ""))[:500]
            refs = [f"verified={str(verified).lower()}"]
            findings.append(
                build_finding(
                    scan_type="SECRETS_TRUFFLEHOG",
                    rule_id=f"trufflehog.{str(detector).lower().replace(' ', '-')}",
                    rule_name=f"{detector} secret detected",
                    message=f"Potential secret detected by TruffleHog detector: {detector}.",
                    severity=severity,
                    confidence=confidence,
                    target=file_path,
                    file_path=file_path,
                    line_number=line_no,
                    code_snippet=redacted,
                    why_risky="Exposed secrets can be used for unauthorized access, data exfiltration, or infrastructure compromise.",
                    remediation_guidance="1) Revoke/rotate exposed credential immediately. 2) Remove secret from source and history. 3) Move credentials to secret manager. 4) Add push/CI secret scanning gates.",
                    references=refs,
                )
            )
    return findings


def parse_dependency_check(_report_path: Path) -> list[Finding]:
    reports = sorted(REPORTS_DIR.glob("dependency-check-report*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        return []
    data = json.loads(reports[0].read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for dep in data.get("dependencies", []):
        file_name = dep.get("fileName", "dependency")
        for vuln in dep.get("vulnerabilities", []):
            sev = normalize_severity(vuln.get("severity", "MEDIUM"))
            title = vuln.get("name", "Dependency vulnerability")
            details = vuln.get("description", "").replace("\n", " ")
            refs = [title]
            refs.extend([str(c) for c in (vuln.get("cwes") or [])[:3]])
            pkg = dep.get("packagePath", file_name)
            findings.append(
                build_finding(
                    scan_type="SCA",
                    rule_id=title,
                    rule_name=title,
                    message=details[:300] or "Known vulnerable dependency detected.",
                    severity=sev,
                    confidence="HIGH",
                    target=file_name,
                    file_path=file_name,
                    line_number="N/A",
                    code_snippet=f"Dependency: {pkg}",
                    why_risky=details[:300] or "Vulnerable dependency increases exploitability in the software supply chain.",
                    remediation_guidance="1) Upgrade to a patched version. 2) Pin dependency versions. 3) Review transitive dependencies. 4) Enforce CVE policy gates in CI/CD.",
                    references=refs,
                )
            )
    return findings


def parse_trivy(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []

    def resolve_target_path(raw_target: str) -> Path | None:
        candidate = Path(raw_target)
        lookup = [candidate, ROOT / raw_target, ROOT / "targets" / raw_target]
        for path in lookup:
            if path.exists() and path.is_file():
                return path
        if "/" in raw_target:
            parts = raw_target.split("/", 1)
            if len(parts) == 2:
                alt = ROOT / "targets" / parts[0] / parts[1]
                if alt.exists() and alt.is_file():
                    return alt
        return None

    def locate_dependency_line(file_path: Path, pkg: str, version: str) -> tuple[str, str]:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return "N/A", ""

        pkg_l = pkg.lower().strip()
        ver_l = version.lower().strip()
        if not pkg_l:
            return "N/A", ""

        def snippet_at(idx: int) -> str:
            start = max(0, idx - 2)
            end = min(len(lines), idx + 3)
            out = []
            for i in range(start, end):
                out.append(f"{i+1}: {lines[i]}")
            return "\n".join(out)

        # 1) same-line match (common in lock files)
        for i, raw in enumerate(lines):
            line = raw.lower()
            if pkg_l in line and (not ver_l or ver_l in line):
                return str(i + 1), snippet_at(i)

        # 2) nearby-line match where package/version appear in a block
        pkg_indices = [i for i, raw in enumerate(lines) if pkg_l in raw.lower()]
        for i in pkg_indices:
            window = "\n".join(lines[i : min(len(lines), i + 8)]).lower()
            if ver_l and ver_l in window:
                return str(i + 1), snippet_at(i)

        # 3) lockfile key style, e.g. /axios@1.13.2:
        if ver_l:
            pat = re.compile(rf"{re.escape(pkg_l)}[@\\s:/=]+{re.escape(ver_l)}")
            for i, raw in enumerate(lines):
                if pat.search(raw.lower()):
                    return str(i + 1), snippet_at(i)

        return "N/A", ""

    for result in data.get("Results", []) or []:
        target = result.get("Target", "dependency-scan")
        resolved_target = resolve_target_path(target)
        vuln_list = result.get("Vulnerabilities", []) or []
        for vuln in vuln_list:
            vuln_id = vuln.get("VulnerabilityID", "TRIVY-VULN")
            pkg = vuln.get("PkgName", "package")
            installed = vuln.get("InstalledVersion", "unknown")
            fixed = vuln.get("FixedVersion", "N/A")
            detected_line = "N/A"
            detected_snippet = ""
            if resolved_target is not None:
                detected_line, detected_snippet = locate_dependency_line(resolved_target, pkg, installed)
            title = vuln.get("Title", vuln.get("Description", "Dependency vulnerability"))
            refs = []
            primary_url = vuln.get("PrimaryURL")
            if primary_url:
                refs.append(str(primary_url))
            refs.extend([str(r) for r in (vuln.get("References") or [])[:4]])
            findings.append(
                build_finding(
                    scan_type="SCA_TRIVY",
                    rule_id=vuln_id,
                    rule_name=title[:120],
                    message=(vuln.get("Description") or title or "Known vulnerable component detected.")[:300],
                    severity=normalize_severity(vuln.get("Severity", "MEDIUM")),
                    confidence="HIGH",
                    target=target,
                    file_path=target,
                    line_number=detected_line,
                    code_snippet=detected_snippet or f"{pkg} {installed} (fixed: {fixed})",
                    why_risky=f"Dependency {pkg}@{installed} is associated with known vulnerabilities that may be exploitable.",
                    remediation_guidance="1) Upgrade to fixed version. 2) Verify transitive dependency paths. 3) Add SCA policy gate in CI to block vulnerable versions.",
                    references=refs,
                )
            )
    return findings


def parse_zap(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for site in data.get("site", []):
        site_name = site.get("@name", "webapp")
        for alert in site.get("alerts", []):
            risk = str(alert.get("riskdesc", "INFO")).split(" ")[0].upper()
            sev = normalize_severity(risk)
            title = alert.get("name", "ZAP Alert")
            instances = alert.get("instances", [])
            url = ""
            if instances and isinstance(instances, list):
                url = str(instances[0].get("uri", "") or instances[0].get("url", ""))
            refs = []
            if alert.get("cweid"):
                refs.append(f"CWE-{alert.get('cweid')}")
            if alert.get("wascid"):
                refs.append(f"WASC-{alert.get('wascid')}")
            findings.append(
                build_finding(
                    scan_type="DAST",
                    rule_id=f"zap.{alert.get('pluginid', 'generic')}",
                    rule_name=title,
                    message=alert.get("desc", "").replace("\n", " ")[:300] or title,
                    severity=sev,
                    confidence="MEDIUM",
                    target=site_name or url or "webapp",
                    file_path=url or site_name or "N/A",
                    line_number="N/A",
                    code_snippet=alert.get("evidence", "")[:500],
                    why_risky=alert.get("desc", "").replace("\n", " ")[:300],
                    remediation_guidance=alert.get(
                        "solution",
                        "1) Apply secure server-side controls. 2) Validate input/output handling. 3) Re-test endpoint after patching.",
                    ),
                    references=refs,
                )
            )
    return findings


def parse_checkov(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    checks: list[dict] = []

    if isinstance(data, dict):
        checks = data.get("results", {}).get("failed_checks", []) or []
    elif isinstance(data, list):
        for section in data:
            if not isinstance(section, dict):
                continue
            section_results = section.get("results", {})
            if isinstance(section_results, dict):
                section_failed = section_results.get("failed_checks", []) or []
                if isinstance(section_failed, list):
                    checks.extend([c for c in section_failed if isinstance(c, dict)])

    remediation_by_rule = {
        "CKV_DOCKER_2": "1) Add a HEALTHCHECK instruction that validates app responsiveness. 2) Ensure it fails fast for unhealthy containers. 3) Validate restart behavior in orchestrator.",
        "CKV_DOCKER_3": "1) Create a non-root user in the image. 2) Switch to it with USER. 3) Verify file permissions required by the app.",
    }

    risk_by_rule = {
        "CKV_DOCKER_2": "Without HEALTHCHECK, orchestrators may keep serving unhealthy containers, increasing outage and security detection blind spots.",
        "CKV_DOCKER_3": "Running containers as root increases blast radius if the application is compromised.",
    }

    def normalize_iac_path(path: str) -> str:
        p = (path or "").strip()
        if p.startswith("/src/"):
            parts = p.split("/", 3)
            if len(parts) >= 4:
                return "/" + parts[3]
        if p.startswith("/rever_"):
            parts = p.split("/", 2)
            if len(parts) >= 3:
                return "/" + parts[2]
        return p or "iac"

    def normalize_iac_severity(raw: str | None, rule_id: str) -> str:
        sev = normalize_severity(raw or "UNKNOWN")
        if sev == "UNKNOWN":
            if rule_id in {"CKV_DOCKER_2", "CKV_DOCKER_3"}:
                return "MEDIUM"
            return "MEDIUM"
        return sev

    for item in checks:
        rule_id = item.get("check_id", "checkov.generic")
        sev = normalize_iac_severity(item.get("severity"), rule_id)
        title = item.get("check_name", item.get("check_id", "IaC issue"))
        file_path = normalize_iac_path(item.get("file_path", "iac"))
        line_range = item.get("file_line_range", ["?"])
        line_number = str(line_range[0]) if line_range else "?"
        guideline = item.get("guideline", "") or ""
        snippet = ""
        code_block = item.get("code_block", [])
        if isinstance(code_block, list):
            snippet_lines: list[str] = []
            for line in code_block[:6]:
                if isinstance(line, list) and len(line) > 1:
                    snippet_lines.append(f"{line[0]}: {str(line[1]).rstrip()}")
                elif isinstance(line, str):
                    snippet_lines.append(line.rstrip())
            snippet = "\n".join(snippet_lines)
        why_risky = risk_by_rule.get(
            rule_id,
            "This infrastructure setting weakens security controls and may increase exposure to unauthorized access or lateral movement.",
        )
        remediation = remediation_by_rule.get(
            rule_id,
            "1) Review this resource against least-privilege and secure-default practices. 2) Apply the required policy setting in IaC. 3) Re-run Checkov before deployment.",
        )
        if guideline:
            remediation = f"{remediation} Reference: {guideline}"
        findings.append(
            build_finding(
                scan_type="IAC",
                rule_id=rule_id,
                rule_name=title,
                message=title,
                severity=sev,
                confidence="HIGH",
                target=file_path,
                file_path=file_path,
                line_number=line_number,
                code_snippet=snippet,
                why_risky=why_risky,
                remediation_guidance=remediation,
                references=[rule_id] if rule_id else [],
            )
        )
    return findings


def parse_iast(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    if data.get("error"):
        findings.append(
            build_finding(
                scan_type="IAST",
                rule_id="iast.runtime.connectivity",
                rule_name="IAST-lite runtime probe failed",
                message="Runtime checks could not execute against the provided URL.",
                severity="INFO",
                confidence="LOW",
                target=data.get("url", ""),
                file_path=data.get("url", ""),
                line_number="N/A",
                code_snippet=str(data.get("error", "")),
                why_risky="Runtime checks could not be completed; security posture is unknown.",
                remediation_guidance="1) Verify URL is reachable from scanner host. 2) Start target application. 3) Re-run IAST scan.",
            )
        )
    for item in data.get("findings", []):
        findings.append(
            build_finding(
                scan_type="IAST",
                rule_id=f"iast.{item.get('title', 'runtime').lower().replace(' ', '-')}",
                rule_name=item.get("title", "IAST finding"),
                message=item.get("title", "IAST finding"),
                severity=normalize_severity(item.get("severity", "MEDIUM")),
                confidence="MEDIUM",
                target=data.get("url", ""),
                file_path=data.get("url", ""),
                line_number="N/A",
                code_snippet=item.get("evidence", "")[:500],
                why_risky=item.get("evidence", "Runtime behavior indicates missing security hardening."),
                remediation_guidance=item.get(
                    "recommendation",
                    "1) Apply missing security headers/cookie protections. 2) Harden web server config. 3) Re-test endpoint.",
                ),
            )
        )
    return findings


def ask_target() -> tuple[Path, str | None]:
    print(c("1) Scan local source directory", Color.BLUE))
    print(c("2) Scan remote repository (clone first)", Color.BLUE))
    choice = input("Select target mode [1/2]: ").strip()

    if choice == "2":
        repo_url = input("Enter git repository URL: ").strip()
        if not repo_url:
            raise ValueError("Repository URL is required.")
        parsed = urlparse(repo_url)
        repo_name = Path(parsed.path).stem or "target"
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_path = TARGETS_DIR / f"{repo_name}_{stamp}"
        TARGETS_DIR.mkdir(parents=True, exist_ok=True)
        code, out, err = run_command(["git", "clone", repo_url, str(target_path)])
        if code != 0:
            raise RuntimeError(err or out or "git clone failed")
        print(c(f"Cloned repository to {target_path}", Color.GREEN))
        return target_path, None

    path_str = input("Enter local source path: ").strip()
    target = Path(path_str).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        raise ValueError("Source path must be an existing directory.")
    return target, None


def ask_scans() -> list[str]:
    menu = ["sast", "sca", "secrets", "iac", "dast", "iast"]
    print(c("\nAvailable scan types:", Color.BLUE))
    for i, item in enumerate(menu, start=1):
        print(f"{i}) {item}")
    raw = input("Select scans (comma list like 1,2,5 or 'all'): ").strip().lower()
    if raw == "all":
        return menu
    selected: list[str] = []
    idx_to_key = {str(i): key for i, key in enumerate(menu, start=1)}
    for token in [t.strip() for t in raw.split(",") if t.strip()]:
        if token in idx_to_key:
            selected.append(idx_to_key[token])
        elif token in menu:
            selected.append(token)
    return list(dict.fromkeys(selected))


def preflight(selected: list[str], scan_defs: dict[str, ScanDef]) -> tuple[list[str], list[str]]:
    ready: list[str] = []
    skipped: list[str] = []
    print(c("\n=== Preflight Check ===", Color.BOLD))

    for key in selected:
        scan = scan_defs[key]
        missing: list[str] = []
        for req in scan.required_cmds:
            choices = [c.strip() for c in req.split("|") if c.strip()]
            if not any(shutil.which(choice) is not None for choice in choices):
                missing.append(req)
        if missing:
            skipped.append(key)
            print(c(f"[SKIP] {scan.name}", Color.YELLOW))
            print(c(f"       Missing: {', '.join(missing)}", Color.DIM))
            print(c(f"       Install: {scan.install_hint}", Color.DIM))
            continue
        ready.append(key)
        print(c(f"[OK]   {scan.name}", Color.GREEN))

    return ready, skipped


def print_summary(findings: list[Finding]) -> None:
    if not findings:
        print(c("\nNo findings detected by selected scanners.", Color.GREEN))
        return

    counts: dict[str, int] = {}
    for f in findings:
        sev = normalize_severity(f.severity)
        counts[sev] = counts.get(sev, 0) + 1

    print(c("\n=== Findings Summary ===", Color.BOLD))
    ordered = sorted(counts.items(), key=lambda x: severity_rank(x[0]), reverse=True)
    print(" | ".join([c(f"{k}: {v}", severity_color(k)) for k, v in ordered]))

    sorted_findings = sorted(findings, key=lambda f: severity_rank(f.severity), reverse=True)
    print(c("\n=== Security Issues Report ===", Color.BOLD))
    for i, f in enumerate(sorted_findings[:25], start=1):
        sev = normalize_severity(f.severity)
        print(c(f"\n[{i:02d}] [{sev}] {f.scan_type}", severity_color(sev)))
        print(f"Rule ID and Name      : {f.rule_id} | {f.rule_name}")
        print(f"Message/Description   : {f.message[:300]}")
        print(f"Severity/Confidence   : {sev} / {f.confidence}")
        print(f"Target                : {f.target}")
        print(f"File Path/Line Number : {f.file_path}:{f.line_number}")
        if f.code_snippet:
            print(c("Code Snippet:", Color.DIM))
            print(c(f.code_snippet[:500], Color.DIM))
        print(f"Why Risky             : {f.why_risky[:350]}")
        print(f"Remediation Guidance  : {f.remediation_guidance[:350]}")
        if f.references:
            print(c(f"Refs       : {', '.join(f.references[:5])}", Color.DIM))


def write_combined_report(target: Path, selected: list[str], findings: list[Finding], executions: list[dict[str, str]]) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_DIR / "combined_report.json"
    severity_summary: dict[str, int] = {}
    scan_summary: dict[str, int] = {}
    for f in findings:
        sev = normalize_severity(f.severity)
        severity_summary[sev] = severity_summary.get(sev, 0) + 1
        scan_summary[f.scan_type] = scan_summary.get(f.scan_type, 0) + 1
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": str(target),
        "selected_scans": selected,
        "summary": {
            "total_findings": len(findings),
            "severity": severity_summary,
            "scan_type": scan_summary,
        },
        "execution": executions,
        "findings": [f.__dict__ for f in findings],
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


def main() -> int:
    print_banner()

    scan_defs = {
        "sast": ScanDef(
            "sast",
            "SAST (Semgrep)",
            ROOT / "scanners/sast/semgrep.sh",
            False,
            "reports/semgrep.json",
            parse_semgrep,
            ["semgrep|docker"],
            "Install Semgrep (`pipx install semgrep`) or run with Docker available.",
        ),
        "sca": ScanDef(
            "sca",
            "SCA (Dependency-Check)",
            ROOT / "scanners/sca/dependencycheck.sh",
            False,
            "reports/dependency-check-report.json",
            parse_dependency_check,
            ["dependency-check|docker"],
            "Install OWASP Dependency-Check or use Docker (`owasp/dependency-check` image).",
        ),
        "sca_trivy": ScanDef(
            "sca_trivy",
            "SCA (Trivy)",
            ROOT / "scanners/sca/trivy.sh",
            False,
            "reports/trivy-sca.json",
            parse_trivy,
            ["trivy|docker"],
            "Install Trivy (`brew install trivy`) or use Docker (`aquasec/trivy`).",
        ),
        "secrets": ScanDef(
            "secrets",
            "Secrets (Gitleaks)",
            ROOT / "scanners/secrets/gitleaks.sh",
            False,
            "reports/gitleaks.json",
            parse_gitleaks,
            ["gitleaks|docker"],
            "Install Gitleaks or use Docker (`ghcr.io/gitleaks/gitleaks`).",
        ),
        "secrets_trufflehog": ScanDef(
            "secrets_trufflehog",
            "Secrets (TruffleHog)",
            ROOT / "scanners/secrets/trufflehog.sh",
            False,
            "reports/trufflehog.json",
            parse_trufflehog,
            ["trufflehog|docker"],
            "Install TruffleHog (`brew install trufflehog`) or use Docker (`trufflesecurity/trufflehog`).",
        ),
        "iac": ScanDef(
            "iac",
            "IaC (Checkov)",
            ROOT / "scanners/iac/checkov.sh",
            False,
            "reports/checkov.json",
            parse_checkov,
            ["checkov|docker"],
            "Install Checkov (`pipx install checkov`) or use Docker (`bridgecrew/checkov`).",
        ),
        "dast": ScanDef(
            "dast",
            "DAST (ZAP baseline)",
            ROOT / "scanners/dast/zap.sh",
            True,
            "reports/zap.json",
            parse_zap,
            ["docker"],
            "Install Docker Desktop and start it; ensure your user can access the Docker socket.",
        ),
        "iast": ScanDef(
            "iast",
            "IAST-lite (Runtime header checks)",
            ROOT / "scanners/iast/iast.sh",
            True,
            "reports/iast-lite.json",
            parse_iast,
            ["python3"],
            "Install Python 3.",
        ),
    }

    try:
        target, _ = ask_target()
        requested_scans = ask_scans()
        if not requested_scans:
            raise ValueError("No valid scan selected.")

        # Expand grouped scan types so each category runs all relevant tools.
        expanded: list[str] = []
        for key in requested_scans:
            if key == "sca":
                expanded.extend(["sca", "sca_trivy"])
            elif key == "secrets":
                expanded.extend(["secrets", "secrets_trufflehog"])
            else:
                expanded.append(key)
        selected = list(dict.fromkeys(expanded))

        selected, skipped = preflight(selected, scan_defs)
        if skipped:
            print(c(f"Skipped scans: {', '.join(skipped)}", Color.YELLOW))
        if not selected:
            raise ValueError("No runnable scans selected. Install missing tools and retry.")

        url = None
        if any(scan_defs[s].needs_url for s in selected):
            url = input("Enter target URL for DAST/IAST (example: http://localhost:3000): ").strip()
            if not url:
                raise ValueError("A URL is required for DAST/IAST scans.")

        all_findings: list[Finding] = []
        executions: list[dict[str, str]] = []

        for key in selected:
            scan = scan_defs[key]
            print(c(f"\nRunning {scan.name}...", Color.CYAN))
            arg = url if scan.needs_url else str(target)
            cmd = [str(scan.script), arg, scan.report_hint] if key != "sca" else [str(scan.script), arg, str(REPORTS_DIR)]
            code, out, err = run_command(cmd)

            executions.append(
                {
                    "scan": key,
                    "status": "success" if code == 0 else "failed",
                    "command": " ".join([shlex.quote(p) for p in cmd]),
                    "stdout": out[-1000:],
                    "stderr": err[-1000:],
                }
            )

            if code == 0:
                print(c(f"{scan.name} completed", Color.GREEN))
            else:
                print(c(f"{scan.name} failed (continuing).", Color.RED))
                failure_text = err or out
                if failure_text:
                    print(c(failure_text.splitlines()[-1], Color.DIM))
                if "docker.sock" in failure_text and "permission denied" in failure_text.lower():
                    print(c("Docker permission issue detected. Start Docker Desktop and grant socket access.", Color.DIM))

            if code == 0:
                try:
                    report = ROOT / scan.report_hint
                    all_findings.extend(scan.parser(report))
                except Exception as parse_exc:
                    print(c(f"Could not parse {scan.key} results: {parse_exc}", Color.YELLOW))

        print_summary(all_findings)
        combined_report = write_combined_report(target, requested_scans, all_findings, executions)
        print(c(f"\nDetailed JSON report: {combined_report}", Color.BLUE))
        return 0

    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        return 130
    except Exception as exc:
        print(c(f"\nError: {exc}", Color.RED))
        return 1


if __name__ == "__main__":
    sys.exit(main())
