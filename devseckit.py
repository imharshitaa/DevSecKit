#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import tempfile
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
    timeout_seconds: int = 600


def print_banner() -> None:
    print(c("\nDevSecKit - Terminal DevSecOps Scanner", Color.BOLD + Color.CYAN))
    print(c("SAST | SCA | Secrets | IaC | DAST | IAST-lite\n", Color.DIM))


def run_command(cmd: list[str], timeout_seconds: int | None = None) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, cwd=ROOT, timeout=timeout_seconds)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"Timed out after {timeout_seconds}s"


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
    base = _report_path if _report_path.is_dir() else _report_path.parent
    reports = sorted(base.glob("dependency-check-report*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
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


def ask_target() -> tuple[Path, str, bool]:
    print(c("1) Scan local source directory", Color.BLUE))
    print(c("2) Scan remote directory (provide the git URL)", Color.BLUE))
    choice = input("Select target mode [1/2]: ").strip()

    if choice == "2":
        repo_url = input("Enter git repository URL: ").strip()
        if not repo_url:
            raise ValueError("Repository URL is required.")
        commit_sha = input("Optional commit SHA to pin (press Enter to skip): ").strip()
        parsed = urlparse(repo_url)
        repo_name = Path(parsed.path).stem or "target"
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_path = TARGETS_DIR / f"{repo_name}_{stamp}"
        TARGETS_DIR.mkdir(parents=True, exist_ok=True)
        code, out, err = run_command(["git", "clone", "--depth", "1", repo_url, str(target_path)], timeout_seconds=300)
        if code != 0:
            raise RuntimeError(err or out or "git clone failed")
        if commit_sha:
            fetch_cmd = ["git", "-C", str(target_path), "fetch", "--depth", "1", "origin", commit_sha]
            f_code, f_out, f_err = run_command(fetch_cmd, timeout_seconds=180)
            if f_code != 0:
                raise RuntimeError(f_err or f_out or f"failed to fetch commit {commit_sha}")
            c_code, c_out, c_err = run_command(["git", "-C", str(target_path), "checkout", commit_sha], timeout_seconds=120)
            if c_code != 0:
                raise RuntimeError(c_err or c_out or f"failed to checkout commit {commit_sha}")
        print(c(f"Cloned repository to {target_path}", Color.GREEN))
        keep_clone = str(os.environ.get("DEVSECKIT_KEEP_CLONE", "")).lower() in {"1", "true", "yes"}
        cleanup = not keep_clone
        return target_path, repo_url, cleanup

    path_str = input("Enter local source path: ").strip()
    target = Path(path_str).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        raise ValueError("Source path must be an existing directory.")
    return target, "local://source", False


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


def write_combined_report(target_label: str, selected: list[str], findings: list[Finding], executions: list[dict[str, str]]) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_DIR / "scan_report.json"
    severity_summary: dict[str, int] = {}
    scan_summary: dict[str, int] = {}
    for f in findings:
        sev = normalize_severity(f.severity)
        severity_summary[sev] = severity_summary.get(sev, 0) + 1
        scan_summary[f.scan_type] = scan_summary.get(f.scan_type, 0) + 1
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": target_label,
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
    target: Path | None = None
    target_label = "local://source"
    cleanup_target = False
    run_reports_dir: Path | None = None

    try:
        target, target_label, cleanup_target = ask_target()
        requested_scans = ask_scans()
        if not requested_scans:
            raise ValueError("No valid scan selected.")

        run_reports_dir = Path(tempfile.mkdtemp(prefix="devseckit-run-"))

        scan_defs = {
            "sast": ScanDef(
                "sast",
                "SAST (Semgrep)",
                ROOT / "scanners/sast/semgrep.sh",
                False,
                str(run_reports_dir / "semgrep.json"),
                parse_semgrep,
                ["semgrep|docker"],
                "Install Semgrep (`pipx install semgrep`) or run with Docker available.",
                timeout_seconds=600,
            ),
            "sca": ScanDef(
                "sca",
                "SCA (Trivy)",
                ROOT / "scanners/sca/trivy.sh",
                False,
                str(run_reports_dir / "trivy-sca.json"),
                parse_trivy,
                ["trivy|docker"],
                "Install Trivy (`brew install trivy`) or use Docker (`aquasec/trivy`).",
                timeout_seconds=900,
            ),
            "secrets": ScanDef(
                "secrets",
                "Secrets (Gitleaks)",
                ROOT / "scanners/secrets/gitleaks.sh",
                False,
                str(run_reports_dir / "gitleaks.json"),
                parse_gitleaks,
                ["gitleaks|docker"],
                "Install Gitleaks or use Docker (`ghcr.io/gitleaks/gitleaks`).",
                timeout_seconds=300,
            ),
            "secrets_trufflehog": ScanDef(
                "secrets_trufflehog",
                "Secrets (TruffleHog)",
                ROOT / "scanners/secrets/trufflehog.sh",
                False,
                str(run_reports_dir / "trufflehog.json"),
                parse_trufflehog,
                ["trufflehog|docker"],
                "Install TruffleHog (`brew install trufflehog`) or use Docker (`trufflesecurity/trufflehog`).",
                timeout_seconds=360,
            ),
            "iac": ScanDef(
                "iac",
                "IaC (Checkov)",
                ROOT / "scanners/iac/checkov.sh",
                False,
                str(run_reports_dir / "checkov.json"),
                parse_checkov,
                ["checkov|docker"],
                "Install Checkov (`pipx install checkov`) or use Docker (`bridgecrew/checkov`).",
                timeout_seconds=600,
            ),
            "dast": ScanDef(
                "dast",
                "DAST (ZAP baseline)",
                ROOT / "scanners/dast/zap.sh",
                True,
                str(run_reports_dir / "zap.json"),
                parse_zap,
                ["docker"],
                "Install Docker Desktop and start it; ensure your user can access the Docker socket.",
                timeout_seconds=1200,
            ),
            "iast": ScanDef(
                "iast",
                "IAST-lite (Runtime header checks)",
                ROOT / "scanners/iast/iast.sh",
                True,
                str(run_reports_dir / "iast-lite.json"),
                parse_iast,
                ["python3"],
                "Install Python 3.",
                timeout_seconds=180,
            ),
        }

        # Expand grouped scan types so each category runs all relevant tools.
        expanded: list[str] = []
        for key in requested_scans:
            if key == "secrets":
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

        priority = {"secrets": 1, "secrets_trufflehog": 1, "sast": 2, "sca": 2, "iac": 3, "iast": 4, "dast": 5}
        selected = sorted(selected, key=lambda k: priority.get(k, 9))

        for key in selected:
            print(c(f"\nQueued {scan_defs[key].name}...", Color.CYAN))

        def _run_scan(scan_key: str) -> tuple[str, int, str, str, list[Finding]]:
            scan = scan_defs[scan_key]
            arg = url if scan.needs_url else str(target)
            cmd = [str(scan.script), arg, scan.report_hint]
            code, out, err = run_command(cmd, timeout_seconds=scan.timeout_seconds)
            parsed_findings: list[Finding] = []
            if code == 0:
                try:
                    parsed_findings = scan.parser(Path(scan.report_hint))
                except Exception as parse_exc:
                    err = (err + "\n" if err else "") + f"parse error: {parse_exc}"
            return scan_key, code, out, err, parsed_findings

        with ThreadPoolExecutor(max_workers=max(1, min(4, len(selected)))) as pool:
            future_map = {pool.submit(_run_scan, key): key for key in selected}
            for future in as_completed(future_map):
                key, code, out, err, parsed = future.result()
                scan = scan_defs[key]
                executions.append(
                    {
                        "scan": key,
                        "status": "success" if code == 0 else "failed",
                        "command": " ".join([shlex.quote(p) for p in [str(scan.script), (url if scan.needs_url else str(target)), scan.report_hint]]),
                        "stdout": out[-1000:],
                        "stderr": err[-1000:],
                    }
                )
                if code == 0:
                    print(c(f"{scan.name} completed", Color.GREEN))
                    all_findings.extend(parsed)
                else:
                    print(c(f"{scan.name} failed (continuing).", Color.RED))
                    failure_text = err or out
                    if failure_text:
                        print(c(failure_text.splitlines()[-1], Color.DIM))
                    if code == 124:
                        print(c(f"{scan.name} hit timeout ({scan.timeout_seconds}s).", Color.DIM))
                    if "docker.sock" in failure_text and "permission denied" in failure_text.lower():
                        print(c("Docker permission issue detected. Start Docker Desktop and grant socket access.", Color.DIM))

        print_summary(all_findings)
        combined_report = write_combined_report(target_label, requested_scans, all_findings, executions)
        print(c(f"\nFinal scan report: {combined_report}", Color.BLUE))

        return 0

    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        return 130
    except Exception as exc:
        print(c(f"\nError: {exc}", Color.RED))
        return 1
    finally:
        if run_reports_dir and run_reports_dir.exists():
            shutil.rmtree(run_reports_dir, ignore_errors=True)
        if cleanup_target and target and target.exists():
            shutil.rmtree(target, ignore_errors=True)
            print(c(f"Cleaned up cloned target: {target}", Color.DIM))


if __name__ == "__main__":
    sys.exit(main())
