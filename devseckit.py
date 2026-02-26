#!/usr/bin/env python3
from __future__ import annotations

import json
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

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
    severity: str
    title: str
    location: str
    details: str


@dataclass
class ScanDef:
    key: str
    name: str
    script: Path
    needs_url: bool
    report_hint: str
    parser: Callable[[Path], list[Finding]]


def print_banner() -> None:
    print(c("\nDevSecKit - Terminal DevSecOps Scanner", Color.BOLD + Color.CYAN))
    print(c("SAST | SCA | Secrets | IaC | DAST | IAST-lite\n", Color.DIM))


def run_command(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, text=True, capture_output=True)
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


def parse_semgrep(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for item in data.get("results", []):
        sev = normalize_severity(item.get("extra", {}).get("severity", "MEDIUM"))
        location = f"{item.get('path', '')}:{item.get('start', {}).get('line', '?')}"
        findings.append(
            Finding("SAST", sev, item.get("check_id", "Semgrep Finding"), location, item.get("extra", {}).get("message", ""))
        )
    return findings


def parse_gitleaks(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for item in data if isinstance(data, list) else []:
        title = item.get("Description", "Potential secret exposed")
        location = f"{item.get('File', '')}:{item.get('StartLine', '?')}"
        details = item.get("Secret", "")[:6] + "..." if item.get("Secret") else "Redacted"
        findings.append(Finding("SECRETS", "HIGH", title, location, details))
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
            details = vuln.get("description", "")[:180].replace("\n", " ")
            findings.append(Finding("SCA", sev, title, file_name, details))
    return findings


def parse_zap(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = str(alert.get("riskdesc", "INFO")).split(" ")[0].upper()
            sev = normalize_severity(risk)
            title = alert.get("name", "ZAP Alert")
            details = alert.get("desc", "")[:180].replace("\n", " ")
            findings.append(Finding("DAST", sev, title, site.get("@name", "webapp"), details))
    return findings


def parse_checkov(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    checks = data.get("results", {}).get("failed_checks", [])
    for item in checks:
        sev = normalize_severity(item.get("severity", "MEDIUM"))
        title = item.get("check_name", item.get("check_id", "IaC issue"))
        location = item.get("file_path", "iac")
        details = item.get("guideline", item.get("check_id", ""))
        findings.append(Finding("IAC", sev, title, location, details))
    return findings


def parse_iast(report_path: Path) -> list[Finding]:
    if not report_path.exists():
        return []
    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    if data.get("error"):
        findings.append(Finding("IAST", "HIGH", "IAST-lite request failed", data.get("url", ""), data["error"]))
    for item in data.get("findings", []):
        findings.append(
            Finding(
                "IAST",
                normalize_severity(item.get("severity", "MEDIUM")),
                item.get("title", "IAST finding"),
                data.get("url", ""),
                item.get("evidence", ""),
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
    print(c("\nTop findings:", Color.BOLD))
    for i, f in enumerate(sorted_findings[:20], start=1):
        sev = normalize_severity(f.severity)
        line = f"{i:02d}. [{sev}] {f.scan_type} | {f.title} | {f.location}"
        print(c(line, severity_color(sev)))
        if f.details:
            print(c(f"    {f.details[:200]}", Color.DIM))


def write_combined_report(target: Path, selected: list[str], findings: list[Finding], executions: list[dict[str, str]]) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_DIR / "combined_report.json"
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": str(target),
        "selected_scans": selected,
        "execution": executions,
        "findings": [f.__dict__ for f in findings],
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


def main() -> int:
    print_banner()

    scan_defs = {
        "sast": ScanDef("sast", "SAST (Semgrep)", ROOT / "scanners/sast/semgrep.sh", False, "reports/semgrep.json", parse_semgrep),
        "sca": ScanDef("sca", "SCA (Dependency-Check)", ROOT / "scanners/sca/dependencycheck.sh", False, "reports/dependency-check-report.json", parse_dependency_check),
        "secrets": ScanDef("secrets", "Secrets (Gitleaks)", ROOT / "scanners/secrets/gitleaks.sh", False, "reports/gitleaks.json", parse_gitleaks),
        "iac": ScanDef("iac", "IaC (Checkov)", ROOT / "scanners/iac/checkov.sh", False, "reports/checkov.json", parse_checkov),
        "dast": ScanDef("dast", "DAST (ZAP baseline)", ROOT / "scanners/dast/zap.sh", True, "reports/zap.json", parse_zap),
        "iast": ScanDef("iast", "IAST-lite (Runtime header checks)", ROOT / "scanners/iast/iast.sh", True, "reports/iast-lite.json", parse_iast),
    }

    try:
        target, _ = ask_target()
        selected = ask_scans()
        if not selected:
            raise ValueError("No valid scan selected.")

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
                if err:
                    print(c(err.splitlines()[-1], Color.DIM))

            try:
                report = ROOT / scan.report_hint
                all_findings.extend(scan.parser(report))
            except Exception as parse_exc:
                print(c(f"Could not parse {scan.key} results: {parse_exc}", Color.YELLOW))

        print_summary(all_findings)
        combined_report = write_combined_report(target, selected, all_findings, executions)
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
