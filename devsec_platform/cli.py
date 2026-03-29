from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import PurePosixPath

from devsec_platform.orchestrator import Orchestrator
from devsec_platform.schemas import ScanRequest, ScanTarget


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"


def c(text: str, color: str) -> str:
    return f"{color}{text}{Color.RESET}"


def sev_color(sev: str) -> str:
    s = (sev or "").upper()
    if s in {"CRITICAL", "HIGH"}:
        return Color.RED
    if s == "MEDIUM":
        return Color.YELLOW
    return Color.GREEN


def print_summary(response: dict) -> None:
    all_findings = []
    for ex in response.get("executed_plugins", []):
        all_findings.extend(ex.get("findings", []))

    sev_counts = Counter((f.get("severity") or "UNKNOWN").upper() for f in all_findings)
    print(c("\n=== Findings Summary ===", Color.CYAN + Color.BOLD))
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]:
        if sev_counts.get(sev):
            print(f"{c(sev, sev_color(sev))}: {sev_counts[sev]}")


def print_final_report(response: dict) -> None:
    findings = []
    for ex in response.get("executed_plugins", []):
        findings.extend(ex.get("findings", []))

    risks = response.get("unified_risks", [])
    insights_by_risk = {i.get("risk_id"): i for i in response.get("ai_insights", [])}
    plans_by_risk = {p.get("risk_id"): p for p in response.get("remediation_plans", [])}

    target_files = []
    for f in findings:
        path = str(f.get("file_path") or "N/A")
        if path not in target_files:
            target_files.append(path)

    print(c("\n============================================================", Color.CYAN))
    print(c("FINAL SECURITY REPORT", Color.CYAN + Color.BOLD))
    print(c("============================================================", Color.CYAN))
    print(f"Target: {response.get('target', {}).get('repo_url', 'N/A')}")
    print(f"Event: {response.get('event_type', 'N/A')}")
    print("Plugins Executed: " + ", ".join(ex.get("plugin", "unknown") for ex in response.get("executed_plugins", [])))
    print(f"Total Findings: {len(findings)} | Total Unified Risks: {len(risks)}")

    print(c("\nTarget Files Used", Color.MAGENTA + Color.BOLD))
    if target_files:
        for idx, full_path in enumerate(target_files, start=1):
            file_name = PurePosixPath(full_path).name if "/" in full_path else full_path
            print(f"{idx:02d}. {file_name}  ({full_path})")
    else:
        print("No target files.")

    print_summary(response)

    if not risks:
        print(c("\nNo risks detected.", Color.GREEN))
        return

    print(c("\nConsolidated Risk Results", Color.MAGENTA + Color.BOLD))
    for idx, r in enumerate(risks, start=1):
        sev = (r.get("severity") or "UNKNOWN").upper()
        risk_id = r.get("risk_id", "N/A")
        print(f"\n[{idx:02d}] {risk_id} {c('[' + sev + ']', sev_color(sev))}")
        print(f"Title                 : {r.get('title', 'N/A')}")
        print(
            "Risk Scores           : "
            f"composite={r.get('composite_score')} "
            f"exploitability={r.get('exploitability_score')} "
            f"exposure={r.get('exposure_score')} "
            f"business_impact={r.get('business_impact_score')}"
        )
        print(f"Business Service      : {r.get('business_service', 'unknown')}")
        print(f"Internet Exposed      : {r.get('internet_exposed')}")
        print(f"Recommendation        : {r.get('recommendation', 'N/A')}")

        correlated = r.get("correlated_findings") or []
        if correlated:
            top = correlated[0]
            line = top.get("line")
            line_str = str(line) if line is not None else "N/A"
            print(
                "Primary Location      : "
                f"{top.get('file_path', 'N/A')}:{line_str} "
                f"({top.get('plugin_type', 'N/A')} via {top.get('tool', 'N/A')})"
            )

        insight = insights_by_risk.get(risk_id, {})
        if insight:
            print(f"Why Risky             : {insight.get('summary', 'N/A')}")
            print(f"Root Cause            : {insight.get('probable_root_cause', 'N/A')}")
            fixes = insight.get("fix_suggestions") or []
            if fixes:
                print(f"Remediation Guidance  : {fixes[0]}")

        plan = plans_by_risk.get(risk_id, {})
        if plan:
            files = ", ".join(plan.get("files_to_change", [])[:4]) or "N/A"
            print(f"Auto-Remediation Plan : {plan.get('action_type', 'N/A')} | safe_to_auto_apply={plan.get('safe_to_auto_apply')}")
            print(f"Files To Change       : {files}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="DevSecKit Platform CLI report mode")
    p.add_argument("--event", default="pr", choices=["pr", "deploy", "runtime"])
    p.add_argument("--repo", help="Target repository URL")
    p.add_argument("--runtime-url", default="")
    p.add_argument("--business-service", default="unknown")
    p.add_argument("--internet-exposed", action="store_true")
    p.add_argument("--data-classification", default="internal")
    p.add_argument("--known-exploits", action="store_true")
    p.add_argument("--plugins", default="", help="Comma-separated plugin types")
    p.add_argument("--json", action="store_true", help="Also print full JSON")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    repo = args.repo or input("Enter git repository URL: ").strip()
    if not repo:
        print("Repository URL is required.")
        return 1

    requested_plugins = [x.strip() for x in args.plugins.split(",") if x.strip()] or None

    req = ScanRequest(
        event_type=args.event,
        target=ScanTarget(
            repo_url=repo,
            environment="prod" if args.event in {"deploy", "runtime"} else "dev",
            runtime_url=args.runtime_url or None,
        ),
        requested_plugins=requested_plugins,
        context={
            "business_service": args.business_service,
            "internet_exposed": args.internet_exposed,
            "data_classification": args.data_classification,
            "known_exploits": args.known_exploits,
        },
        roles=["security_engineer"],
        actor="terminal-user",
    )

    orchestrator = Orchestrator()
    response = orchestrator.run(req)
    data = {
        "request_id": response.request_id,
        "event_type": response.event_type,
        "target": response.target,
        "executed_plugins": response.executed_plugins,
        "unified_risks": response.unified_risks,
        "ai_insights": response.ai_insights,
        "remediation_plans": response.remediation_plans,
        "generated_at": response.generated_at,
    }

    print(c("\nDevSecKit Platform Terminal Report", Color.BOLD + Color.CYAN))
    print(f"Target: {data['target'].get('repo_url')}")
    print(f"Event: {data['event_type']}")
    print("Plugins Executed: " + ", ".join(ex.get("plugin", "unknown") for ex in data["executed_plugins"]))
    print_final_report(data)

    if args.json:
        print(c("\n=== Raw JSON ===", Color.CYAN + Color.BOLD))
        print(json.dumps(data, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
