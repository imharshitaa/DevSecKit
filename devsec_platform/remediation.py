from __future__ import annotations

from dataclasses import dataclass
import os
import subprocess

from devsec_platform.schemas import AIInsight, RemediationPlan, UnifiedRisk


@dataclass
class PRResult:
    created: bool
    pr_url: str
    branch: str
    title: str


class AutoRemediationEngine:
    @staticmethod
    def generate_plans(risks: list[UnifiedRisk], insights: list[AIInsight]) -> list[RemediationPlan]:
        insight_map = {i.risk_id: i for i in insights}
        plans: list[RemediationPlan] = []
        for risk in risks:
            if risk.severity not in {"CRITICAL", "HIGH", "MEDIUM"}:
                continue

            files = []
            for f in risk.correlated_findings:
                path = f.get("file_path", "")
                if not path:
                    continue
                if path.startswith(("cloud://", "http://", "https://", "runtime://")):
                    continue
                lowered = path.lower().replace("\\", "/")
                if any(seg in lowered for seg in [".github/workflows", ".git/", ".env", "secrets", "credentials", ".ssh/"]):
                    continue
                if path not in files:
                    files.append(path)

            suggestion = insight_map.get(risk.risk_id)
            summary = suggestion.fix_suggestions[0] if suggestion and suggestion.fix_suggestions else "Apply secure baseline fix."

            if not files:
                continue

            plans.append(
                RemediationPlan(
                    risk_id=risk.risk_id,
                    action_type="github_pr",
                    files_to_change=files[:5],
                    patch_summary=summary,
                    validation_steps=[
                        "Run unit tests",
                        "Re-run affected scanners",
                        "Require code review approval",
                    ],
                    safe_to_auto_apply=risk.severity in {"MEDIUM"},
                )
            )
        return plans


class GitHubRemediator:
    @staticmethod
    def create_pr(plan: RemediationPlan, repo: str, base_branch: str = "main", dry_run: bool = True) -> PRResult:
        branch = f"codex/remediate-{plan.risk_id.lower()}"
        title = f"fix(security): remediate {plan.risk_id}"
        if dry_run:
            return PRResult(
                created=False,
                pr_url=f"https://github.com/{repo}/pull/new/{branch}",
                branch=branch,
                title=title,
            )

        if not os.environ.get("GITHUB_TOKEN"):
            return PRResult(created=False, pr_url="", branch=branch, title=f"{title} (missing GITHUB_TOKEN)")

        # Minimal real behavior (best effort): assumes branch and commits already prepared.
        cmd = [
            "gh",
            "pr",
            "create",
            "--repo",
            repo,
            "--base",
            base_branch,
            "--head",
            branch,
            "--title",
            title,
            "--body",
            f"Auto-remediation for {plan.risk_id}\\n\\n{plan.patch_summary}",
        ]
        proc = subprocess.run(cmd, text=True, capture_output=True)
        if proc.returncode == 0:
            return PRResult(created=True, pr_url=proc.stdout.strip(), branch=branch, title=title)

        return PRResult(
            created=False,
            pr_url=proc.stderr.strip(),
            branch=branch,
            title=title,
        )
