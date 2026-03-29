from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
import shutil
import subprocess
import tempfile
from uuid import uuid4

from devsec_platform.ai_module import analyze_risks, suggest_plugins_for_event
from devsec_platform.audit import AuditLogger
from devsec_platform.guardrails import RBACEngine, ValidationEngine
from devsec_platform.plugins.registry import PluginRegistry
from devsec_platform.remediation import AutoRemediationEngine, GitHubRemediator, PRResult
from devsec_platform.risk_engine import correlate_findings
from devsec_platform.schemas import (
    AuditEvent,
    PluginExecution,
    RemediationPlan,
    ScanRequest,
    ScanResponse,
    to_dict,
)


class Orchestrator:
    def __init__(self) -> None:
        self.registry = PluginRegistry()
        self.audit = AuditLogger()

    def _resolve_target_path(self, request: ScanRequest) -> tuple[str, str | None]:
        repo = request.target.repo_url
        maybe_local = Path(repo)
        if maybe_local.exists() and maybe_local.is_dir():
            return str(maybe_local.resolve()), None

        if repo.startswith("http://") or repo.startswith("https://"):
            tmp_root = Path(tempfile.mkdtemp(prefix="devsec-target-"))
            clone_path = tmp_root / "repo"
            proc = subprocess.run(
                ["git", "clone", "--depth", "1", repo, str(clone_path)],
                text=True,
                capture_output=True,
                timeout=300,
            )
            if proc.returncode != 0:
                raise RuntimeError(proc.stderr.strip() or f"git clone failed for {repo}")
            return str(clone_path), str(tmp_root)

        raise ValueError("target.repo_url must be an existing local directory or a git URL")

    def select_plugins(self, request: ScanRequest) -> list[str]:
        if request.requested_plugins:
            return request.requested_plugins

        base = ["sast", "sca", "secrets", "iac"]
        if request.event_type == "deploy":
            base.extend(["cspm", "easm"])
        if request.event_type == "runtime":
            base = ["iast", "dast", "cspm", "easm", "secrets"]

        ai_plugins = suggest_plugins_for_event(request.event_type, request.context)
        combined = []
        for name in base + ai_plugins:
            if name not in combined:
                combined.append(name)
        return combined

    def _execute_plugin(self, plugin_name: str, request: ScanRequest) -> tuple[PluginExecution, list]:
        plugin = self.registry.get(plugin_name)
        started = datetime.utcnow().isoformat() + "Z"
        if not plugin:
            ended = datetime.utcnow().isoformat() + "Z"
            execution = PluginExecution(
                plugin=plugin_name,
                tool="unknown",
                status="failed",
                started_at=started,
                ended_at=ended,
                findings=[],
                error="plugin not registered",
            )
            return execution, []

        try:
            plugin_findings = plugin.run(request)
            ended = datetime.utcnow().isoformat() + "Z"
            execution = PluginExecution(
                plugin=plugin_name,
                tool=plugin.tool_name,
                status="success",
                started_at=started,
                ended_at=ended,
                findings=plugin_findings,
            )
            return execution, plugin_findings
        except Exception as exc:
            ended = datetime.utcnow().isoformat() + "Z"
            execution = PluginExecution(
                plugin=plugin_name,
                tool=plugin.tool_name,
                status="failed",
                started_at=started,
                ended_at=ended,
                findings=[],
                error=str(exc),
            )
            return execution, []

    def run(self, request: ScanRequest) -> ScanResponse:
        auth = RBACEngine.authorize(request.roles, "scan:run")
        if not auth.allowed:
            self.audit.write(AuditEvent(actor=request.actor, action="scan.run", resource=request.target.repo_url, status="DENY", message=auth.reason))
            raise PermissionError(auth.reason)

        selected_plugins = self.select_plugins(request)
        executions: list[PluginExecution] = []
        findings = []
        target_path, cleanup_dir = self._resolve_target_path(request)
        request_copy = copy.deepcopy(request)
        request_copy.context["_resolved_target_path"] = target_path
        request_copy.context["_repo_root"] = target_path

        try:
            with ThreadPoolExecutor(max_workers=max(1, min(6, len(selected_plugins)))) as pool:
                future_map = {pool.submit(self._execute_plugin, name, request_copy): name for name in selected_plugins}
                for future in as_completed(future_map):
                    execution, plugin_findings = future.result()
                    executions.append(execution)
                    findings.extend(plugin_findings)
        finally:
            if cleanup_dir:
                shutil.rmtree(cleanup_dir, ignore_errors=True)

        # Preserve plugin selection order for readability in reports.
        execution_order = {name: idx for idx, name in enumerate(selected_plugins)}
        executions.sort(key=lambda e: execution_order.get(e.plugin, 999))

        risks = correlate_findings(findings, request_copy.context)
        insights = analyze_risks(risks)
        plans = AutoRemediationEngine.generate_plans(risks, insights)

        validated_plans = []
        for p in plans:
            result = ValidationEngine.validate_remediation_plan(
                p.files_to_change,
                p.patch_summary,
                repo_root=request_copy.context.get("_repo_root"),
            )
            if result.allowed:
                validated_plans.append(p)

        response = ScanResponse(
            request_id=str(uuid4()),
            event_type=request.event_type,
            target=to_dict(request.target),
            executed_plugins=[to_dict(e) for e in executions],
            unified_risks=[to_dict(r) for r in risks],
            ai_insights=[to_dict(i) for i in insights],
            remediation_plans=[to_dict(p) for p in validated_plans],
            generated_at=datetime.utcnow().isoformat() + "Z",
        )

        self.audit.write(
            AuditEvent(
                actor=request.actor,
                action="scan.run",
                resource=request.target.repo_url,
                status="OK",
                message=f"plugins={','.join(selected_plugins)} findings={len(findings)} risks={len(risks)}",
            )
        )

        return response

    def apply_remediation(
        self,
        plan: RemediationPlan,
        repo: str,
        roles: list[str],
        actor: str,
        dry_run: bool = True,
        repo_root: str | None = None,
    ) -> PRResult:
        auth = RBACEngine.authorize(roles, "remediate:apply")
        if not auth.allowed:
            self.audit.write(AuditEvent(actor=actor, action="remediate.apply", resource=repo, status="DENY", message=auth.reason))
            raise PermissionError(auth.reason)

        if not dry_run and not plan.safe_to_auto_apply:
            reason = "plan is not marked safe_to_auto_apply"
            self.audit.write(AuditEvent(actor=actor, action="remediate.apply", resource=repo, status="DENY", message=reason))
            raise ValueError(reason)

        validation = ValidationEngine.validate_remediation_plan(
            plan.files_to_change,
            plan.patch_summary,
            repo_root=repo_root,
        )
        if not validation.allowed:
            self.audit.write(AuditEvent(actor=actor, action="remediate.apply", resource=repo, status="DENY", message=validation.reason))
            raise ValueError(validation.reason)

        result = GitHubRemediator.create_pr(plan=plan, repo=repo, dry_run=dry_run)
        status = "OK" if result.created else "PENDING"
        self.audit.write(
            AuditEvent(
                actor=actor,
                action="remediate.apply",
                resource=repo,
                status=status,
                message=f"risk={plan.risk_id} branch={result.branch} pr={result.pr_url}",
            )
        )
        return result
