from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


PLUGIN_TYPES = {"sast", "sca", "secrets", "iac", "cspm", "easm", "dast", "iast"}
EVENT_TYPES = {"pr", "deploy", "runtime"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
CONFIDENCE = {"HIGH", "MEDIUM", "LOW"}


@dataclass
class ScanTarget:
    repo_url: str
    branch: str = "main"
    commit_sha: str | None = None
    environment: str = "dev"
    runtime_url: str | None = None


@dataclass
class Finding:
    plugin_type: str
    tool: str
    rule_id: str
    title: str
    severity: str
    confidence: str
    file_path: str
    line: int | None
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanRequest:
    event_type: str
    target: ScanTarget
    requested_plugins: list[str] | None = None
    context: dict[str, Any] = field(default_factory=dict)
    actor: str = "system"
    roles: list[str] = field(default_factory=lambda: ["security_engineer"])


@dataclass
class ScanContext:
    deployment_tier: str = "non_prod"
    internet_exposed: bool = False
    data_classification: str = "internal"
    business_service: str = "unknown"
    known_exploits: bool = False


@dataclass
class PluginExecution:
    plugin: str
    tool: str
    status: str
    started_at: str
    ended_at: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


@dataclass
class UnifiedRisk:
    risk_id: str
    title: str
    severity: str
    exploitability_score: float
    exposure_score: float
    business_impact_score: float
    composite_score: float
    business_service: str
    internet_exposed: bool
    correlated_findings: list[dict[str, Any]]
    recommendation: str


@dataclass
class AIInsight:
    risk_id: str
    summary: str
    probable_root_cause: str
    fix_suggestions: list[str]
    confidence: float


@dataclass
class RemediationPlan:
    risk_id: str
    action_type: str
    files_to_change: list[str]
    patch_summary: str
    validation_steps: list[str]
    safe_to_auto_apply: bool = False


@dataclass
class ScanResponse:
    request_id: str
    event_type: str
    target: dict[str, Any]
    executed_plugins: list[dict[str, Any]]
    unified_risks: list[dict[str, Any]]
    ai_insights: list[dict[str, Any]]
    remediation_plans: list[dict[str, Any]]
    generated_at: str


@dataclass
class AuditEvent:
    actor: str
    action: str
    resource: str
    status: str
    message: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


def to_dict(obj: Any) -> dict[str, Any]:
    return asdict(obj)


def normalize_severity(value: str) -> str:
    sev = (value or "MEDIUM").upper()
    aliases = {
        "WARN": "MEDIUM",
        "WARNING": "MEDIUM",
        "ERROR": "HIGH",
        "INFORMATIONAL": "INFO",
    }
    sev = aliases.get(sev, sev)
    return sev if sev in SEVERITIES else "MEDIUM"


def normalize_confidence(value: str) -> str:
    conf = (value or "MEDIUM").upper()
    return conf if conf in CONFIDENCE else "MEDIUM"


def validate_scan_request_data(payload: dict[str, Any]) -> None:
    event_type = payload.get("event_type", "pr")
    if event_type not in EVENT_TYPES:
        raise ValueError(f"invalid event_type: {event_type}")

    target = payload.get("target")
    if not isinstance(target, dict):
        raise ValueError("target must be an object")
    if not target.get("repo_url"):
        raise ValueError("target.repo_url is required")

    actor = payload.get("actor")
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor is required")

    roles = payload.get("roles")
    if not isinstance(roles, list) or not roles:
        raise ValueError("roles must be a non-empty list")
    if not all(isinstance(r, str) and r.strip() for r in roles):
        raise ValueError("roles must contain non-empty strings")

    requested_plugins = payload.get("requested_plugins")
    if requested_plugins is not None:
        if not isinstance(requested_plugins, list):
            raise ValueError("requested_plugins must be a list")
        invalid = [p for p in requested_plugins if p not in PLUGIN_TYPES]
        if invalid:
            raise ValueError(f"invalid requested_plugins: {','.join(invalid)}")


def validate_finding(finding: Finding) -> None:
    if finding.plugin_type not in PLUGIN_TYPES:
        raise ValueError(f"invalid plugin_type: {finding.plugin_type}")
    finding.severity = normalize_severity(finding.severity)
    finding.confidence = normalize_confidence(finding.confidence)
    if not finding.rule_id:
        raise ValueError("rule_id is required")
    if not finding.title:
        raise ValueError("title is required")
    if not finding.file_path:
        finding.file_path = "N/A"
