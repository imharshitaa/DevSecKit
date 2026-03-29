from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class GuardrailResult:
    allowed: bool
    reason: str


class RBACEngine:
    role_permissions = {
        "security_engineer": {"scan:run", "risk:read", "remediate:propose"},
        "appsec_lead": {"scan:run", "risk:read", "remediate:propose", "remediate:apply"},
        "developer": {"scan:run", "risk:read", "remediate:propose"},
        "viewer": {"risk:read"},
    }

    @classmethod
    def authorize(cls, roles: list[str], permission: str) -> GuardrailResult:
        for role in roles:
            perms = cls.role_permissions.get(role, set())
            if permission in perms:
                return GuardrailResult(True, f"role '{role}' granted")
        return GuardrailResult(False, f"missing permission: {permission}")


class ValidationEngine:
    @staticmethod
    def validate_remediation_plan(files_to_change: list[str], patch_summary: str, repo_root: str | None = None) -> GuardrailResult:
        if not files_to_change:
            return GuardrailResult(False, "no files to change")
        if len(files_to_change) > 20:
            return GuardrailResult(False, "too many files in remediation plan")
        lowered_summary = (patch_summary or "").lower()
        if "rm -rf" in lowered_summary or "drop table" in lowered_summary:
            return GuardrailResult(False, "dangerous remediation content detected")
        if any(path.startswith("/") and "/etc/" in path for path in files_to_change):
            return GuardrailResult(False, "protected filesystem path in remediation plan")
        if any(path.startswith("http://") or path.startswith("https://") or path.startswith("cloud://") for path in files_to_change):
            return GuardrailResult(False, "non-repository target path detected")
        blocked_segments = [".github/workflows", ".git/", ".ssh/", "id_rsa", "secrets", ".env", "credentials", "kubeconfig"]
        for path in files_to_change:
            norm = path.replace("\\", "/").lower()
            if any(seg in norm for seg in blocked_segments):
                return GuardrailResult(False, f"privilege-sensitive path blocked: {path}")
        allowed_suffixes = (".py", ".js", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".tf", ".yaml", ".yml", ".json", ".xml", ".toml", ".ini", ".cfg", ".md")
        if any("." in path and not path.endswith(allowed_suffixes) for path in files_to_change):
            return GuardrailResult(False, "disallowed file type in remediation plan")
        if len((patch_summary or "").strip()) < 20:
            return GuardrailResult(False, "patch summary is too short")
        dangerous_tokens = ["sudo ", "curl ", "wget ", "chmod 777", "chown ", "bash -c", "sh -c", "eval("]
        if any(tok in lowered_summary for tok in dangerous_tokens):
            return GuardrailResult(False, "patch summary contains disallowed command-like content")

        if repo_root:
            root = Path(repo_root).resolve()
            for path in files_to_change:
                candidate = (root / path).resolve()
                if root not in candidate.parents and candidate != root:
                    return GuardrailResult(False, f"path escapes repository root: {path}")
        return GuardrailResult(True, "remediation validation passed")
