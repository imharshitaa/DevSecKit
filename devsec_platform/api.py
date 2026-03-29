from __future__ import annotations

import json
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from urllib.parse import urlparse

from devsec_platform.orchestrator import Orchestrator
from devsec_platform.schemas import ScanRequest, ScanTarget, validate_scan_request_data


def is_authorized(headers: dict, expected_token: str) -> bool:
    token = (expected_token or "").strip()
    if not token:
        return False
    auth_header = headers.get("Authorization", "")
    api_key = headers.get("X-API-Key", "")
    return auth_header == f"Bearer {token}" or api_key == token


class DevSecAPIHandler(BaseHTTPRequestHandler):
    orchestrator = Orchestrator()

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _is_authorized(self) -> bool:
        token = os.environ.get("DEVSEC_API_TOKEN", "").strip()
        return is_authorized(dict(self.headers), token)

    def _allowed_roles(self) -> set[str]:
        raw = os.environ.get("DEVSEC_API_ALLOWED_ROLES", "security_engineer,appsec_lead,developer")
        return {r.strip() for r in raw.split(",") if r.strip()}

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._json(200, {"status": "ok"})
            return

        if parsed.path.startswith("/api/") and not self._is_authorized():
            self._json(401, {"error": "unauthorized"})
            return

        if parsed.path == "/api/v1/plugins":
            self._json(200, {"plugins": self.orchestrator.registry.list_plugins()})
            return

        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/") and not self._is_authorized():
            self._json(401, {"error": "unauthorized"})
            return

        if parsed.path == "/api/v1/scans":
            try:
                payload = self._read_json()
                validate_scan_request_data(payload)
                allowed_roles = self._allowed_roles()
                req_roles = payload.get("roles", [])
                disallowed = [r for r in req_roles if r not in allowed_roles]
                if disallowed:
                    self._json(403, {"error": f"disallowed roles: {','.join(disallowed)}"})
                    return
                target_data = payload.get("target", {})
                target = ScanTarget(
                    repo_url=target_data.get("repo_url", "local://repo"),
                    branch=target_data.get("branch", "main"),
                    commit_sha=target_data.get("commit_sha"),
                    environment=target_data.get("environment", "dev"),
                    runtime_url=target_data.get("runtime_url"),
                )
                request = ScanRequest(
                    event_type=payload.get("event_type", "pr"),
                    target=target,
                    requested_plugins=payload.get("requested_plugins"),
                    context=payload.get("context", {}),
                    actor=payload.get("actor"),
                    roles=payload.get("roles"),
                )
                response = self.orchestrator.run(request)
                self._json(200, asdict(response))
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return

        if parsed.path == "/api/v1/remediations/preview":
            payload = self._read_json()
            repo = payload.get("repo", "owner/repo")
            plan = payload.get("plan", {})
            result = {
                "created": False,
                "branch": f"codex/remediate-{plan.get('risk_id', 'risk').lower()}",
                "pr_url": f"https://github.com/{repo}/pulls",
                "title": f"fix(security): remediate {plan.get('risk_id', 'RISK')}",
            }
            self._json(200, result)
            return

        self._json(404, {"error": "not_found"})


def run_api_server(host: str = "127.0.0.1", port: int = 8787) -> None:
    server = HTTPServer((host, port), DevSecAPIHandler)
    print(f"DevSec platform API listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_api_server()
