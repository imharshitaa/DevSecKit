from __future__ import annotations

import json
import os
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from devsec_platform.api import DevSecAPIHandler, is_authorized


class APIAuthTests(unittest.TestCase):
    def test_rejects_missing_token(self) -> None:
        self.assertFalse(is_authorized({}, ""))

    def test_accepts_bearer_token(self) -> None:
        headers = {"Authorization": "Bearer test-token"}
        self.assertTrue(is_authorized(headers, "test-token"))

    def test_accepts_x_api_key(self) -> None:
        headers = {"X-API-Key": "test-token"}
        self.assertTrue(is_authorized(headers, "test-token"))

    def test_rejects_invalid_token(self) -> None:
        headers = {"Authorization": "Bearer wrong-token"}
        self.assertFalse(is_authorized(headers, "test-token"))


class APIServerIntegrationTests(unittest.TestCase):
    """Exercises the real HTTP handler end-to-end over a loopback socket."""

    TOKEN = "test-secret-token"

    @classmethod
    def setUpClass(cls) -> None:
        cls._env_overrides = {
            "DEVSEC_API_TOKEN": cls.TOKEN,
            "DEVSEC_API_ALLOWED_ROLES": "security_engineer,appsec_lead,developer,viewer",
        }
        cls._old_env = {k: os.environ.get(k) for k in cls._env_overrides}
        os.environ.update(cls._env_overrides)

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DevSecAPIHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        for key, value in cls._old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _request(self, method: str, path: str, body: dict | None = None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.TOKEN}")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_health_check_does_not_require_auth(self) -> None:
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health") as resp:
            self.assertEqual(resp.status, 200)

    def test_scan_denies_role_without_scan_permission(self) -> None:
        status, payload = self._request(
            "POST",
            "/api/v1/scans",
            {
                "event_type": "pr",
                "target": {"repo_url": "."},
                "actor": "tester",
                "roles": ["viewer"],
            },
        )
        self.assertEqual(status, 403)
        self.assertIn("missing permission", payload["error"])

    def test_scan_rejects_oversized_body_with_413(self) -> None:
        with patch("devsec_platform.api.MAX_REQUEST_BODY_BYTES", 1024):
            status, _ = self._request("POST", "/api/v1/scans", {"padding": "x" * 2000})
        self.assertEqual(status, 413)

    def test_remediation_preview_denies_role_without_permission(self) -> None:
        status, payload = self._request(
            "POST",
            "/api/v1/remediations/preview",
            {"repo": "owner/repo", "plan": {"risk_id": "RISK-1"}, "roles": ["viewer"]},
        )
        self.assertEqual(status, 403)
        self.assertIn("missing permission", payload["error"])

    def test_remediation_preview_allows_authorized_role(self) -> None:
        status, payload = self._request(
            "POST",
            "/api/v1/remediations/preview",
            {"repo": "owner/repo", "plan": {"risk_id": "RISK-1"}, "roles": ["security_engineer"]},
        )
        self.assertEqual(status, 200)
        self.assertFalse(payload["created"])


if __name__ == "__main__":
    unittest.main()
