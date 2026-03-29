from __future__ import annotations

import unittest

from devsec_platform.guardrails import ValidationEngine
from devsec_platform.schemas import validate_scan_request_data


class ValidationTests(unittest.TestCase):
    def test_scan_request_requires_actor_roles(self) -> None:
        with self.assertRaises(ValueError):
            validate_scan_request_data(
                {
                    "event_type": "pr",
                    "target": {"repo_url": "."},
                }
            )

    def test_scan_request_accepts_valid_payload(self) -> None:
        validate_scan_request_data(
            {
                "event_type": "pr",
                "target": {"repo_url": "."},
                "actor": "tester",
                "roles": ["developer"],
                "requested_plugins": ["sast", "sca"],
            }
        )

    def test_remediation_guardrail_blocks_sensitive_paths(self) -> None:
        result = ValidationEngine.validate_remediation_plan(
            [".github/workflows/deploy.yml"],
            "Update dangerous workflow",
            repo_root=".",
        )
        self.assertFalse(result.allowed)

    def test_remediation_guardrail_blocks_command_like_patch(self) -> None:
        result = ValidationEngine.validate_remediation_plan(
            ["src/app.py"],
            "Apply change and run curl http://malicious",
            repo_root=".",
        )
        self.assertFalse(result.allowed)


if __name__ == "__main__":
    unittest.main()
