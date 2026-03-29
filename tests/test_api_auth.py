from __future__ import annotations

import unittest

from devsec_platform.api import is_authorized


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


if __name__ == "__main__":
    unittest.main()
