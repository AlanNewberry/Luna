import unittest
from unittest.mock import patch, MagicMock

from luna.modules.auth import check_weak_authentication


class TestAuthModule(unittest.TestCase):
    @patch("luna.modules.auth.requests.get")
    def test_endpoint_accessible_without_auth(self, mock_get):
        # First call (no auth) returns 200, second call (with token) returns 200
        resp_no_auth = MagicMock()
        resp_no_auth.status_code = 200
        resp_with_auth = MagicMock()
        resp_with_auth.status_code = 200
        mock_get.side_effect = [resp_no_auth, resp_with_auth]

        findings = check_weak_authentication("https://example.com/api/data", "test-token")
        auth_findings = [f for f in findings if f.id == "AUTH-001"]
        self.assertEqual(len(auth_findings), 1)
        self.assertEqual(auth_findings[0].severity, "High")

    @patch("luna.modules.auth.requests.get")
    def test_endpoint_requires_auth(self, mock_get):
        # First call (no auth) returns 401, second call (with token) returns 200
        resp_no_auth = MagicMock()
        resp_no_auth.status_code = 401
        resp_with_auth = MagicMock()
        resp_with_auth.status_code = 200
        mock_get.side_effect = [resp_no_auth, resp_with_auth]

        findings = check_weak_authentication("https://example.com/api/data", "test-token")
        auth_findings = [f for f in findings if f.id == "AUTH-001"]
        self.assertEqual(len(auth_findings), 0)

    @patch("luna.modules.auth.requests.get")
    def test_token_rejected(self, mock_get):
        # First call (no auth) returns 401, second call (with token) returns 401
        resp_no_auth = MagicMock()
        resp_no_auth.status_code = 401
        resp_with_auth = MagicMock()
        resp_with_auth.status_code = 401
        mock_get.side_effect = [resp_no_auth, resp_with_auth]

        findings = check_weak_authentication("https://example.com/api/data", "bad-token")
        reject_findings = [f for f in findings if f.id == "AUTH-002"]
        self.assertEqual(len(reject_findings), 1)
        self.assertEqual(reject_findings[0].severity, "Medium")


if __name__ == "__main__":
    unittest.main()
