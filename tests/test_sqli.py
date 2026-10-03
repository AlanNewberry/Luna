import unittest
from unittest.mock import patch, MagicMock

from luna.modules.sqli import check_sql_injection, _inject_into_params


class TestSQLiModule(unittest.TestCase):
    def test_inject_into_params_with_query(self):
        result = _inject_into_params("https://example.com/api?id=1&name=test", "' OR '1'='1")
        self.assertIn("id=", result)
        self.assertNotIn("id=1", result)

    def test_inject_into_params_no_query(self):
        result = _inject_into_params("https://example.com/api", "payload")
        self.assertIsNone(result)

    @patch("luna.modules.sqli.requests.get")
    def test_sql_error_detected(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "You have an error in your SQL syntax near..."
        mock_get.return_value = mock_response

        findings = check_sql_injection(
            "https://example.com/api?id=1",
            ["' OR '1'='1"],
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "SQLI-001")
        self.assertEqual(findings[0].severity, "Critical")

    @patch("luna.modules.sqli.requests.get")
    def test_no_error_no_finding(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "OK, results here"
        mock_get.return_value = mock_response

        findings = check_sql_injection(
            "https://example.com/api?id=1",
            ["' OR '1'='1"],
        )
        self.assertEqual(len(findings), 0)

    @patch("luna.modules.sqli.requests.get")
    def test_500_status_detected(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_get.return_value = mock_response

        findings = check_sql_injection(
            "https://example.com/api?id=1",
            ["' UNION SELECT NULL--"],
        )
        self.assertEqual(len(findings), 1)

    def test_no_destructive_payloads_in_defaults(self):
        from luna.modules.sqli import DEFAULT_PAYLOADS
        for p in DEFAULT_PAYLOADS:
            self.assertNotIn("DROP", p.upper())
            self.assertNotIn("SHUTDOWN", p.upper())
            self.assertNotIn("DELETE", p.upper())


if __name__ == "__main__":
    unittest.main()
