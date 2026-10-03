import unittest
from unittest.mock import patch, MagicMock

from luna.modules.xss import check_xss, _inject_into_params


class TestXSSModule(unittest.TestCase):
    def test_inject_into_params_with_query(self):
        result = _inject_into_params("https://example.com/search?q=hello", "<script>alert(1)</script>")
        self.assertIn("q=", result)
        self.assertNotIn("q=hello", result)

    def test_inject_into_params_no_query(self):
        result = _inject_into_params("https://example.com/search", "payload")
        self.assertIsNone(result)

    @patch("luna.modules.xss.requests.get")
    def test_xss_reflected(self, mock_get):
        payload = "<script>alert('XSS')</script>"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"<html><body>{payload}</body></html>"
        mock_get.return_value = mock_response

        findings = check_xss("https://example.com/search?q=test", [payload])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "XSS-001")
        self.assertEqual(findings[0].severity, "High")

    @patch("luna.modules.xss.requests.get")
    def test_xss_not_reflected(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>safe content</body></html>"
        mock_get.return_value = mock_response

        findings = check_xss(
            "https://example.com/search?q=test",
            ["<script>alert('XSS')</script>"],
        )
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
