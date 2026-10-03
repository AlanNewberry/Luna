import unittest
from unittest.mock import patch, MagicMock

from luna.modules.headers import check_https_security


class TestHeadersModule(unittest.TestCase):
    @patch("luna.modules.headers.requests.get")
    def test_missing_hsts_header(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_get.return_value = mock_response

        findings = check_https_security("https://example.com")
        hsts_findings = [f for f in findings if f.id == "HEADERS-HSTS"]
        self.assertEqual(len(hsts_findings), 1)
        self.assertEqual(hsts_findings[0].severity, "Medium")

    @patch("luna.modules.headers.requests.get")
    def test_hsts_present(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        }
        mock_get.return_value = mock_response

        findings = check_https_security("https://example.com")
        header_findings = [f for f in findings if f.id.startswith("HEADERS-")]
        self.assertEqual(len(header_findings), 0)

    def test_http_scheme_detected(self):
        with patch("luna.modules.headers.requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
            }
            mock_get.return_value = mock_response

            findings = check_https_security("http://example.com")
            http_findings = [f for f in findings if f.id == "HEADERS-HTTP"]
            self.assertEqual(len(http_findings), 1)
            self.assertEqual(http_findings[0].severity, "High")

    @patch("luna.modules.headers.requests.get")
    def test_connection_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.RequestException("Connection failed")

        findings = check_https_security("https://example.com")
        error_findings = [f for f in findings if f.id == "HEADERS-CONN"]
        self.assertEqual(len(error_findings), 1)

    @patch("luna.modules.headers.requests.get")
    def test_missing_csp_header(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Strict-Transport-Security": "max-age=31536000"}
        mock_get.return_value = mock_response

        findings = check_https_security("https://example.com")
        csp_findings = [f for f in findings if f.id == "HEADERS-CSP"]
        self.assertEqual(len(csp_findings), 1)
        self.assertEqual(csp_findings[0].severity, "Medium")

    @patch("luna.modules.headers.requests.get")
    def test_all_seven_headers_missing(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_get.return_value = mock_response

        findings = check_https_security("https://example.com")
        header_findings = [f for f in findings if f.id.startswith("HEADERS-")]
        self.assertEqual(len(header_findings), 7)


if __name__ == "__main__":
    unittest.main()
