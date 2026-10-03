import time
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from luna.core.findings import Finding


def _substitute_param(url: str, param_name: str, value: str) -> Optional[str]:
    """Replace a specific query parameter value using proper URL encoding."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if param_name not in params:
        return None
    params[param_name] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check_idor(url: str, param_name: str, valid_value: str, invalid_value: str) -> list:
    findings: list[Finding] = []
    start = time.time()

    valid_url = _substitute_param(url, param_name, valid_value)
    invalid_url = _substitute_param(url, param_name, invalid_value)

    if valid_url is None or invalid_url is None:
        return findings

    try:
        response_valid = requests.get(valid_url, timeout=5)
        response_invalid = requests.get(invalid_url, timeout=5)
    except requests.RequestException:
        return findings

    if response_valid.status_code == 200 and response_invalid.status_code == 200:
        elapsed = time.time() - start
        findings.append(Finding(
            id="IDOR-001",
            title="Possible IDOR vulnerability",
            severity="High",
            description="Both a valid and invalid resource ID returned 200 OK, suggesting missing authorization checks.",
            evidence=(
                f"Valid ({valid_value}): {response_valid.status_code}, "
                f"Invalid ({invalid_value}): {response_invalid.status_code} "
                f"(module took {elapsed:.2f}s)"
            ),
            affected_resource=url,
            remediation="Implement proper authorization checks to ensure users can only access their own resources.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        ))

    return findings
