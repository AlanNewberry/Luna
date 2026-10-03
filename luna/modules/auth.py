import time

import requests

from luna.core.findings import Finding


def check_weak_authentication(url: str, token: str) -> list:
    findings: list[Finding] = []
    start = time.time()

    # First: test WITHOUT auth to see if the endpoint is open
    try:
        response_no_auth = requests.get(url, timeout=5)
    except requests.RequestException:
        return findings

    if response_no_auth.status_code == 200:
        elapsed = time.time() - start
        findings.append(Finding(
            id="AUTH-001",
            title="Endpoint accessible without authentication",
            severity="High",
            description="The endpoint returned 200 OK without any authentication token, suggesting missing access controls.",
            evidence=f"Status without token: {response_no_auth.status_code} (module took {elapsed:.2f}s)",
            affected_resource=url,
            remediation="Require valid authentication credentials for this endpoint.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        ))

    # Second: test WITH the provided token
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response_with_auth = requests.get(url, headers=headers, timeout=5)
    except requests.RequestException:
        return findings

    if response_with_auth.status_code == 401:
        elapsed = time.time() - start
        findings.append(Finding(
            id="AUTH-002",
            title="Valid token rejected by endpoint",
            severity="Medium",
            description="The endpoint rejected the provided bearer token.",
            evidence=f"Status with token: {response_with_auth.status_code} (module took {elapsed:.2f}s)",
            affected_resource=url,
            remediation="Verify token validation logic, enforce expiration, and use strong signing algorithms.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        ))

    return findings
