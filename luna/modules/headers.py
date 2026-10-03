import time
from typing import List, Tuple

import requests
from urllib.parse import urlparse

from luna.core.findings import Finding

SECURITY_HEADERS: List[Tuple[str, str, str]] = [
    ("Strict-Transport-Security", "HSTS", "Medium"),
    ("Content-Security-Policy", "CSP", "Medium"),
    ("X-Content-Type-Options", "CTO", "Low"),
    ("X-Frame-Options", "XFO", "Medium"),
    ("X-XSS-Protection", "XSS-PROT", "Low"),
    ("Referrer-Policy", "REFERRER", "Low"),
    ("Permissions-Policy", "PERMISSIONS", "Low"),
]


def check_https_security(url: str) -> list:
    findings: list[Finding] = []
    parsed = urlparse(url)
    start = time.time()

    if parsed.scheme != "https":
        findings.append(Finding(
            id="HEADERS-HTTP",
            title="HTTP used instead of HTTPS",
            severity="High",
            description="The target URL uses HTTP, which transmits data in plaintext.",
            evidence=f"URL scheme: {parsed.scheme}",
            affected_resource=url,
            remediation="Enforce HTTPS across all endpoints.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        ))

    try:
        response = requests.get(url, verify=True, timeout=5)
    except requests.RequestException:
        findings.append(Finding(
            id="HEADERS-CONN",
            title="HTTPS connection failed",
            severity="High",
            description="Could not establish a secure connection to the target.",
            evidence="Connection or SSL error during request",
            affected_resource=url,
            remediation="Verify the server's TLS configuration and certificate validity.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        ))
        return findings

    for header_name, label, severity in SECURITY_HEADERS:
        if header_name not in response.headers:
            findings.append(Finding(
                id=f"HEADERS-{label}",
                title=f"Missing {header_name} header",
                severity=severity,
                description=f"The server does not set the {header_name} header.",
                evidence=f"{header_name} header absent from response",
                affected_resource=url,
                remediation=f"Add the {header_name} header with an appropriate value.",
                references=["https://owasp.org/www-project-secure-headers/"],
            ))

    elapsed = time.time() - start
    for f in findings:
        f.evidence += f" (module took {elapsed:.2f}s)"

    return findings
