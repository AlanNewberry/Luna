import time
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from luna.core.findings import Finding

DEFAULT_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
]


def _inject_into_params(url: str, payload: str) -> Optional[str]:
    """Inject payload into each query parameter of the URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return None
    injected = {}
    for key in params:
        injected[key] = payload
    new_query = urlencode(injected, doseq=False)
    return urlunparse(parsed._replace(query=new_query))


def check_xss(
    url: str,
    payloads: Optional[list] = None,
) -> list:
    findings: list[Finding] = []
    if payloads is None:
        payloads = DEFAULT_PAYLOADS
    start = time.time()

    for payload in payloads:
        injected_url = _inject_into_params(url, payload)
        if injected_url is None:
            continue

        try:
            response = requests.get(injected_url, timeout=5)
        except requests.RequestException:
            continue

        if payload in response.text:
            findings.append(Finding(
                id="XSS-001",
                title="Reflected XSS detected",
                severity="High",
                description="The server reflected a script payload back in the response body without sanitization.",
                evidence=f"Payload reflected: {payload}",
                affected_resource=url,
                remediation="Sanitize and encode all user-supplied input before rendering it in responses.",
                references=["https://owasp.org/www-community/attacks/xss/"],
            ))

    elapsed = time.time() - start
    for f in findings:
        f.evidence += f" (module took {elapsed:.2f}s)"

    return findings
