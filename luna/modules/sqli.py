import time
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from luna.core.findings import Finding

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "ora-01756",
    "pg_query",
    "sqlite3.operationalerror",
    "unterminated string",
    "syntax error at or near",
]

DEFAULT_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "1; SELECT 1--",
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


def check_sql_injection(
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

        body_lower = response.text.lower()
        matched_error = None
        for sig in SQL_ERRORS:
            if sig in body_lower:
                matched_error = sig
                break

        if matched_error or response.status_code == 500:
            evidence = f"Payload: {payload}, Status: {response.status_code}"
            if matched_error:
                evidence += f", DB error: {matched_error}"
            findings.append(Finding(
                id="SQLI-001",
                title="Possible SQL injection",
                severity="Critical",
                description="The server returned a database error signature when given a SQL injection payload.",
                evidence=evidence,
                affected_resource=url,
                remediation="Use parameterized queries and validate all user input.",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            ))

    elapsed = time.time() - start
    for f in findings:
        f.evidence += f" (module took {elapsed:.2f}s)"

    return findings
