import sys
import time
import threading
from typing import Optional

from luna.core.findings import Finding
from luna.modules.headers import check_https_security
from luna.modules.xss import check_xss
from luna.modules.sqli import check_sql_injection
from luna.modules.idor import check_idor
from luna.modules.auth import check_weak_authentication

ALL_MODULES = {
    "headers": check_https_security,
    "xss": check_xss,
    "sqli": check_sql_injection,
    "idor": check_idor,
    "auth": check_weak_authentication,
}


class Scanner:
    def __init__(
        self,
        url: str,
        modules: Optional[list] = None,
        param: Optional[str] = None,
        valid_value: Optional[str] = None,
        invalid_value: Optional[str] = None,
        token: Optional[str] = None,
        sql_payloads: Optional[list] = None,
        xss_payloads: Optional[list] = None,
    ):
        self.url = url
        self.modules = modules or list(ALL_MODULES.keys())
        self.param = param
        self.valid_value = valid_value
        self.invalid_value = invalid_value
        self.token = token
        self.sql_payloads = sql_payloads
        self.xss_payloads = xss_payloads

    def run(self) -> list:
        findings: list[Finding] = []
        self.start_time = time.time()

        for module_name in self.modules:
            if module_name not in ALL_MODULES:
                continue
            module_findings = self._run_module(module_name)
            findings.extend(module_findings)

        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        return findings

    def _run_module(self, module_name: str) -> list:
        try:
            if module_name == "headers":
                return check_https_security(self.url)
            elif module_name == "xss":
                return check_xss(self.url, self.xss_payloads)
            elif module_name == "sqli":
                return check_sql_injection(self.url, self.sql_payloads)
            elif module_name == "idor":
                if self.param and self.valid_value and self.invalid_value:
                    return check_idor(self.url, self.param, self.valid_value, self.invalid_value)
                return []
            elif module_name == "auth":
                if self.token:
                    return check_weak_authentication(self.url, self.token)
                return []
        except Exception as exc:
            print(f"[luna] error in module '{module_name}': {exc}", file=sys.stderr)
            return []
        return []

    @staticmethod
    def run_parallel(scanners: list) -> dict:
        results: dict = {}
        lock = threading.Lock()

        def _scan(scanner: "Scanner") -> None:
            findings = scanner.run()
            with lock:
                results[scanner.url] = findings

        threads = [threading.Thread(target=_scan, args=(s,)) for s in scanners]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        return results
