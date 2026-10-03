import argparse

from luna.core.scanner import Scanner
from luna.reporting.console import print_banner, print_console_report
from luna.reporting.json_report import generate_json_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="luna",
        description="Luna, API Security Scanner",
    )
    parser.add_argument("url", type=str, help="Target URL to scan")
    parser.add_argument("--modules", type=str, default=None, help="Comma-separated list of modules: headers,xss,sqli,idor,auth")
    parser.add_argument("--output", type=str, choices=["console", "json"], default="console", help="Output format")
    parser.add_argument("--output-file", type=str, default=None, help="Write JSON report to this file")
    parser.add_argument("--param", type=str, default=None, help="URL parameter name for IDOR testing")
    parser.add_argument("--valid-value", type=str, default=None, help="Valid parameter value for IDOR testing")
    parser.add_argument("--invalid-value", type=str, default=None, help="Invalid parameter value for IDOR testing")
    parser.add_argument("--token", type=str, default=None, help="Bearer token for authentication testing")
    parser.add_argument("--sql-payloads", type=str, nargs="+", default=None, help="Custom SQL injection payloads")
    parser.add_argument("--xss-payloads", type=str, nargs="+", default=None, help="Custom XSS payloads")
    parser.add_argument("--parallel", type=str, nargs="+", default=None, help="Additional URLs to scan in parallel")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.output == "console":
        print_banner()

    modules = args.modules.split(",") if args.modules else None

    urls = [args.url]
    if args.parallel:
        urls.extend(args.parallel)

    scanners = [
        Scanner(
            url=url,
            modules=modules,
            param=args.param,
            valid_value=args.valid_value,
            invalid_value=args.invalid_value,
            token=args.token,
            sql_payloads=args.sql_payloads,
            xss_payloads=args.xss_payloads,
        )
        for url in urls
    ]

    if len(scanners) == 1:
        scanner = scanners[0]
        findings = scanner.run()
        _output(findings, args.url, args.output, args.output_file, scanner)
    else:
        results = Scanner.run_parallel(scanners)
        for url, findings in results.items():
            _output(findings, url, args.output, args.output_file)


def _output(findings: list, url: str, output_format: str, output_file: str = None, scanner: "Scanner" = None) -> None:
    if output_format == "json" or output_file:
        start_time = getattr(scanner, "start_time", None)
        end_time = getattr(scanner, "end_time", None)
        modules_used = getattr(scanner, "modules", None)
        report = generate_json_report(findings, url, start_time, end_time, modules_used)
        if output_file:
            with open(output_file, "w") as f:
                f.write(report)
        if output_format == "json":
            print(report)
    else:
        print_console_report(findings, url)
