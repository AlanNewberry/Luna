from luna.core.findings import Finding

SEVERITY_COLORS = {
    "Critical": "\033[91m",
    "High": "\033[31m",
    "Medium": "\033[33m",
    "Low": "\033[36m",
    "Info": "\033[37m",
}
RESET = "\033[0m"


def print_banner() -> None:
    logo = r"""
__/\\\_____________________________________________________________________________________/\\\\\\\\\\__
 _\/\\\____________________________________________________________________________/\\\___/\\\///////\\\_
  _\/\\\_________________________________________________________________________/\\\//___\///______/\\\__
   _\/\\\______________/\\\____/\\\__/\\/\\\\\\____/\\\\\\\\\__________________/\\\//_____________/\\\//___
    _\/\\\_____________\/\\\___\/\\\_\/\\\////\\\__\////////\\\______________/\\\//_______________\////\\\__
     _\/\\\_____________\/\\\___\/\\\_\/\\\__\//\\\___/\\\\\\\\\\____________\////\\\_________________\//\\\_
      _\/\\\_____________\/\\\___\/\\\_\/\\\___\/\\\__/\\\/////\\\_______________\////\\\_____/\\\______/\\\__
       _\/\\\\\\\\\\\\\\\_\//\\\\\\\\\__\/\\\___\/\\\_\//\\\\\\\\/\\_________________\////\\\_\///\\\\\\\\\/___
        _\///////////////___\/////////___\///____\///___\////////\//_____________________\///____\/////////_____
                  Luna API Security Scanner
    """
    print(logo)


def print_console_report(findings: list[Finding], url: str) -> None:
    print(f"\nScan results for: {url}")
    print(f"Total findings: {len(findings)}\n")

    if not findings:
        print("No findings detected.")
        return

    for finding in findings:
        color = SEVERITY_COLORS.get(finding.severity, RESET)
        print(f"  [{color}{finding.severity}{RESET}] {finding.id}: {finding.title}")
        print(f"    {finding.description}")
        print(f"    Evidence: {finding.evidence}")
        print(f"    Resource: {finding.affected_resource}")
        print(f"    Remediation: {finding.remediation}")
        if finding.references:
            print(f"    References: {', '.join(finding.references)}")
        print()
