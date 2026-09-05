from __future__ import annotations

import argparse
import sys
import json
from pathlib import Path

from exposed import __version__
from exposed.checks import ALL_CHECKS
from exposed.models import CheckResult, Severity
from exposed.output import console, print_banner, print_scanning, print_result, print_score


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="exposed",
        description="Audit your development environment for security misconfigurations and leaked secrets.",
    )
    parser.add_argument("-v", "--version", action="version", version=f"exposed {__version__}")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only show critical and warning findings")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Output results as JSON")
    parser.add_argument("--no-banner", action="store_true", help="Skip the banner")
    parser.add_argument(
        "--checks",
        type=str,
        default=None,
        help="Comma-separated list of checks to run (ssh,git,secrets,history,permissions,network,docker)",
    )
    args = parser.parse_args()

    check_map = {fn.__name__.replace("check_", ""): fn for fn in ALL_CHECKS}

    if args.checks:
        selected = [c.strip().lower() for c in args.checks.split(",")]
        checks_to_run = []
        for name in selected:
            if name not in check_map:
                console.print(f"[red]Unknown check: {name}[/red]")
                console.print(f"Available: {', '.join(sorted(check_map.keys()))}")
                sys.exit(1)
            checks_to_run.append(check_map[name])
    else:
        checks_to_run = ALL_CHECKS

    if args.json_output:
        _run_json(checks_to_run)
    else:
        _run_interactive(checks_to_run, quiet=args.quiet, banner=not args.no_banner)


def _run_interactive(checks: list, quiet: bool, banner: bool) -> None:
    if banner:
        print_banner()
    print_scanning()

    results: list[CheckResult] = []
    for check_fn in checks:
        result = check_fn()
        results.append(result)

        if quiet:
            result.findings = [
                f for f in result.findings
                if f.severity in (Severity.CRITICAL, Severity.WARNING)
            ]
            if not result.findings:
                continue

        print_result(result)

    print_score(results)

    crits = sum(1 for cr in results for f in cr.findings if f.severity == Severity.CRITICAL)
    sys.exit(1 if crits > 0 else 0)


def _run_json(checks: list) -> None:
    results = []
    for check_fn in checks:
        cr = check_fn()
        results.append({
            "check": cr.name,
            "findings": [
                {
                    "severity": f.severity.value,
                    "title": f.title,
                    "detail": f.detail,
                    "remediation": f.remediation,
                }
                for f in cr.findings
            ],
        })
    print(json.dumps({"version": __version__, "results": results}, indent=2))


if __name__ == "__main__":
    main()
