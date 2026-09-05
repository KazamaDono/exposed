from __future__ import annotations

import os
import stat
from pathlib import Path

from exposed.models import CheckResult, Finding, Severity

SENSITIVE_FILES = [
    (".gnupg", 0o700, "GPG keyring directory"),
    (".aws/credentials", 0o600, "AWS credentials"),
    (".aws/config", 0o600, "AWS config"),
    (".kube/config", 0o600, "Kubernetes config"),
    (".docker/config.json", 0o600, "Docker config (may contain registry tokens)"),
    (".netrc", 0o600, "Netrc credentials file"),
    (".npmrc", 0o600, "npm config (may contain auth tokens)"),
    (".pypirc", 0o600, "PyPI credentials"),
    (".gem/credentials", 0o600, "RubyGems credentials"),
    (".config/gh/hosts.yml", 0o600, "GitHub CLI credentials"),
    (".config/gcloud/credentials.db", 0o600, "Google Cloud credentials"),
]

PRIVATE_KEY_EXTENSIONS = {".pem", ".key", ".p12", ".pfx", ".jks"}


def check_permissions() -> CheckResult:
    result = CheckResult(name="File Permissions", icon=">")
    home = Path.home()
    found_issues = False

    for rel_path, expected_mode, label in SENSITIVE_FILES:
        fp = home / rel_path
        if not fp.exists():
            continue
        actual = fp.stat().st_mode
        if fp.is_dir():
            mask = 0o777
        else:
            mask = 0o777

        actual_perms = actual & mask
        if actual_perms & ~expected_mode:
            found_issues = True
            result.findings.append(Finding(
                Severity.WARNING,
                f"~/{rel_path} has loose permissions ({oct(actual_perms)} → should be {oct(expected_mode)})",
                detail=label,
                remediation=f"chmod {oct(expected_mode)[2:]} {fp}",
            ))
        else:
            result.findings.append(Finding(Severity.PASS, f"~/{rel_path} permissions OK"))

    _check_stray_keys(result, home)

    if not found_issues and not any(f.severity != Severity.PASS for f in result.findings):
        if not result.findings:
            result.findings.append(Finding(Severity.PASS, "No sensitive files with loose permissions"))

    return result


def _check_stray_keys(result: CheckResult, home: Path) -> None:
    stray = []
    scan_dirs = [home, home / "Desktop", home / "Downloads", home / "Documents"]
    for d in scan_dirs:
        if not d.is_dir():
            continue
        try:
            for entry in d.iterdir():
                if entry.is_file() and entry.suffix in PRIVATE_KEY_EXTENSIONS:
                    stray.append(entry)
        except PermissionError:
            continue

    if stray:
        names = ", ".join(f"~/{s.relative_to(home)}" for s in stray[:5])
        extra = f" (+{len(stray) - 5} more)" if len(stray) > 5 else ""
        result.findings.append(Finding(
            Severity.WARNING,
            f"Private key file(s) found in exposed location: {names}{extra}",
            remediation="Move private keys to ~/.ssh/ or a vault and set permissions to 600.",
        ))
