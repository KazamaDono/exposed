from __future__ import annotations

import re
from pathlib import Path

from exposed.models import CheckResult, Finding, Severity

DOTFILES = [".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile"]

ENV_GLOBS = [".env", ".env.*"]

SECRET_RE = [
    (re.compile(r'export\s+\w*(SECRET|TOKEN|PASSWORD|API_?KEY|PRIVATE|CREDENTIAL)\w*\s*=\s*["\']?[^\s"\']{8,}', re.I), "exported secret"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS access key"),
    (re.compile(r'(?:sk|rk)[-_](?:live|test)[-_][A-Za-z0-9]{24,}'), "Stripe/OpenAI key"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "GitHub PAT"),
    (re.compile(r'gho_[A-Za-z0-9]{36}'), "GitHub OAuth token"),
    (re.compile(r'xox[bpras]-[A-Za-z0-9\-]{24,}'), "Slack token"),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'), "embedded private key"),
    (re.compile(r'mongodb(?:\+srv)?://[^\s]+:[^\s]+@'), "MongoDB connection string with password"),
    (re.compile(r'postgres(?:ql)?://[^\s]+:[^\s]+@'), "Postgres connection string with password"),
    (re.compile(r'mysql://[^\s]+:[^\s]+@'), "MySQL connection string with password"),
    (re.compile(r'redis://:[^\s]+@'), "Redis connection string with password"),
]


def check_secrets() -> CheckResult:
    result = CheckResult(name="Secrets in Dotfiles", icon=">")
    home = Path.home()

    found = 0
    for name in DOTFILES:
        fp = home / name
        if fp.is_file():
            found += _scan_file(result, fp, f"~/{name}")

    for pattern in ENV_GLOBS:
        for fp in home.glob(pattern):
            if fp.is_file():
                found += _scan_file(result, fp, f"~/{fp.name}")

    _scan_env_dirs(result, home)

    if found == 0:
        result.findings.append(Finding(Severity.PASS, "No secrets found in dotfiles"))

    return result


def _scan_file(result: CheckResult, path: Path, display: str) -> int:
    try:
        content = path.read_text(errors="replace")
    except PermissionError:
        return 0

    hits = 0
    seen_labels: set[str] = set()
    for pat, label in SECRET_RE:
        if label not in seen_labels and pat.search(content):
            seen_labels.add(label)
            hits += 1
            result.findings.append(Finding(
                Severity.CRITICAL,
                f"{display} contains {label}",
                detail="Secrets in shell profiles persist in plaintext and survive reboots.",
                remediation=f"Move the secret to a credential manager or a properly-protected .env file, then remove it from {display}.",
            ))
    return hits


def _scan_env_dirs(result: CheckResult, home: Path) -> None:
    common_dirs = ["projects", "code", "dev", "src", "repos", "workspace", "work", "Documents", "Desktop"]
    env_count = 0
    checked = set()

    for d in common_dirs:
        base = home / d
        if not base.is_dir():
            continue
        try:
            for fp in base.rglob(".env"):
                if fp in checked:
                    continue
                checked.add(fp)
                if fp.is_file() and fp.stat().st_size > 0:
                    env_count += 1
                if env_count >= 20:
                    break
        except PermissionError:
            continue
        if env_count >= 20:
            break

    if env_count > 0:
        result.findings.append(Finding(
            Severity.WARNING,
            f"{env_count} .env file(s) found in project directories",
            detail="Ensure these are gitignored and contain only development credentials.",
            remediation="Add .env to your global gitignore.",
        ))
