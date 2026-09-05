from __future__ import annotations

import re
from pathlib import Path

from exposed.models import CheckResult, Finding, Severity

HISTORY_FILES = [".bash_history", ".zsh_history", ".python_history"]

CREDENTIAL_CMD_RE = [
    (re.compile(r'curl\s.*(-u\s+\S+:\S+|--user\s+\S+:\S+)', re.I), "curl with inline credentials"),
    (re.compile(r'curl\s.*-H\s+["\']?Authorization:\s*(Bearer|Basic)\s+\S+', re.I), "curl with auth header"),
    (re.compile(r'mysql\s.*-p\S+'), "mysql with inline password"),
    (re.compile(r'psql\s.*://\S+:\S+@'), "psql with password in connection string"),
    (re.compile(r'docker\s+login\s.*-p\s+\S+', re.I), "docker login with inline password"),
    (re.compile(r'(?:export\s+)?(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*=\s*\S{10,}', re.I), "secret exported in shell"),
    (re.compile(r'htpasswd\s.*-b\s+\S+\s+\S+\s+\S+'), "htpasswd with inline password"),
    (re.compile(r'sshpass\s+-p\s+'), "sshpass with inline password"),
    (re.compile(r'heroku\s+config:set\s+\S*(?:SECRET|TOKEN|KEY|PASSWORD)\S*=\S+', re.I), "heroku config with secret"),
]


def check_history() -> CheckResult:
    result = CheckResult(name="Shell History", icon="📜")
    home = Path.home()
    total_hits = 0

    for name in HISTORY_FILES:
        fp = home / name
        if not fp.is_file():
            continue

        try:
            tail_lines = _tail(fp, 5000)
        except PermissionError:
            continue

        seen: set[str] = set()
        hits = 0
        for line in tail_lines:
            for pat, label in CREDENTIAL_CMD_RE:
                if label not in seen and pat.search(line):
                    seen.add(label)
                    hits += 1

        if hits:
            total_hits += hits
            result.findings.append(Finding(
                Severity.WARNING,
                f"~/{name} contains {hits} command(s) with inline credentials",
                detail="Credentials in shell history persist across reboots and may be readable by other local users.",
                remediation=f"Remove sensitive lines: edit ~/{name} or run 'history -c' (bash) / clear with 'fc -W' (zsh).",
            ))

    if total_hits == 0:
        result.findings.append(Finding(Severity.PASS, "No credentials found in recent shell history"))

    _check_histfile_perms(result, home)
    return result


def _tail(path: Path, n: int) -> list[str]:
    try:
        lines = path.read_text(errors="replace").splitlines()
        return lines[-n:]
    except (PermissionError, OSError):
        return []


def _check_histfile_perms(result: CheckResult, home: Path) -> None:
    for name in HISTORY_FILES:
        fp = home / name
        if not fp.is_file():
            continue
        mode = fp.stat().st_mode & 0o777
        if mode & 0o077:
            result.findings.append(Finding(
                Severity.WARNING,
                f"~/{name} is readable by others ({oct(mode)})",
                remediation=f"chmod 600 {fp}",
            ))
