from __future__ import annotations

import re
import subprocess
from pathlib import Path

from exposed.models import CheckResult, Finding, Severity

SECRET_PATTERNS = [
    (re.compile(r'(?:password|passwd|secret|token|api.?key)\s*[=:]\s*["\']?.{8,}', re.I), "credential assignment"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "GitHub personal access token"),
    (re.compile(r'gho_[A-Za-z0-9]{36}'), "GitHub OAuth token"),
    (re.compile(r'sk-[A-Za-z0-9]{40,}'), "OpenAI/Stripe secret key"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS access key ID"),
]


def check_git() -> CheckResult:
    result = CheckResult(name="Git Configuration", icon=">")

    _check_signing(result)
    _check_credential_helper(result)
    _check_global_config_secrets(result)
    _check_global_ignore(result)

    return result


def _git_config(key: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "config", "--global", key],
            capture_output=True, text=True, timeout=5,
        )
        return proc.stdout.strip() if proc.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _check_signing(result: CheckResult) -> None:
    gpg_key = _git_config("user.signingkey")
    sign_commits = _git_config("commit.gpgsign")

    if gpg_key and sign_commits and sign_commits.lower() == "true":
        result.findings.append(Finding(Severity.PASS, "Commit signing is enabled"))
    elif gpg_key:
        result.findings.append(Finding(
            Severity.INFO,
            "Signing key configured but commit.gpgsign is not enabled",
            remediation="git config --global commit.gpgsign true",
        ))
    else:
        result.findings.append(Finding(
            Severity.WARNING,
            "Commit signing not configured",
            detail="Unsigned commits can be trivially spoofed by anyone who knows your email.",
            remediation="git config --global commit.gpgsign true  # after setting up GPG or SSH signing",
        ))


def _check_credential_helper(result: CheckResult) -> None:
    helper = _git_config("credential.helper")
    if not helper:
        result.findings.append(Finding(Severity.INFO, "No credential helper configured"))
    elif helper == "store":
        result.findings.append(Finding(
            Severity.CRITICAL,
            "Credential helper 'store' saves passwords in plaintext",
            detail=f"Credentials are stored unencrypted in {Path.home() / '.git-credentials'}",
            remediation="Switch to a keyring-based helper: git config --global credential.helper cache  # or libsecret/osxkeychain",
        ))
        _check_plaintext_creds(result)
    elif "cache" in helper:
        result.findings.append(Finding(Severity.PASS, "Credential helper uses in-memory cache"))
    else:
        result.findings.append(Finding(Severity.PASS, f"Credential helper: {helper}"))


def _check_plaintext_creds(result: CheckResult) -> None:
    cred_file = Path.home() / ".git-credentials"
    if cred_file.is_file():
        try:
            lines = [l for l in cred_file.read_text().splitlines() if l.strip()]
            if lines:
                result.findings.append(Finding(
                    Severity.CRITICAL,
                    f"~/.git-credentials contains {len(lines)} plaintext credential(s)",
                    remediation="rm ~/.git-credentials && git config --global credential.helper cache",
                ))
        except PermissionError:
            pass


def _check_global_config_secrets(result: CheckResult) -> None:
    gitconfig = Path.home() / ".gitconfig"
    if not gitconfig.is_file():
        return
    try:
        content = gitconfig.read_text(errors="replace")
        for pat, label in SECRET_PATTERNS:
            if pat.search(content):
                result.findings.append(Finding(
                    Severity.CRITICAL,
                    f"Possible {label} found in ~/.gitconfig",
                    remediation="Remove the secret from ~/.gitconfig and use environment variables instead.",
                ))
                return
    except PermissionError:
        pass


def _check_global_ignore(result: CheckResult) -> None:
    ignore = _git_config("core.excludesfile")
    if not ignore:
        result.findings.append(Finding(
            Severity.INFO,
            "No global gitignore configured",
            detail="A global gitignore prevents accidentally committing .env, *.pem, id_rsa, etc.",
            remediation="echo '.env\\n*.pem\\nid_rsa' > ~/.gitignore_global && git config --global core.excludesfile ~/.gitignore_global",
        ))
    else:
        result.findings.append(Finding(Severity.PASS, f"Global gitignore configured ({ignore})"))
