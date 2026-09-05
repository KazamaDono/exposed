from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from exposed.models import CheckResult, Finding, Severity


def check_ssh() -> CheckResult:
    result = CheckResult(name="SSH Keys", icon="🔑")
    ssh_dir = Path.home() / ".ssh"

    if not ssh_dir.is_dir():
        result.findings.append(Finding(Severity.INFO, "No ~/.ssh directory found"))
        return result

    _check_dir_perms(result, ssh_dir)

    key_files = []
    for f in ssh_dir.iterdir():
        if f.is_file() and not f.name.startswith("known_hosts") and not f.name.endswith(".pub") and f.name != "config" and f.name != "authorized_keys":
            if _looks_like_private_key(f):
                key_files.append(f)

    if not key_files:
        result.findings.append(Finding(Severity.INFO, "No private keys found in ~/.ssh"))
        return result

    for kf in key_files:
        _audit_key(result, kf)

    _check_config(result, ssh_dir / "config")
    return result


def _check_dir_perms(result: CheckResult, ssh_dir: Path) -> None:
    mode = ssh_dir.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        result.findings.append(Finding(
            Severity.CRITICAL,
            f"~/.ssh has overly permissive permissions ({oct(mode & 0o777)})",
            remediation="chmod 700 ~/.ssh",
        ))
    else:
        result.findings.append(Finding(Severity.PASS, "~/.ssh directory permissions OK (700)"))


def _looks_like_private_key(path: Path) -> bool:
    try:
        head = path.read_bytes()[:64]
        return b"PRIVATE KEY" in head or b"OPENSSH PRIVATE" in head
    except (PermissionError, OSError):
        return False


def _audit_key(result: CheckResult, key_path: Path) -> None:
    name = f"~/.ssh/{key_path.name}"

    mode = key_path.stat().st_mode & 0o777
    if mode != 0o600 and mode != 0o400:
        result.findings.append(Finding(
            Severity.CRITICAL,
            f"{name} has wrong permissions ({oct(mode)})",
            remediation=f"chmod 600 {key_path}",
        ))

    try:
        info = subprocess.run(
            ["ssh-keygen", "-l", "-f", str(key_path)],
            capture_output=True, text=True, timeout=5,
        )
        if info.returncode == 0:
            line = info.stdout.strip()
            bits_str = line.split()[0]
            try:
                bits = int(bits_str)
            except ValueError:
                bits = 0
            algo = _extract_algo(line)

            if "DSA" in algo.upper():
                result.findings.append(Finding(
                    Severity.CRITICAL,
                    f"{name} uses DSA (deprecated and insecure)",
                    remediation="Generate a new Ed25519 key: ssh-keygen -t ed25519",
                ))
            elif "RSA" in algo.upper() and bits < 3072:
                result.findings.append(Finding(
                    Severity.WARNING,
                    f"{name} uses RSA-{bits} (consider upgrading)",
                    detail="RSA keys should be at least 3072 bits; Ed25519 is preferred.",
                    remediation="ssh-keygen -t ed25519",
                ))
            elif "ED25519" in algo.upper():
                result.findings.append(Finding(Severity.PASS, f"{name} uses Ed25519"))
            elif "ECDSA" in algo.upper():
                result.findings.append(Finding(Severity.PASS, f"{name} uses ECDSA-{bits}"))
            else:
                result.findings.append(Finding(Severity.INFO, f"{name} uses {algo} ({bits} bits)"))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    _check_passphrase(result, key_path, name)


def _extract_algo(keygen_line: str) -> str:
    parts = keygen_line.strip().split()
    if parts:
        last = parts[-1].strip("()")
        if last in ("RSA", "DSA", "ECDSA", "ED25519"):
            return last
    for p in parts:
        p = p.strip("()")
        if p.upper() in ("RSA", "DSA", "ECDSA", "ED25519"):
            return p
    return "unknown"


def _check_passphrase(result: CheckResult, key_path: Path, name: str) -> None:
    try:
        proc = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", str(key_path)],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0:
            result.findings.append(Finding(
                Severity.WARNING,
                f"{name} has no passphrase",
                detail="Anyone who copies this file gets full access to every server that trusts it.",
                remediation=f"ssh-keygen -p -f {key_path}",
            ))
        else:
            result.findings.append(Finding(Severity.PASS, f"{name} is passphrase-protected"))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


def _check_config(result: CheckResult, config_path: Path) -> None:
    if not config_path.is_file():
        return
    mode = config_path.stat().st_mode & 0o777
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        result.findings.append(Finding(
            Severity.WARNING,
            f"~/.ssh/config is world/group-readable ({oct(mode)})",
            remediation="chmod 600 ~/.ssh/config",
        ))
