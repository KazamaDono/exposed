from __future__ import annotations

import json
import os
import subprocess

from exposed.models import CheckResult, Finding, Severity


def check_docker() -> CheckResult:
    result = CheckResult(name="Docker", icon=">")

    if not _docker_available():
        result.findings.append(Finding(Severity.INFO, "Docker not installed or not running"))
        return result

    _check_socket(result)
    _check_running_containers(result)

    return result


def _docker_available() -> bool:
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=10,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _check_socket(result: CheckResult) -> None:
    socket_path = "/var/run/docker.sock"
    if not os.path.exists(socket_path):
        return

    try:
        st = os.stat(socket_path)
        mode = st.st_mode & 0o777
        if mode & 0o006:
            result.findings.append(Finding(
                Severity.WARNING,
                f"Docker socket is world-accessible ({oct(mode)})",
                detail="Any user on this machine can run containers, effectively gaining root.",
                remediation="Add your user to the 'docker' group and tighten socket permissions.",
            ))
        else:
            result.findings.append(Finding(Severity.PASS, "Docker socket permissions are restricted"))
    except OSError:
        pass


def _check_running_containers(result: CheckResult) -> None:
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode != 0:
            return

        containers = []
        for line in proc.stdout.strip().splitlines():
            if line.strip():
                try:
                    containers.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if not containers:
            result.findings.append(Finding(Severity.PASS, "No running containers"))
            return

        root_containers = []
        for c in containers:
            name = c.get("Names", "unknown")
            inspect = _inspect_container(c.get("ID", ""))
            if inspect and _runs_as_root(inspect):
                root_containers.append(name)

        if root_containers:
            names = ", ".join(root_containers[:5])
            result.findings.append(Finding(
                Severity.WARNING,
                f"{len(root_containers)} container(s) running as root: {names}",
                detail="Containers running as root increase the blast radius of container escapes.",
                remediation="Add 'USER nonroot' to your Dockerfile or use --user in docker run.",
            ))
        else:
            result.findings.append(Finding(Severity.PASS, f"{len(containers)} container(s) running, none as root"))

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


def _inspect_container(container_id: str) -> dict | None:
    if not container_id:
        return None
    try:
        proc = subprocess.run(
            ["docker", "inspect", container_id],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            return data[0] if data else None
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return None
    return None


def _runs_as_root(inspect_data: dict) -> bool:
    config = inspect_data.get("Config", {})
    user = config.get("User", "")
    return user in ("", "0", "root")
