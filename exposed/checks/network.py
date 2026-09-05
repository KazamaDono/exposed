from __future__ import annotations

import subprocess

from exposed.models import CheckResult, Finding, Severity

RISKY_PORTS = {
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "27017": "MongoDB",
    "9200": "Elasticsearch",
    "5601": "Kibana",
    "8080": "HTTP (alt)",
    "8443": "HTTPS (alt)",
    "2375": "Docker (unencrypted)",
    "2376": "Docker (TLS)",
    "11211": "Memcached",
    "9042": "Cassandra",
    "5672": "RabbitMQ",
    "15672": "RabbitMQ Management",
    "4444": "Metasploit/Generic",
}


def check_network() -> CheckResult:
    result = CheckResult(name="Network Exposure", icon=">")

    listeners = _get_listeners()
    if listeners is None:
        result.findings.append(Finding(Severity.INFO, "Could not enumerate listening ports (ss/netstat not available)"))
        return result

    exposed = []
    local_only = []

    for proto, addr, port, process in listeners:
        port_str = str(port)
        service = RISKY_PORTS.get(port_str, "")
        label = f"{service} ({proto}:{port})" if service else f"{proto}:{port}"

        if _is_wildcard(addr):
            exposed.append((label, addr, port, process))
        else:
            if service:
                local_only.append(label)

    for label, addr, port, process in exposed:
        proc_info = f" [{process}]" if process else ""
        result.findings.append(Finding(
            Severity.WARNING,
            f"{label} listening on {addr}:{port}{proc_info} (network-accessible)",
            detail="This service accepts connections from any interface, not just localhost.",
            remediation=f"Bind to 127.0.0.1 instead of 0.0.0.0, or use a firewall rule.",
        ))

    if local_only:
        result.findings.append(Finding(
            Severity.PASS,
            f"{len(local_only)} service(s) correctly bound to localhost only",
        ))

    if not exposed and not local_only:
        result.findings.append(Finding(Severity.PASS, "No known dev services listening"))

    return result


def _get_listeners() -> list[tuple[str, str, int, str]] | None:
    try:
        proc = subprocess.run(
            ["ss", "-tlnpH"],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            return _parse_ss(proc.stdout)
    except FileNotFoundError:
        pass

    try:
        proc = subprocess.run(
            ["netstat", "-tlnp"],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            return _parse_netstat(proc.stdout)
    except FileNotFoundError:
        pass

    return None


def _parse_ss(output: str) -> list[tuple[str, str, int, str]]:
    results = []
    for line in output.strip().splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[3]
        process = parts[-1] if "users:" in parts[-1] else ""
        addr, port_s = _split_addr(local)
        try:
            port = int(port_s)
        except ValueError:
            continue
        results.append(("tcp", addr, port, _clean_process(process)))
    return results


def _parse_netstat(output: str) -> list[tuple[str, str, int, str]]:
    results = []
    for line in output.strip().splitlines():
        if not line.startswith("tcp"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        process = parts[-1] if len(parts) >= 7 else ""
        addr, port_s = _split_addr(local)
        try:
            port = int(port_s)
        except ValueError:
            continue
        results.append(("tcp", addr, port, process))
    return results


def _split_addr(local: str) -> tuple[str, str]:
    if local.startswith("["):
        idx = local.rfind("]:")
        if idx >= 0:
            return local[1:idx], local[idx + 2:]
    idx = local.rfind(":")
    if idx >= 0:
        return local[:idx], local[idx + 1:]
    return local, "0"


def _is_wildcard(addr: str) -> bool:
    return addr in ("0.0.0.0", "*", "::", "[::]", "")


def _clean_process(raw: str) -> str:
    if "users:" not in raw:
        return raw
    import re
    m = re.search(r'\("([^"]+)"', raw)
    return m.group(1) if m else raw
