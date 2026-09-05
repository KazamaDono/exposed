# exposed

**Find what you forgot to hide.**

A fast, zero-config CLI tool that audits your development environment for security misconfigurations and accidentally exposed secrets.

```
$ exposed
```

```
 ██████╗██╗  ██╗██████╗  █████╗ ███████╗███████╗██████╗
██╔════╝╚██╗██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗
█████╗   ╚███╔╝ ██████╔╝██║  ██║███████╗█████╗  ██║  ██║
██╔══╝   ██╔██╗ ██╔═══╝ ██║  ██║╚════██║██╔══╝  ██║  ██║
███████╗██╔╝╚██╗██║     ╚█████╔╝███████║███████╗██████╔╝
╚══════╝╚═╝  ╚═╝╚═╝      ╚════╝ ╚══════╝╚══════╝╚═════╝
  Find what you forgot to hide.

Scanning your development environment...

╭──── 🔑  SSH Keys ────────────────────────────────────────╮
│  ✓ ~/.ssh directory permissions OK (700)                 │
│  ✓ ~/.ssh/id_ed25519 uses Ed25519                        │
│  ⚠ ~/.ssh/id_ed25519 has no passphrase                   │
│      fix: ssh-keygen -p -f ~/.ssh/id_ed25519             │
╰──────────────────────────────────────────────────────────╯

╭──── 📦  Git Configuration ──────────────────────────────╮
│  ⚠ Commit signing not configured                         │
│  ✗ Credential helper 'store' saves passwords in          │
│    plaintext                                             │
│      fix: git config --global credential.helper cache    │
╰──────────────────────────────────────────────────────────╯

╭──── 🌐  Network Exposure ───────────────────────────────╮
│  ⚠ PostgreSQL (tcp:5432) listening on 0.0.0.0            │
│      fix: Bind to 127.0.0.1 instead of 0.0.0.0          │
│  ✓ 2 service(s) correctly bound to localhost only        │
╰──────────────────────────────────────────────────────────╯

╭───────────── Security Score ─────────────────╮
│  Score     6.5/10                            │
│  Rating    Fair                              │
│                                              │
│  ✗ Critical   2                              │
│  ⚠ Warnings   4                              │
│  ✓ Passed     8                              │
╰──────────────────────────────────────────────╯
```

## What it checks

| Check | What it looks for |
|-------|-------------------|
| **SSH Keys** | Weak algorithms (DSA, short RSA), missing passphrases, wrong file permissions |
| **Git Config** | Plaintext credential storage, unsigned commits, missing global gitignore, secrets in gitconfig |
| **Secrets in Dotfiles** | API keys, tokens, passwords, and connection strings in .bashrc, .zshrc, .profile, .env files |
| **Shell History** | Credentials passed inline to curl, mysql, docker, psql, and other commands |
| **File Permissions** | Overly permissive sensitive files (.aws/credentials, .kube/config, .npmrc, etc.) |
| **Network Exposure** | Dev services (databases, caches, Docker) listening on 0.0.0.0 instead of localhost |
| **Docker** | World-accessible socket, containers running as root |

## Install

```bash
pip install exposed-cli
```

Or run directly from the repo:

```bash
git clone https://github.com/aiida-com/exposed.git
cd exposed
pip install .
exposed
```

## Usage

```bash
# Full scan
exposed

# Only critical/warning findings
exposed -q

# JSON output (for CI/CD pipelines)
exposed --json

# Run specific checks only
exposed --checks ssh,git,network

# No banner
exposed --no-banner
```

### CI/CD Integration

`exposed` exits with code 1 if any critical findings are detected, making it easy to use in CI pipelines:

```yaml
# GitHub Actions
- name: Security audit
  run: |
    pip install exposed-cli
    exposed --json > audit.json
    exposed -q
```

### JSON Output

```bash
exposed --json | jq '.results[] | select(.findings[] | .severity == "critical")'
```

## Available Checks

Run only the checks you need:

```bash
exposed --checks ssh           # SSH keys only
exposed --checks git,secrets   # Git config + dotfile secrets
exposed --checks network       # Network exposure only
```

Available check names: `ssh`, `git`, `secrets`, `history`, `permissions`, `network`, `docker`

## Why exposed?

Most secret scanners focus on your **git history**. `exposed` focuses on your **actual machine** — the SSH keys, shell history, dotfiles, running services, and file permissions that attackers target after initial access.

It's the security audit you should run on every dev machine, CI runner, and cloud instance.

## Requirements

- Python 3.9+
- Linux or macOS
- Optional: Docker CLI (for container checks)

## License

MIT
