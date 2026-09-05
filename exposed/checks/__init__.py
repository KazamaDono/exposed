from exposed.checks.ssh import check_ssh
from exposed.checks.git import check_git
from exposed.checks.secrets import check_secrets
from exposed.checks.history import check_history
from exposed.checks.permissions import check_permissions
from exposed.checks.network import check_network
from exposed.checks.docker import check_docker

ALL_CHECKS = [
    check_ssh,
    check_git,
    check_secrets,
    check_history,
    check_permissions,
    check_network,
    check_docker,
]
