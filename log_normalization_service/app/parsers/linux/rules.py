from typing import Dict, Any, List, Tuple

# (regex_pattern, normalized_fields)
# Patterns are checked top-to-bottom; first match wins.
LINUX_PATTERNS: List[Tuple[str, Dict[str, Any]]] = [
    # ── SSH ─────────────────────────────────────────────────────────────────
    (r"sshd.*Failed password",
     {"category": "authentication", "action": "login", "result": "failure", "severity": "medium"}),

    (r"sshd.*Accepted (?:password|publickey)",
     {"category": "authentication", "action": "login", "result": "success", "severity": "low"}),

    (r"sshd.*Disconnected from.*user",
     {"category": "authentication", "action": "logout", "result": "success", "severity": "low"}),

    (r"sshd.*error: maximum authentication attempts exceeded",
     {"category": "authentication", "action": "login", "result": "failure", "severity": "high"}),

    (r"sshd.*Invalid user",
     {"category": "authentication", "action": "login", "result": "failure", "severity": "medium"}),

    # ── PAM ──────────────────────────────────────────────────────────────────
    (r"pam_unix.*authentication failure",
     {"category": "authentication", "action": "login", "result": "failure", "severity": "medium"}),

    (r"pam_unix.*session opened",
     {"category": "authentication", "action": "login", "result": "success", "severity": "low"}),

    (r"pam_unix.*session closed",
     {"category": "authentication", "action": "logout", "result": "success", "severity": "low"}),

    # ── sudo ─────────────────────────────────────────────────────────────────
    (r"\bsudo\b.*COMMAND=",
     {"category": "privilege", "action": "sudo", "result": "success", "severity": "medium"}),

    (r"\bsudo\b.*authentication failure",
     {"category": "privilege", "action": "sudo", "result": "failure", "severity": "high"}),

    (r"\bsudo\b.*user NOT in sudoers",
     {"category": "privilege", "action": "sudo", "result": "failure", "severity": "high"}),

    # ── Account management ────────────────────────────────────────────────────
    (r"useradd.*new (?:user|account)",
     {"category": "account_management", "action": "create", "result": "success", "severity": "medium"}),

    (r"userdel.*deleting user",
     {"category": "account_management", "action": "delete", "result": "success", "severity": "high"}),

    (r"\busermod\b",
     {"category": "account_management", "action": "modify", "result": "success", "severity": "medium"}),

    (r"passwd.*password changed for",
     {"category": "account_management", "action": "password_change", "result": "success", "severity": "medium"}),

    # ── systemd service ───────────────────────────────────────────────────────
    (r"systemd.*Started .+\.service",
     {"category": "service", "action": "start", "result": "success", "severity": "low"}),

    (r"systemd.*Stopped .+\.service",
     {"category": "service", "action": "stop", "result": "success", "severity": "low"}),

    (r"systemd.*Failed to start .+\.service",
     {"category": "service", "action": "start", "result": "failure", "severity": "high"}),

    # ── auditd record types ───────────────────────────────────────────────────
    (r"type=USER_AUTH.*res=failed",
     {"category": "authentication", "action": "login", "result": "failure", "severity": "medium"}),

    (r"type=USER_AUTH.*res=success",
     {"category": "authentication", "action": "login", "result": "success", "severity": "low"}),

    (r"type=USER_LOGIN.*res=failed",
     {"category": "authentication", "action": "login", "result": "failure", "severity": "medium"}),

    (r"type=USER_LOGIN.*res=success",
     {"category": "authentication", "action": "login", "result": "success", "severity": "low"}),

    (r"type=USER_CMD",
     {"category": "privilege", "action": "command", "result": "success", "severity": "medium"}),

    (r"type=ADD_USER",
     {"category": "account_management", "action": "create", "result": "success", "severity": "medium"}),

    (r"type=DEL_USER",
     {"category": "account_management", "action": "delete", "result": "success", "severity": "high"}),

    (r"type=SYSCALL|type=EXECVE",
     {"category": "process", "action": "start", "result": "success", "severity": "low"}),

    (r"type=PATH",
     {"category": "file", "action": "access", "result": "success", "severity": "low"}),
]

# auditd record type → category mapping
AUDITD_TYPE_RULES: Dict[str, Dict[str, Any]] = {
    "USER_AUTH":   {"category": "authentication",    "action": "login"},
    "USER_LOGIN":  {"category": "authentication",    "action": "login"},
    "USER_LOGOUT": {"category": "authentication",    "action": "logout"},
    "USER_CMD":    {"category": "privilege",          "action": "command"},
    "SYSCALL":     {"category": "process",            "action": "syscall"},
    "EXECVE":      {"category": "process",            "action": "start"},
    "PATH":        {"category": "file",               "action": "access"},
    "SOCKADDR":    {"category": "network",            "action": "connect"},
    "USER_MGMT":   {"category": "account_management", "action": "modify"},
    "ADD_USER":    {"category": "account_management", "action": "create"},
    "DEL_USER":    {"category": "account_management", "action": "delete"},
    "ADD_GROUP":   {"category": "account_management", "action": "group_create"},
    "DEL_GROUP":   {"category": "account_management", "action": "group_delete"},
}

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
