from typing import Dict, Any

# Windows Event ID → normalized action fields
WINDOWS_EVENT_RULES: Dict[int, Dict[str, Any]] = {
    # ── Authentication ──────────────────────────────────────────────────────
    4624: {"category": "authentication", "action": "login",               "result": "success", "severity": "low"},
    4625: {"category": "authentication", "action": "login",               "result": "failure", "severity": "medium"},
    4634: {"category": "authentication", "action": "logout",              "result": "success", "severity": "low"},
    4647: {"category": "authentication", "action": "logout",              "result": "success", "severity": "low"},
    4648: {"category": "authentication", "action": "login",               "result": "success", "severity": "medium"},
    4771: {"category": "authentication", "action": "kerberos_preauth",    "result": "failure", "severity": "medium"},
    4776: {"category": "authentication", "action": "credential_validate", "result": "success", "severity": "low"},
    4778: {"category": "authentication", "action": "session_reconnect",   "result": "success", "severity": "low"},
    4779: {"category": "authentication", "action": "session_disconnect",  "result": "success", "severity": "low"},
    4800: {"category": "authentication", "action": "lock",                "result": "success", "severity": "low"},
    4801: {"category": "authentication", "action": "unlock",              "result": "success", "severity": "low"},

    # ── Privilege ────────────────────────────────────────────────────────────
    4672: {"category": "privilege", "action": "privilege_assigned", "result": "success", "severity": "medium"},
    4704: {"category": "privilege", "action": "privilege_assigned", "result": "success", "severity": "medium"},
    4705: {"category": "privilege", "action": "privilege_removed",  "result": "success", "severity": "medium"},

    # ── Account management ───────────────────────────────────────────────────
    4720: {"category": "account_management", "action": "create",          "result": "success", "severity": "medium"},
    4722: {"category": "account_management", "action": "enable",          "result": "success", "severity": "medium"},
    4723: {"category": "account_management", "action": "password_change", "result": "success", "severity": "medium"},
    4724: {"category": "account_management", "action": "password_reset",  "result": "success", "severity": "medium"},
    4725: {"category": "account_management", "action": "disable",         "result": "success", "severity": "medium"},
    4726: {"category": "account_management", "action": "delete",          "result": "success", "severity": "high"},
    4738: {"category": "account_management", "action": "modify",          "result": "success", "severity": "medium"},
    4740: {"category": "account_management", "action": "lockout",         "result": "success", "severity": "high"},
    4767: {"category": "account_management", "action": "unlock",          "result": "success", "severity": "medium"},
    4781: {"category": "account_management", "action": "rename",          "result": "success", "severity": "medium"},
    # Group management
    4727: {"category": "account_management", "action": "group_create",        "result": "success", "severity": "medium"},
    4728: {"category": "account_management", "action": "group_member_add",    "result": "success", "severity": "medium"},
    4729: {"category": "account_management", "action": "group_member_remove", "result": "success", "severity": "medium"},
    4730: {"category": "account_management", "action": "group_delete",        "result": "success", "severity": "high"},
    4731: {"category": "account_management", "action": "group_create",        "result": "success", "severity": "medium"},
    4732: {"category": "account_management", "action": "group_member_add",    "result": "success", "severity": "medium"},
    4733: {"category": "account_management", "action": "group_member_remove", "result": "success", "severity": "medium"},
    4734: {"category": "account_management", "action": "group_delete",        "result": "success", "severity": "high"},
    4735: {"category": "account_management", "action": "group_modify",        "result": "success", "severity": "medium"},
    4737: {"category": "account_management", "action": "group_modify",        "result": "success", "severity": "medium"},
    4756: {"category": "account_management", "action": "group_member_add",    "result": "success", "severity": "medium"},
    4757: {"category": "account_management", "action": "group_member_remove", "result": "success", "severity": "medium"},

    # ── Process ──────────────────────────────────────────────────────────────
    4688: {"category": "process", "action": "start", "result": "success", "severity": "low"},
    4689: {"category": "process", "action": "stop",  "result": "success", "severity": "low"},

    # ── Service ──────────────────────────────────────────────────────────────
    7034: {"category": "service", "action": "crash",             "result": "failure", "severity": "high"},
    7035: {"category": "service", "action": "control",           "result": "success", "severity": "low"},
    7036: {"category": "service", "action": "state_change",      "result": "success", "severity": "low"},
    7040: {"category": "service", "action": "start_type_change", "result": "success", "severity": "medium"},
    7045: {"category": "service", "action": "install",           "result": "success", "severity": "high"},

    # ── Network / Firewall ───────────────────────────────────────────────────
    5140: {"category": "network",   "action": "share_access", "result": "success", "severity": "low"},
    5156: {"category": "firewall",  "action": "allow",        "result": "success", "severity": "low"},
    5157: {"category": "firewall",  "action": "block",        "result": "failure", "severity": "medium"},

    # ── Configuration / Policy ───────────────────────────────────────────────
    4719: {"category": "configuration", "action": "policy_change",          "result": "success", "severity": "high"},
    4698: {"category": "configuration", "action": "scheduled_task_create",  "result": "success", "severity": "high"},
    4699: {"category": "configuration", "action": "scheduled_task_delete",  "result": "success", "severity": "medium"},
    4700: {"category": "configuration", "action": "scheduled_task_enable",  "result": "success", "severity": "medium"},
    4701: {"category": "configuration", "action": "scheduled_task_disable", "result": "success", "severity": "medium"},
    4702: {"category": "configuration", "action": "scheduled_task_update",  "result": "success", "severity": "medium"},
    4904: {"category": "configuration", "action": "audit_policy_change",    "result": "success", "severity": "high"},
    4905: {"category": "configuration", "action": "audit_policy_change",    "result": "success", "severity": "high"},
}

# Logon type code → human-readable name
LOGON_TYPES: Dict[str, str] = {
    "2":  "interactive",
    "3":  "network",
    "4":  "batch",
    "5":  "service",
    "7":  "unlock",
    "8":  "network_cleartext",
    "9":  "new_credentials",
    "10": "remote_interactive",
    "11": "cached_interactive",
}
