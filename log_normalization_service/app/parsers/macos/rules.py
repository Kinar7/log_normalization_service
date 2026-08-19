from typing import Dict, Any, List, Tuple

MACOS_PATTERNS: List[Tuple[str, Dict[str, Any]]] = [
    # ── SSH ─────────────────────────────────────────────────────────────────
    (r"sshd.*Failed password",
     {"category": "authentication", "action": "login", "result": "failure", "severity": "medium"}),

    (r"sshd.*Accepted (?:password|publickey)",
     {"category": "authentication", "action": "login", "result": "success", "severity": "low"}),

    # ── sudo ──────────────────────────────────────────────────────────────────
    (r"sudo.*COMMAND=",
     {"category": "privilege", "action": "sudo", "result": "success", "severity": "medium"}),

    (r"sudo.*authentication failure",
     {"category": "privilege", "action": "sudo", "result": "failure", "severity": "high"}),

    # ── PAM ──────────────────────────────────────────────────────────────────
    (r"pam_unix.*authentication failure",
     {"category": "authentication", "action": "login", "result": "failure", "severity": "medium"}),

    (r"pam_unix.*session opened",
     {"category": "authentication", "action": "login", "result": "success", "severity": "low"}),

    (r"pam_unix.*session closed",
     {"category": "authentication", "action": "logout", "result": "success", "severity": "low"}),

    # ── Apple Security / OpenDirectory ────────────────────────────────────────
    (r"com\.apple\.\S+.*authentication.?fail|authenticationFailed|Failed to authenticate",
     {"category": "authentication", "action": "login", "result": "failure", "severity": "medium"}),

    (r"com\.apple\.\S+.*authenticated successfully|Login succeeded",
     {"category": "authentication", "action": "login", "result": "success", "severity": "low"}),

    # ── Unified Log JSON fields ───────────────────────────────────────────────
    (r'"type"\s*:\s*"LoginFailure"',
     {"category": "authentication", "action": "login", "result": "failure", "severity": "medium"}),

    (r'"type"\s*:\s*"LoginSuccess"',
     {"category": "authentication", "action": "login", "result": "success", "severity": "low"}),

    # ── Screen lock ───────────────────────────────────────────────────────────
    (r"com\.apple\.screenLock|CGSSession.*lockscreen|screensaver.*lock",
     {"category": "authentication", "action": "lock", "result": "success", "severity": "low"}),

    # ── Process ───────────────────────────────────────────────────────────────
    (r"com\.apple\.security\.audit.*exec|process.*launched|launchd.*spawn",
     {"category": "process", "action": "start", "result": "success", "severity": "low"}),
]
