import re
from typing import List, Tuple

from ..schemas.normalized_event import NormalizedEvent

VALID_CATEGORIES = frozenset({
    "authentication", "account_management", "privilege",
    "process", "service", "file", "network", "firewall",
    "malware", "endpoint_security", "system", "configuration",
    "application", "unknown",
})

# (regex, category) — applied to raw_log + message when category is still "unknown"
_FALLBACK_RULES: List[Tuple[str, str]] = [
    (r"fail(?:ed)?.*(?:login|password|auth)|invalid user|authentication.*fail", "authentication"),
    (r"(?:login|logon|session opened|accepted password|accepted publickey)",    "authentication"),
    (r"(?:logout|logoff|session closed|disconnected|signed out)",               "authentication"),
    (r"(?:useradd|userdel|usermod|account.*creat|account.*delet|new user|deleting user)", "account_management"),
    (r"(?:sudo|privilege|elevated|runas|su\b)",                                 "privilege"),
    (r"(?:process.*start|exec\b|spawn\b|new.*process)",                        "process"),
    (r"(?:service.*start|service.*stop|daemon.*start|\.service)",               "service"),
    (r"(?:file.*(?:open|read|write|delet)|unlink|chmod|chown)",                "file"),
    (r"(?:connect\b|packet\b|port\s+\d+|src=|dst=|tcp|udp)",                  "network"),
    (r"(?:drop\b|block\b|deny\b|firewall|iptables|nftables)",                  "firewall"),
    (r"(?:malware|virus|trojan|ransomware|threat detected|infected)",           "malware"),
    (r"(?:edr|antivirus|av.*detect|endpoint.*security|defender)",               "endpoint_security"),
    (r"(?:policy.*change|config.*change|setting.*modif|registry.*modif)",      "configuration"),
]


class EventClassifier:

    def classify(self, event: NormalizedEvent) -> str:
        category = event.event.category

        if category and category != "unknown" and category in VALID_CATEGORIES:
            return category

        search_text = " ".join(filter(None, [event.raw_log, event.message]))

        for pattern, cat in _FALLBACK_RULES:
            if re.search(pattern, search_text, re.IGNORECASE):
                return cat

        return "unknown"
