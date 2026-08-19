import re


class SourceDetector:
    """
    Identifies the log source type by matching patterns against raw log content.
    Rules are ordered from most specific to least specific.
    """

    # Each entry: (source_type, list_of_regex_patterns)
    # First match wins.
    _RULES = [
        ("windows", [
            r"<Event\s+xmlns=['\"]http://schemas\.microsoft\.com/win/2004/08/events/event",
            r"<EventID>\d+</EventID>",
        ]),
        ("windows", [
            r"EventCode=\d+",
            r"EventID[:\s=]+\d+",
            r"Provider Name.*Microsoft-Windows",
        ]),
        ("linux", [
            r"^type=(?:USER_AUTH|USER_LOGIN|USER_LOGOUT|USER_CMD|SYSCALL|EXECVE|PATH|ADD_USER|DEL_USER)\s+msg=audit\(",
        ]),
        ("linux", [
            r"^MESSAGE=",
            r"^_SYSTEMD_UNIT=",
            r"^__REALTIME_TIMESTAMP=",
        ]),
        ("linux", [
            r"\bsshd\[\d+\]",
            r"\bsudo:\s",
            r"\bpam_unix\(",
            r"\buseradd\[",
            r"\buserdel\[",
        ]),
        ("macos", [
            r'"subsystem"\s*:\s*"com\.apple',
            r'"eventMessage"',
        ]),
        ("macos", [
            r"com\.apple\.",
            r"CGSSession",
        ]),
        ("firewall", [
            r"\baction=(?:drop|accept|deny|reject|allow)\b",
            r"\b(?:DROP|ACCEPT|REJECT)\s+(?:IN|OUT)=",
            r"SRC=\d{1,3}\.\d{1,3}.*DST=\d{1,3}\.\d{1,3}",
        ]),
        # Generic syslog: "Mon DD HH:MM:SS host process[pid]:"
        ("linux", [
            r"^\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+",
        ]),
    ]

    def detect(self, raw_log: str) -> str:
        for source_type, patterns in self._RULES:
            for pattern in patterns:
                if re.search(pattern, raw_log, re.MULTILINE | re.IGNORECASE):
                    return source_type
        return "unknown"
