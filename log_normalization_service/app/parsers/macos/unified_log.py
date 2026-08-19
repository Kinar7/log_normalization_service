import json
import re
from typing import Dict, Any, Optional

from ..base import BaseParser
from .rules import MACOS_PATTERNS

_SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s{1,2}(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.*)"
)


class MacOSParser(BaseParser):
    source_type = "macos"

    def can_parse(self, raw_log: str) -> bool:
        return bool(
            "com.apple" in raw_log
            or "CGSSession" in raw_log
            or (raw_log.lstrip().startswith("{") and "subsystem" in raw_log)
            or re.search(r"\blaunchd\b|\bdarwin\b", raw_log, re.IGNORECASE)
        )

    def parse(self, raw_log: str) -> Dict[str, Any]:
        stripped = raw_log.strip()
        if stripped.startswith("{"):
            return self._parse_unified_json(stripped)
        return self._parse_text(raw_log)

    # ── macOS Unified Log JSON export ────────────────────────────────────────

    def _parse_unified_json(self, raw_log: str) -> Dict[str, Any]:
        try:
            data = json.loads(raw_log)
        except json.JSONDecodeError:
            return self._parse_text(raw_log)

        message = data.get("eventMessage") or data.get("message") or ""
        subsystem = data.get("subsystem") or ""
        process_name = data.get("processImagePath") or data.get("process")
        hostname = data.get("machineID") or data.get("host")
        event_time = data.get("timestamp") or data.get("time")
        pid = data.get("processID")

        rule = _classify(message, f"{subsystem} {process_name or ''}")

        result: Dict[str, Any] = {
            "source_type": "macos",
            "product": f"macOS/{subsystem}" if subsystem else "macOS",
            "hostname": hostname,
            "event_time": event_time,
            "process_name": process_name,
            "message": message,
            **rule,
        }
        if isinstance(pid, int):
            result["process_pid"] = pid

        result.update(_extract_fields(message))
        return result

    # ── syslog-style text (macOS uses same BSD syslog format) ─────────────────

    def _parse_text(self, raw_log: str) -> Dict[str, Any]:
        m = _SYSLOG_RE.match(raw_log.strip())

        if m:
            hostname = m.group("host")
            process = m.group("process")
            pid = m.group("pid")
            message = m.group("message")
        else:
            hostname = process = pid = None
            message = raw_log

        rule = _classify(message or raw_log, process or "")

        result: Dict[str, Any] = {
            "source_type": "macos",
            "product": "macOS",
            "hostname": hostname,
            "process_name": process,
            "message": message,
            **rule,
        }
        if pid:
            result["process_pid"] = int(pid)

        result.update(_extract_fields(message or raw_log))
        return result


# ── Module-level helpers ─────────────────────────────────────────────────────

def _classify(message: str, subsystem: str) -> Dict[str, Any]:
    combined = f"{subsystem} {message}"
    for pattern, fields in MACOS_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return dict(fields)
    return {"category": "unknown"}


def _extract_fields(message: str) -> Dict[str, Any]:
    fields: Dict[str, Any] = {}

    m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)", message)
    if m:
        fields["user_name"] = m.group(1)
        fields["src_ip"] = m.group(2)
        fields["src_port"] = int(m.group(3))
        return fields

    m = re.search(r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)", message)
    if m:
        fields["user_name"] = m.group(1)
        fields["src_ip"] = m.group(2)
        fields["src_port"] = int(m.group(3))
        return fields

    m = re.search(r"(\S+)\s*:\s*TTY=\S+\s*;.*?USER=(\S+)\s*;\s*COMMAND=(.*)", message)
    if m:
        fields["user_name"] = m.group(1)
        fields["command_line"] = m.group(3).strip()

    return fields
