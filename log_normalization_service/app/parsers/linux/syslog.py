import json
import re
from datetime import datetime, date, timezone
from typing import Dict, Any, Optional

from ..base import BaseParser
from .rules import LINUX_PATTERNS, AUDITD_TYPE_RULES, _MONTH_MAP

_SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s{1,2}(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.*)$"
)
_AUDIT_RE = re.compile(
    r"^type=(?P<type>\S+)\s+msg=audit\((?P<ts>[^:)]+)(?::\d+)?\):\s*(?P<fields>.*)$"
)
_JOURNALD_KV_RE = re.compile(r"^(?P<key>[A-Z_][A-Z0-9_]*)=(?P<value>.*)$")


class LinuxParser(BaseParser):
    source_type = "linux"

    def can_parse(self, raw_log: str) -> bool:
        stripped = raw_log.strip()
        return bool(
            _SYSLOG_RE.match(stripped)
            or _AUDIT_RE.match(stripped)
            or stripped.startswith("MESSAGE=")
            or (stripped.startswith("{") and ("MESSAGE" in stripped or "_HOSTNAME" in stripped))
            or re.search(r"sshd\[|sudo:|pam_unix|useradd|userdel", stripped)
        )

    def parse(self, raw_log: str) -> Dict[str, Any]:
        stripped = raw_log.strip()

        if _AUDIT_RE.match(stripped):
            return self._parse_auditd(stripped)
        if stripped.startswith("MESSAGE=") or (stripped.startswith("{") and "_HOSTNAME" in stripped):
            return self._parse_journald(stripped)
        if _SYSLOG_RE.match(stripped):
            return self._parse_syslog(stripped)
        return self._parse_fallback(raw_log)

    # ── Syslog / auth.log ────────────────────────────────────────────────────

    def _parse_syslog(self, raw_log: str) -> Dict[str, Any]:
        m = _SYSLOG_RE.match(raw_log)
        if not m:
            return self._parse_fallback(raw_log)

        hostname = m.group("host")
        process = m.group("process")
        pid = m.group("pid")
        message = m.group("message")
        event_time = _build_syslog_time(m.group("month"), m.group("day"), m.group("time"))

        rule = _classify(f"{process} {message}")
        result: Dict[str, Any] = {
            "source_type": "linux",
            "product": f"Linux/{process}",
            "hostname": hostname,
            "event_time": event_time,
            "process_name": process,
            "message": message,
            **rule,
        }
        if pid:
            result["process_pid"] = int(pid)

        result.update(_extract_syslog_fields(message))
        return result

    # ── journald ─────────────────────────────────────────────────────────────

    def _parse_journald(self, raw_log: str) -> Dict[str, Any]:
        fields: Dict[str, str] = {}

        if raw_log.startswith("{"):
            try:
                fields = json.loads(raw_log)
            except json.JSONDecodeError:
                pass
        else:
            for line in raw_log.splitlines():
                kv = _JOURNALD_KV_RE.match(line)
                if kv:
                    fields[kv.group("key")] = kv.group("value")

        message = fields.get("MESSAGE", "")
        hostname = fields.get("_HOSTNAME") or fields.get("_MACHINE_ID")
        process = fields.get("SYSLOG_IDENTIFIER") or fields.get("_COMM") or ""

        rule = _classify(f"{process} {message}")
        result: Dict[str, Any] = {
            "source_type": "linux",
            "product": f"Linux/journald/{process}" if process else "Linux/journald",
            "hostname": hostname,
            "message": message,
            "process_name": process or None,
            **rule,
        }

        ts = fields.get("__REALTIME_TIMESTAMP")
        if ts and ts.isdigit():
            try:
                result["event_time"] = datetime.fromtimestamp(int(ts) / 1_000_000, tz=timezone.utc).isoformat()
            except (ValueError, OSError):
                pass

        pid_str = fields.get("_PID")
        if pid_str and pid_str.isdigit():
            result["process_pid"] = int(pid_str)

        result.update(_extract_syslog_fields(message))

        uid = fields.get("_UID")
        if uid and not result.get("user_name"):
            result["user_name"] = uid

        return result

    # ── auditd ───────────────────────────────────────────────────────────────

    def _parse_auditd(self, raw_log: str) -> Dict[str, Any]:
        m = _AUDIT_RE.match(raw_log)
        if not m:
            return self._parse_fallback(raw_log)

        audit_type = m.group("type")
        ts_raw = m.group("ts")
        fields_str = m.group("fields")

        kvs: Dict[str, str] = {}
        for kv in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))', fields_str):
            raw_val = kv.group(2) if kv.group(2) is not None else kv.group(3)
            kvs[kv.group(1)] = (raw_val or "").rstrip("'\"")

        event_time: Optional[str] = None
        try:
            event_time = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc).isoformat()
        except (ValueError, OSError):
            pass

        rule = AUDITD_TYPE_RULES.get(audit_type, {"category": "system", "action": audit_type.lower()})

        res = kvs.get("res", kvs.get("result", ""))
        result_val: Optional[str] = None
        if res in ("success", "1"):
            result_val = "success"
        elif res in ("failed", "0"):
            result_val = "failure"

        pid_str = kvs.get("pid")
        exe = kvs.get("exe")
        uid = kvs.get("uid") or kvs.get("auid")

        return {
            "source_type": "linux",
            "product": "Linux/auditd",
            "hostname": kvs.get("hostname"),
            "event_id": audit_type,
            "event_time": event_time,
            "category": rule.get("category", "system"),
            "action": rule.get("action"),
            "result": result_val,
            "severity": "medium" if result_val == "failure" else "low",
            "user_name": uid,
            "src_ip": kvs.get("addr"),
            "process_name": exe,
            "process_pid": int(pid_str) if pid_str and pid_str.isdigit() else None,
            "message": f"auditd {audit_type}: {fields_str[:200]}",
        }

    def _parse_fallback(self, raw_log: str) -> Dict[str, Any]:
        rule = _classify(raw_log)
        return {
            "source_type": "linux",
            "product": "Linux",
            "message": raw_log[:300],
            **rule,
        }


# ── Module-level helpers ─────────────────────────────────────────────────────

def _classify(message: str) -> Dict[str, Any]:
    for pattern, fields in LINUX_PATTERNS:
        if re.search(pattern, message, re.IGNORECASE):
            return dict(fields)
    return {"category": "unknown"}


def _extract_syslog_fields(message: str) -> Dict[str, Any]:
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

    # sudo: user : TTY=... ; USER=root ; COMMAND=/bin/bash
    m = re.search(r"(\S+)\s*:\s*TTY=\S+\s*;.*?USER=(\S+)\s*;\s*COMMAND=(.*)", message)
    if m:
        fields["user_name"] = m.group(1)
        fields["command_line"] = m.group(3).strip()
        return fields

    m = re.search(r"session (?:opened|closed) for user (\S+)", message)
    if m:
        fields["user_name"] = m.group(1)
        return fields

    m = re.search(r"new (?:user|account):\s*name=(\S+)", message)
    if m:
        fields["user_name"] = m.group(1)
        return fields

    m = re.search(r"deleting user '?(\S+?)'?", message)
    if m:
        fields["user_name"] = m.group(1)

    return fields


def _build_syslog_time(month: str, day: str, time: str) -> str:
    m = _MONTH_MAP.get(month, 1)
    year = date.today().year
    return f"{year}-{m:02d}-{int(day):02d}T{time}"
