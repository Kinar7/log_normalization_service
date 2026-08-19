import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional

from ..base import BaseParser
from .rules import WINDOWS_EVENT_RULES, LOGON_TYPES


class WindowsEventLogParser(BaseParser):
    source_type = "windows"

    _NS = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}

    def can_parse(self, raw_log: str) -> bool:
        return bool(
            re.search(
                r"<EventID>|EventCode=\d+|EventID[:\s=]+\d+|"
                r"Provider Name.*Microsoft-Windows|"
                r"<Event\s+xmlns=",
                raw_log,
                re.IGNORECASE,
            )
        )

    def parse(self, raw_log: str) -> Dict[str, Any]:
        if raw_log.lstrip().startswith("<"):
            return self._parse_xml(raw_log)
        return self._parse_text(raw_log)

    # ── XML format ───────────────────────────────────────────────────────────

    def _parse_xml(self, raw_log: str) -> Dict[str, Any]:
        root = ET.fromstring(raw_log)
        ns = self._NS

        system = root.find("ev:System", ns)
        event_data_elem = root.find("ev:EventData", ns)

        event_id = self._text(system, "ev:EventID", ns)
        computer = self._text(system, "ev:Computer", ns)

        time_elem = system.find("ev:TimeCreated", ns) if system is not None else None
        event_time = time_elem.get("SystemTime") if time_elem is not None else None

        provider_elem = system.find("ev:Provider", ns) if system is not None else None
        provider = provider_elem.get("Name") if provider_elem is not None else None

        data: Dict[str, str] = {}
        if event_data_elem is not None:
            for d in event_data_elem.findall("ev:Data", ns):
                name = d.get("Name")
                if name:
                    data[name] = d.text or ""

        rule = WINDOWS_EVENT_RULES.get(int(event_id), {}) if event_id and event_id.isdigit() else {}

        result: Dict[str, Any] = {
            "source_type": "windows",
            "product": provider or "Microsoft Windows",
            "hostname": computer,
            "event_id": event_id,
            "event_time": event_time,
            "category": rule.get("category", "system"),
            "action": rule.get("action"),
            "result": rule.get("result"),
            "severity": rule.get("severity", "low"),
        }

        result["user_name"] = data.get("TargetUserName") or data.get("SubjectUserName") or None
        result["user_domain"] = data.get("TargetDomainName") or data.get("SubjectDomainName") or None

        raw_ip = data.get("IpAddress")
        result["src_ip"] = raw_ip if raw_ip and raw_ip not in ("-", "::1", "127.0.0.1") else None
        raw_port = data.get("IpPort")
        result["src_port"] = int(raw_port) if raw_port and raw_port.isdigit() and raw_port != "0" else None

        result["process_name"] = data.get("NewProcessName") or data.get("ProcessName") or None
        raw_pid = data.get("NewProcessId") or data.get("ProcessId")
        result["process_pid"] = self._parse_pid(raw_pid)
        result["command_line"] = data.get("CommandLine") or None

        logon_type = data.get("LogonType")
        if logon_type:
            result["logon_type"] = LOGON_TYPES.get(logon_type, logon_type)

        result["message"] = self._build_message(event_id, data, rule)

        return result

    # ── Plain-text / syslog-forwarded format ─────────────────────────────────

    def _parse_text(self, raw_log: str) -> Dict[str, Any]:
        event_id = self._grep(r"EventCode=(\d+)|EventID[:\s=]+(\d+)", raw_log)
        computer = self._grep(r"ComputerName=(\S+)|Computer:\s*(\S+)", raw_log)
        event_time = self._grep(r"TimeGenerated=(\S+)", raw_log)

        rule = WINDOWS_EVENT_RULES.get(int(event_id), {}) if event_id and event_id.isdigit() else {}

        return {
            "source_type": "windows",
            "product": "Microsoft Windows",
            "hostname": computer,
            "event_id": event_id,
            "event_time": event_time,
            "category": rule.get("category", "system"),
            "action": rule.get("action"),
            "result": rule.get("result"),
            "severity": rule.get("severity", "low"),
            "user_name": self._grep(r"TargetUserName=(\S+)|Account Name:\s*(\S+)", raw_log),
            "user_domain": self._grep(r"TargetDomainName=(\S+)|Account Domain:\s*(\S+)", raw_log),
            "src_ip": self._grep(r"IpAddress=(\S+)|Source Network Address:\s*(\S+)", raw_log),
            "message": rule.get("action") or f"Windows Event {event_id}",
        }

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _text(parent: Optional[ET.Element], tag: str, ns: Dict[str, str]) -> Optional[str]:
        if parent is None:
            return None
        elem = parent.find(tag, ns)
        return elem.text if elem is not None else None

    @staticmethod
    def _grep(pattern: str, text: str) -> Optional[str]:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return next((g for g in m.groups() if g is not None), None)
        return None

    @staticmethod
    def _parse_pid(raw: Optional[str]) -> Optional[int]:
        if not raw:
            return None
        if raw.startswith("0x") or raw.startswith("0X"):
            try:
                return int(raw, 16)
            except ValueError:
                return None
        if raw.isdigit():
            return int(raw)
        return None

    @staticmethod
    def _build_message(event_id: Optional[str], data: Dict[str, str], rule: Dict[str, Any]) -> str:
        user = data.get("TargetUserName") or data.get("SubjectUserName") or "unknown"
        action = rule.get("action", "event")
        result = rule.get("result", "")
        return f"Windows Event {event_id}: {action} {result} (user: {user})".strip()
