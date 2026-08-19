import re
from typing import Dict, Any, Optional

from .base import BaseParser


class GenericParser(BaseParser):
    """Last-resort parser: best-effort extraction from any log format."""

    source_type = "unknown"

    def can_parse(self, raw_log: str) -> bool:
        return True

    def parse(self, raw_log: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "source_type": "unknown",
            "category": "unknown",
            "message": raw_log[:500],
        }

        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_log)
        if ips:
            result["src_ip"] = ips[0]
            if len(ips) > 1:
                result["dst_ip"] = ips[1]

        m = re.search(r"host(?:name)?[=:\s]+(\S+)", raw_log, re.IGNORECASE)
        if m:
            result["hostname"] = m.group(1)

        m = re.search(r"\buser[=:\s]+(\S+)", raw_log, re.IGNORECASE)
        if m:
            result["user_name"] = m.group(1)

        m = re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", raw_log)
        if m:
            result["event_time"] = m.group(0).replace(" ", "T")

        return result
