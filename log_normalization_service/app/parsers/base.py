from abc import ABC, abstractmethod
from typing import Dict, Any

from loguru import logger


class BaseParser(ABC):
    source_type: str = "unknown"

    @abstractmethod
    def can_parse(self, raw_log: str) -> bool:
        """Return True if this parser can handle the given raw log."""
        pass

    @abstractmethod
    def parse(self, raw_log: str) -> Dict[str, Any]:
        """
        Parse raw_log and return a flat dict of extracted fields.

        Mandatory keys if available: source_type, category, action, result,
        severity, hostname, event_id, event_time, user_name, user_domain,
        src_ip, src_port, dst_ip, dst_port, protocol, process_name,
        process_pid, command_line, message.

        Missing fields must be omitted (not set to None) so the normalizer
        can apply its own defaults.
        """
        pass

    def safe_parse(self, raw_log: str) -> Dict[str, Any]:
        """Wraps parse() and catches any exception without crashing."""
        try:
            result = self.parse(raw_log)
            result.setdefault("source_type", self.source_type)
            return result
        except Exception as exc:
            logger.error(f"[{self.__class__.__name__}] parse error: {exc}")
            return {
                "source_type": "unknown",
                "category": "unknown",
                "parse_error": str(exc),
            }
