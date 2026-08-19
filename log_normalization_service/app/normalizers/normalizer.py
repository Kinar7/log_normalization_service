from datetime import datetime, timezone
from typing import Dict, Any, Optional

from dateutil import parser as dateutil_parser

from ..schemas.normalized_event import (
    NormalizedEvent, SourceInfo, EventInfo,
    UserInfo, NetworkInfo, ProcessInfo,
)


class EventNormalizer:
    """Maps a flat parsed dict to the canonical NormalizedEvent schema."""

    def normalize(self, parsed: Dict[str, Any], raw_log: str) -> NormalizedEvent:
        received_time = datetime.now(timezone.utc)
        event_time = self._parse_time(parsed.get("event_time")) or received_time

        user = UserInfo(
            name=parsed.get("user_name") or None,
            domain=parsed.get("user_domain") or None,
        )
        network = NetworkInfo(
            src_ip=parsed.get("src_ip") or None,
            src_port=parsed.get("src_port") or None,
            dst_ip=parsed.get("dst_ip") or None,
            dst_port=parsed.get("dst_port") or None,
            protocol=parsed.get("protocol") or None,
        )
        process = ProcessInfo(
            name=parsed.get("process_name") or None,
            pid=parsed.get("process_pid") or None,
            command_line=parsed.get("command_line") or None,
        )

        return NormalizedEvent(
            event_time=event_time,
            received_time=received_time,
            source=SourceInfo(
                type=parsed.get("source_type", "unknown"),
                product=parsed.get("product") or None,
                hostname=parsed.get("hostname") or None,
                ip=parsed.get("host_ip") or None,
            ),
            event=EventInfo(
                id=str(parsed["event_id"]) if parsed.get("event_id") is not None else None,
                category=parsed.get("category") or "unknown",
                action=parsed.get("action") or None,
                result=parsed.get("result") or None,
                severity=parsed.get("severity") or None,
            ),
            user=user if self._has_value(user) else None,
            network=network if self._has_value(network) else None,
            process=process if self._has_value(process) else None,
            message=parsed.get("message") or None,
            raw_log=raw_log,
            parse_error=parsed.get("parse_error") or None,
        )

    @staticmethod
    def _parse_time(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return dateutil_parser.parse(value)
        except Exception:
            return None

    @staticmethod
    def _has_value(model) -> bool:
        return any(v is not None for v in model.model_dump().values())
