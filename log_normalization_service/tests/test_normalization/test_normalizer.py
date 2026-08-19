from datetime import datetime, timezone

import pytest

from app.normalizers.normalizer import EventNormalizer
from app.schemas.normalized_event import NormalizedEvent

normalizer = EventNormalizer()


def test_raw_log_preserved():
    raw = "original raw log string"
    event = normalizer.normalize({"source_type": "windows", "category": "authentication"}, raw)
    assert event.raw_log == raw


def test_empty_user_is_none():
    event = normalizer.normalize({"source_type": "unknown", "category": "unknown"}, "x")
    assert event.user is None


def test_empty_network_is_none():
    event = normalizer.normalize({"source_type": "unknown", "category": "unknown"}, "x")
    assert event.network is None


def test_empty_process_is_none():
    event = normalizer.normalize({"source_type": "unknown", "category": "unknown"}, "x")
    assert event.process is None


def test_network_populated_when_present():
    parsed = {
        "source_type": "linux",
        "category": "authentication",
        "src_ip": "10.0.0.1",
        "src_port": 22,
    }
    event = normalizer.normalize(parsed, "x")
    assert event.network is not None
    assert event.network.src_ip == "10.0.0.1"
    assert event.network.src_port == 22


def test_user_populated_when_present():
    parsed = {
        "source_type": "windows",
        "category": "authentication",
        "user_name": "alice",
        "user_domain": "CORP",
    }
    event = normalizer.normalize(parsed, "x")
    assert event.user is not None
    assert event.user.name == "alice"
    assert event.user.domain == "CORP"


def test_event_id_converted_to_string():
    parsed = {"source_type": "windows", "category": "authentication", "event_id": 4625}
    event = normalizer.normalize(parsed, "x")
    assert event.event.id == "4625"


def test_received_time_is_utc():
    event = normalizer.normalize({"source_type": "unknown", "category": "unknown"}, "x")
    assert event.received_time.tzinfo is not None
