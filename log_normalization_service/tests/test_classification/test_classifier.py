from datetime import datetime, timezone

import pytest

from app.classifiers.event_classifier import EventClassifier
from app.schemas.normalized_event import EventInfo, NormalizedEvent, SourceInfo

classifier = EventClassifier()


def _event(category: str, raw_log: str = "", message: str = "") -> NormalizedEvent:
    now = datetime.now(timezone.utc)
    return NormalizedEvent(
        event_time=now,
        received_time=now,
        source=SourceInfo(type="test"),
        event=EventInfo(category=category),
        message=message or None,
        raw_log=raw_log,
    )


def test_already_classified_passes_through():
    assert classifier.classify(_event("authentication", "something")) == "authentication"


def test_all_valid_categories_pass_through():
    categories = [
        "authentication", "account_management", "privilege",
        "process", "service", "file", "network", "firewall",
        "malware", "endpoint_security", "system", "configuration",
        "application",
    ]
    for cat in categories:
        assert classifier.classify(_event(cat, "x")) == cat


def test_fallback_ssh_fail_to_authentication():
    event = _event("unknown", "sshd: Failed password for admin from 1.2.3.4 port 22")
    assert classifier.classify(event) == "authentication"


def test_fallback_sudo_to_privilege():
    event = _event("unknown", "sudo: admin ran COMMAND=/bin/bash")
    assert classifier.classify(event) == "privilege"


def test_fallback_useradd_to_account_management():
    event = _event("unknown", "useradd: new user 'deploy' created")
    assert classifier.classify(event) == "account_management"


def test_fallback_service_start():
    event = _event("unknown", "systemd: Started nginx.service")
    assert classifier.classify(event) == "service"


def test_truly_unknown_stays_unknown():
    event = _event("unknown", "xyz123 completely unrecognized gibberish abc")
    assert classifier.classify(event) == "unknown"
