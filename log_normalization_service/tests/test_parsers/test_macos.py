import pytest
from app.parsers.macos.unified_log import MacOSParser

parser = MacOSParser()

SSHD_FAIL = "Aug 19 12:01:35 MacBook-Pro sshd[1234]: Failed password for test.user from 10.1.1.1 port 22 ssh2"
SSHD_OK = "Aug 19 12:02:00 MacBook-Pro sshd[1234]: Accepted publickey for deploy from 10.0.0.5 port 55000 ssh2"
SUDO_OK = "Aug 19 12:03:00 MacBook-Pro sudo[5678]: admin : TTY=ttys000 ; PWD=/Users/admin ; USER=root ; COMMAND=/bin/sh"
APPLE_AUTH_FAIL = "Aug 19 12:04:00 MacBook-Pro com.apple.securityd[88]: authentication failed for user test.user"
UNIFIED_JSON = (
    '{"subsystem":"com.apple.security","eventMessage":"authentication failed for user test.user",'
    '"processImagePath":"/usr/sbin/sshd","machineID":"MacBook-Pro","timestamp":"2026-08-19T12:01:35Z"}'
)
SCREEN_LOCK = "Aug 19 12:10:00 MacBook-Pro com.apple.screenLock[1]: screen locked by user"


def test_sshd_fail():
    r = parser.parse(SSHD_FAIL)
    assert r["category"] == "authentication"
    assert r["result"] == "failure"
    assert r["user_name"] == "test.user"
    assert r["src_ip"] == "10.1.1.1"


def test_sshd_ok():
    r = parser.parse(SSHD_OK)
    assert r["result"] == "success"
    assert r["user_name"] == "deploy"


def test_sudo_category():
    r = parser.parse(SUDO_OK)
    assert r["category"] == "privilege"
    assert r["action"] == "sudo"


def test_apple_auth_fail():
    r = parser.parse(APPLE_AUTH_FAIL)
    assert r["category"] == "authentication"
    assert r["result"] == "failure"


def test_unified_json_can_parse():
    assert parser.can_parse(UNIFIED_JSON)


def test_unified_json_parse():
    r = parser.parse(UNIFIED_JSON)
    assert r["category"] == "authentication"
    assert r["result"] == "failure"
    assert r["hostname"] == "MacBook-Pro"
    assert r["source_type"] == "macos"


def test_screen_lock():
    r = parser.parse(SCREEN_LOCK)
    assert r["category"] == "authentication"
    assert r["action"] == "lock"
