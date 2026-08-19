import pytest
from app.parsers.linux.syslog import LinuxParser

parser = LinuxParser()

SSHD_FAIL = "Aug 19 12:01:35 server01 sshd[12345]: Failed password for test.user from 10.10.20.25 port 53122 ssh2"
SSHD_INVALID = "Aug 19 12:01:40 server01 sshd[12346]: Failed password for invalid user hacker from 1.2.3.4 port 4444 ssh2"
SSHD_OK = "Aug 19 12:02:00 server01 sshd[12345]: Accepted password for admin from 192.168.1.10 port 22 ssh2"
SUDO_OK = "Aug 19 12:03:00 server01 sudo[5678]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash"
PAM_SESSION = "Aug 19 12:04:00 server01 su[1234]: pam_unix(su:session): session opened for user root"
PAM_FAIL = "Aug 19 12:05:00 server01 login[999]: pam_unix(login:auth): authentication failure; logname= uid=0"

AUDITD_FAIL = (
    "type=USER_AUTH msg=audit(1724063000.123:456): pid=1234 uid=1000 auid=1000 ses=10 "
    "msg='op=PAM:authentication grantors=pam_unix acct=\"admin\" "
    "exe=\"/usr/bin/sudo\" hostname=server01 addr=192.168.1.10 terminal=/dev/pts/0 res=failed'"
)
AUDITD_OK = (
    "type=USER_AUTH msg=audit(1724063060.000:457): pid=1235 uid=0 auid=1001 ses=11 "
    "msg='op=PAM:authentication grantors=pam_unix acct=\"root\" "
    "exe=\"/bin/su\" hostname=server01 addr=::1 terminal=pts/1 res=success'"
)

JOURNALD = (
    "MESSAGE=Failed password for invalid user hacker from 1.2.3.4 port 4444 ssh2\n"
    "_HOSTNAME=server02\n"
    "SYSLOG_IDENTIFIER=sshd\n"
    "_PID=9999\n"
    "__REALTIME_TIMESTAMP=1724063000000000"
)


def test_sshd_fail_can_parse():
    assert parser.can_parse(SSHD_FAIL)


def test_sshd_fail_category():
    r = parser.parse(SSHD_FAIL)
    assert r["category"] == "authentication"
    assert r["result"] == "failure"


def test_sshd_fail_user_and_network():
    r = parser.parse(SSHD_FAIL)
    assert r["user_name"] == "test.user"
    assert r["src_ip"] == "10.10.20.25"
    assert r["src_port"] == 53122


def test_sshd_invalid_user():
    r = parser.parse(SSHD_INVALID)
    assert r["user_name"] == "hacker"
    assert r["result"] == "failure"


def test_sshd_success():
    r = parser.parse(SSHD_OK)
    assert r["result"] == "success"
    assert r["user_name"] == "admin"


def test_sudo_category():
    r = parser.parse(SUDO_OK)
    assert r["category"] == "privilege"
    assert r["action"] == "sudo"
    assert r["result"] == "success"


def test_pam_session_opened():
    r = parser.parse(PAM_SESSION)
    assert r["category"] == "authentication"
    assert r["user_name"] == "root"


def test_pam_failure():
    r = parser.parse(PAM_FAIL)
    assert r["category"] == "authentication"
    assert r["result"] == "failure"


def test_auditd_failure():
    r = parser.parse(AUDITD_FAIL)
    assert r["source_type"] == "linux"
    assert r["category"] == "authentication"
    assert r["result"] == "failure"


def test_auditd_success():
    r = parser.parse(AUDITD_OK)
    assert r["result"] == "success"


def test_journald_parse():
    r = parser.parse(JOURNALD)
    assert r["source_type"] == "linux"
    assert r["category"] == "authentication"
    assert r["result"] == "failure"
    assert r["hostname"] == "server02"
