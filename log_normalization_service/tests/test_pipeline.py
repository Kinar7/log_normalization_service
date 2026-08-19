import pytest
from app.pipelines.processing_pipeline import ProcessingPipeline

pipeline = ProcessingPipeline()

_4625_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-08-19T12:01:35.000Z"/>
    <Computer>PC-001</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">test.user</Data>
    <Data Name="TargetDomainName">KMF</Data>
    <Data Name="IpAddress">10.10.20.25</Data>
    <Data Name="IpPort">53122</Data>
  </EventData>
</Event>"""

_LINUX_SSHD = "Aug 19 12:01:35 server01 sshd[123]: Failed password for admin from 1.2.3.4 port 22 ssh2"
# Use macOS Unified Log JSON format so the detector can distinguish it from Linux syslog
_MACOS_SSHD = (
    '{"subsystem":"com.apple.security","eventMessage":"Failed password for user1 from 5.6.7.8 port 55000",'
    '"processImagePath":"/usr/sbin/sshd","machineID":"MacBook-Pro","timestamp":"2026-08-19T12:01:35Z"}'
)


def test_windows_end_to_end():
    r = pipeline.process(_4625_XML)
    assert r.source.type == "windows"
    assert r.event.category == "authentication"
    assert r.event.result == "failure"
    assert r.user is not None
    assert r.user.name == "test.user"
    assert r.user.domain == "KMF"
    assert r.network is not None
    assert r.network.src_ip == "10.10.20.25"


def test_linux_end_to_end():
    r = pipeline.process(_LINUX_SSHD)
    assert r.source.type == "linux"
    assert r.event.category == "authentication"
    assert r.event.result == "failure"
    assert r.user.name == "admin"


def test_macos_end_to_end():
    r = pipeline.process(_MACOS_SSHD)
    assert r.source.type == "macos"
    assert r.event.category == "authentication"
    assert r.event.result == "failure"


def test_raw_log_always_preserved():
    r = pipeline.process(_4625_XML)
    assert r.raw_log == _4625_XML


def test_unknown_format_does_not_crash():
    r = pipeline.process("THIS IS COMPLETELY UNKNOWN FORMAT !!!")
    assert r.source.type == "unknown"
    assert r.raw_log == "THIS IS COMPLETELY UNKNOWN FORMAT !!!"


def test_unknown_format_raw_log_preserved():
    raw = "xyz abc 123 !!!"
    r = pipeline.process(raw)
    assert r.raw_log == raw
