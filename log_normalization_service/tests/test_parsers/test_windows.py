import pytest
from app.parsers.windows.eventlog import WindowsEventLogParser

parser = WindowsEventLogParser()

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
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>"""

_4688_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-08-19T12:05:00.000Z"/>
    <Computer>PC-001</Computer>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="NewProcessId">0x1A4</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="SubjectUserName">admin</Data>
  </EventData>
</Event>"""

_4720_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4720</EventID>
    <TimeCreated SystemTime="2026-08-19T13:00:00.000Z"/>
    <Computer>DC-001</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">new.employee</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="SubjectUserName">admin</Data>
  </EventData>
</Event>"""


def test_can_parse_xml():
    assert parser.can_parse(_4625_XML)


def test_4625_category_and_result():
    r = parser.parse(_4625_XML)
    assert r["category"] == "authentication"
    assert r["action"] == "login"
    assert r["result"] == "failure"
    assert r["severity"] == "medium"


def test_4625_user_fields():
    r = parser.parse(_4625_XML)
    assert r["user_name"] == "test.user"
    assert r["user_domain"] == "KMF"


def test_4625_network_fields():
    r = parser.parse(_4625_XML)
    assert r["src_ip"] == "10.10.20.25"
    assert r["src_port"] == 53122


def test_4625_hostname():
    r = parser.parse(_4625_XML)
    assert r["hostname"] == "PC-001"


def test_4688_process_category():
    r = parser.parse(_4688_XML)
    assert r["category"] == "process"
    assert r["action"] == "start"


def test_4688_process_pid_hex():
    r = parser.parse(_4688_XML)
    assert r["process_pid"] == 0x1A4


def test_4688_command_line():
    r = parser.parse(_4688_XML)
    assert r["command_line"] == "cmd.exe /c whoami"


def test_4720_account_management():
    r = parser.parse(_4720_XML)
    assert r["category"] == "account_management"
    assert r["action"] == "create"


def test_unknown_event_id_defaults_to_system():
    xml = _4625_XML.replace("<EventID>4625</EventID>", "<EventID>9999</EventID>")
    r = parser.parse(xml)
    assert r["category"] == "system"


def test_text_format():
    text = "EventCode=4625 ComputerName=PC-002 TargetUserName=hacker TargetDomainName=CORP"
    r = parser.parse(text)
    assert r["category"] == "authentication"
    assert r["result"] == "failure"
    assert r["hostname"] == "PC-002"
