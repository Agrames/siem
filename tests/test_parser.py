from datetime import datetime, timezone

from siem.models import Facility, Severity
from siem.parser import parse_line


def test_parses_rfc5424_line():
    line = "<34>1 2026-07-11T22:14:15.003Z mymachine.example.com su 1234 ID47 - 'su root' failed for lral"
    ev = parse_line(line)
    assert ev is not None
    assert ev.facility == Facility.AUTH
    assert ev.severity == Severity.CRITICAL
    assert ev.host == "mymachine.example.com"
    assert ev.app == "su"
    assert ev.pid == 1234
    assert ev.message == "'su root' failed for lral"
    assert ev.ts == datetime(2026, 7, 11, 22, 14, 15, 3000, tzinfo=timezone.utc)


def test_parses_rfc3164_line():
    line = "<86>Jul 11 22:14:16 webserver sshd[2001]: Failed password for invalid user admin from 203.0.113.7 port 4242 ssh2"
    ev = parse_line(line, received_at=datetime(2026, 7, 11, 22, 14, 20, tzinfo=timezone.utc))
    assert ev is not None
    assert ev.facility == Facility.AUTHPRIV
    assert ev.severity == Severity.INFO
    assert ev.host == "webserver"
    assert ev.app == "sshd"
    assert ev.pid == 2001
    assert "Failed password for invalid user admin" in ev.message
    # 3164 has no year, so the parser should take it from received_at
    assert ev.ts.year == 2026
    assert ev.ts.month == 7
    assert ev.ts.day == 11
    assert ev.ts.hour == 22
    assert ev.ts.minute == 14


def test_rfc3164_without_pid():
    line = "<78>Jul 11 09:00:00 host1 cron: job ran"
    ev = parse_line(line)
    assert ev is not None
    assert ev.app == "cron"
    assert ev.pid is None
    assert ev.message == "job ran"


def test_returns_none_on_blank():
    assert parse_line("") is None
    assert parse_line("   \n") is None


def test_keeps_raw_line():
    line = "<86>Jul 11 22:14:16 webserver sshd[2001]: Failed password for root from 10.0.0.1 port 22 ssh2"
    ev = parse_line(line)
    assert ev.raw == line
