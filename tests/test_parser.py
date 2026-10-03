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


def test_rfc5424_nil_procid_and_app_become_none():
    line = "<34>1 2026-07-11T22:14:15Z host - - ID47 - something happened"
    ev = parse_line(line)
    assert ev.app is None
    assert ev.pid is None
    assert ev.message == "something happened"


def test_rfc5424_non_numeric_procid_is_not_a_pid():
    ev = parse_line("<34>1 2026-07-11T22:14:15Z host app worker-3 ID47 - hi")
    assert ev.app == "app"
    assert ev.pid is None
    assert ev.message == "hi"


def test_rfc5424_structured_data_with_spaces_is_not_part_of_the_message():
    line = ('<165>1 2026-07-11T22:14:15Z host evntslog - ID47 '
            '[exampleSDID@32473 iut="3" eventSource="App lication"][x@1 v="a]b"] An application event')
    ev = parse_line(line)
    assert ev.message == "An application event"


def test_rfc5424_without_message():
    ev = parse_line("<34>1 2026-07-11T22:14:15Z host app 1 ID47 -")
    assert ev.message == ""


def test_rfc3164_timestamp_is_utc_aware():
    # 5424 timestamps are timezone-aware; 3164 ones must be too, or comparing them raises
    ev = parse_line("<86>Jul 11 22:14:16 webserver sshd[2001]: hi",
                    received_at=datetime(2026, 7, 11, 22, 14, 20, tzinfo=timezone.utc))
    assert ev.ts == datetime(2026, 7, 11, 22, 14, 16, tzinfo=timezone.utc)


def test_rfc3164_space_padded_day():
    ev = parse_line("<78>Jul  1 09:00:00 host1 cron: job ran",
                    received_at=datetime(2026, 7, 1, 9, 0, 5, tzinfo=timezone.utc))
    assert ev.ts == datetime(2026, 7, 1, 9, 0, 0, tzinfo=timezone.utc)
    assert ev.host == "host1"


def test_rfc3164_new_year_rollover():
    # a line stamped Dec 31 that arrives just after midnight on Jan 1 belongs to last year
    ev = parse_line("<86>Dec 31 23:59:58 webserver sshd[1]: hi",
                    received_at=datetime(2027, 1, 1, 0, 0, 2, tzinfo=timezone.utc))
    assert ev.ts == datetime(2026, 12, 31, 23, 59, 58, tzinfo=timezone.utc)
