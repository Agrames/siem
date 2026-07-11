"""Core event model: the normalized shape every log line becomes after parsing."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum


class Severity(IntEnum):
    # syslog severity, lower number = more severe (RFC 5424 6.2.1)
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7


class Facility(IntEnum):
    # syslog facility codes (RFC 5424 6.2.1)
    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    AUTHPRIV = 10
    FTP = 11
    NTP = 12
    LOG_AUDIT = 13
    LOG_ALERT = 14
    CLOCK = 15
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


@dataclass
class Event:
    """One normalized syslog event. Output of the parser, input to storage and detection."""
    ts: datetime                            # timestamp from the log line (UTC)
    host: str                               # hostname or source that sent it
    message: str                            # the human readable message text
    raw: str                                # original line, kept untouched
    app: str | None = None                  # program name, e.g. "sshd"
    pid: int | None = None                  # process id if the line had one
    facility: Facility | None = None
    severity: Severity | None = None
    received_at: datetime | None = None     # when the collector received it
    source_ip: str | None = None            # network source of the packet
    fields: dict = field(default_factory=dict)  # any extra fields pulled out of the message


@dataclass
class Alert:
    """Something worth telling a human about. Output of a detection rule."""
    rule: str                               # which rule fired, e.g. "ssh-brute-force"
    entity: str                             # what it's about, e.g. the attacking IP
    ts: datetime                            # when it fired
    title: str = ""                         # short human summary
    severity: Severity = Severity.WARNING
    count: int = 1                          # how many events backed it up
    detail: dict = field(default_factory=dict)


def decode_pri(pri: int) -> tuple[Facility | None, Severity | None]:
    # a syslog PRI packs facility and severity into one number: facility*8 + severity
    severity = Severity(pri & 0x07)
    try:
        facility = Facility(pri >> 3)
    except ValueError:
        facility = None  # facility codes only go up to 23
    return facility, severity
