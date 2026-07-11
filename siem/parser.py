"""Parse raw syslog lines into normalized Events. YOU write this part."""
from __future__ import annotations

from datetime import datetime

from .models import Event, decode_pri


def parse_line(raw: str, *, received_at: datetime | None = None,
               source_ip: str | None = None) -> Event | None:
    """
    Turn one raw syslog line into an Event, or return None if it's blank/unparseable.

    You need to handle both syslog formats. Both start with <PRI>.

    RFC 5424 (modern, structured):
        <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID [STRUCTURED-DATA] MSG
        e.g. <34>1 2026-07-11T22:14:15.003Z host su 1234 ID47 - 'su root' failed
        - VERSION is a digit right after the PRI (that's how you spot 5424 vs 3164)
        - TIMESTAMP is ISO 8601, parse it with datetime.fromisoformat (handles the Z)
        - a field that is "-" means "not present" (nil), so store None
        - PROCID is the pid

    RFC 3164 (legacy BSD):
        <PRI>TIMESTAMP HOST TAG: MSG
        e.g. <86>Jul 11 22:14:16 host sshd[2001]: Failed password ...
        - TIMESTAMP is "Mon DD HH:MM:SS" with NO YEAR. Take the year from received_at
          (or the current year if received_at is None). The day can be space padded,
          e.g. "Jul  1" has two spaces.
        - TAG is like "sshd[2001]" or "cron". app is the bit before "[" or ":", and
          pid is the number in the brackets if there is one.

    Use decode_pri(pri) from models to split the PRI into (facility, severity).
    Always keep the original line in Event.raw, and pass received_at / source_ip
    straight through onto the Event.
    """
    raise NotImplementedError("parse_line: implement RFC 5424 and RFC 3164 parsing")
