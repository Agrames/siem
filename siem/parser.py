"""Parse raw syslog lines into normalized Events. YOU write this part."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

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
    if not raw.strip():
        return None
    
    end = raw.index(">")
    pri = int(raw[1:end])
    facility, severity = decode_pri(pri)
    rest = raw[end + 1:].strip()
   

    if rest[0].isdigit():
        # VERSION TIMESTAMP HOST APP PROCID MSGID, then structured data and the message
        parts = rest.split(" ", 6)
        timestamp = _as_utc(datetime.fromisoformat(parts[1]))
        host = parts[2]
        app = _nil(parts[3])
        procid = _nil(parts[4])
        # PROCID is any string in 5424 (e.g. "worker-3"); only a number is a pid
        pid = int(procid) if procid and procid.isdigit() else None
        message = _skip_structured_data(parts[6]) if len(parts) > 6 else ""
    else:
        ts_text = rest[:15]
        the_rest = rest[16:]
        now = _as_utc(received_at) if received_at else datetime.now(timezone.utc)
        # 3164 timestamps carry no timezone; treat them as UTC like everything else
        timestamp = datetime.strptime(f"{ts_text} {now.year}", "%b %d %H:%M:%S %Y")
        timestamp = timestamp.replace(tzinfo=timezone.utc)
        # no year either: a Dec 31 line that arrives on Jan 1 belongs to last year
        if timestamp - now > timedelta(days=1):
            timestamp = timestamp.replace(year=timestamp.year - 1)
        host, tag_and_msg = the_rest.split(" ", 1)
        tag, message = tag_and_msg.split(": ", 1)
        if "[" in tag:
            app, pid_str = tag.split("[", 1)
            pid = int(pid_str.rstrip("]:"))
        else:
            app = tag.rstrip(":")
            pid = None


    return Event(ts=timestamp, host=host, message=message, raw=raw, app=app, pid=pid,
                 facility=facility, severity=severity, received_at=received_at,
                 source_ip=source_ip)
        


def _nil(field: str) -> str | None:
    # "-" is the 5424 NILVALUE: the field is not present
    return None if field == "-" else field


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _skip_structured_data(rest: str) -> str:
    """Return MSG from "STRUCTURED-DATA MSG". Structured data is "-" or one or more
    [id key="value" ...] blocks, and quoted values may contain spaces, "]" and \-escapes,
    so it can't just be split on spaces."""
    if rest == "-" or rest.startswith("- "):
        return rest[2:]
    if not rest.startswith("["):
        return rest  # sender left structured data out entirely; treat it all as the message
    in_quotes = False
    i = 0
    while i < len(rest):
        c = rest[i]
        if in_quotes:
            if c == "\\":
                i += 1  # skip the escaped character
            elif c == '"':
                in_quotes = False
        elif c == '"':
            in_quotes = True
        elif c == "]" and not rest.startswith("[", i + 1):
            return rest[i + 2:]
        i += 1
    return ""
