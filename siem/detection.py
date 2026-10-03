"""SSH brute force detection. YOU write the process() logic."""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta

from .models import Alert, Event, Severity

_MIN_SWEEP_AT = 1024


class BruteForceDetector:
    """
    Fires one alert when a single source IP racks up too many failed SSH logins
    inside a time window. Classic sliding window over event timestamps.
    """

    def __init__(self, *, threshold: int = 5, window_seconds: int = 120):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        # per-IP timestamps of recent failed logins
        self.hits: dict[str, deque] = defaultdict(deque)
        # IPs we've already alerted on, so we don't fire again every event during a burst
        self.fired: set[str] = set()
        # once this many IPs are tracked, forget the idle ones (see _sweep)
        self._sweep_at = _MIN_SWEEP_AT

    def process(self, event: Event) -> Alert | None:
        
        """
        Feed one Event. Return an Alert the moment an IP first crosses the threshold
        inside the window, otherwise None.

        Steps:
        1. ignore anything that isn't an sshd "Failed password" event
        2. pull the attacker IP out of the message (the bit after "from "). Note this
           is NOT event.source_ip, which is whoever sent the syslog packet
        3. push event.ts onto that IP's deque, then drop timestamps older than the
           window (anything more than self.window before this event)
        4. if the count has reached self.threshold and the IP isn't already in
           self.fired, build and return an Alert:
               rule="ssh-brute-force", entity=<ip>, ts=event.ts,
               count=<hits in window>, severity=Severity.WARNING
           and add the IP to self.fired
        5. if a previously fired IP drops back below threshold, remove it from
           self.fired so a fresh burst later can alert again

           im just going to type my straight thoughts in
           an event returns an alert when ip crosses the threshold otehrwise it returns None
           filter out anything that isnt an sshd "failed password event"
           pull the attacker ip out from the message
           push event.ts onto that ips deque then drop timestamps older than the window
           if count = treshold and ip not in self.fired, build and return an alert and add the ip to self.fired
           if previously fired < threshold, remove from self.fired and return a new alert if it crosses the threshold again
        """

        if "Failed password" not in event.message or not event.app or "sshd" not in event.app:
            return None
        ip = _attacker_ip(event.message)
        if ip is None:
            return None
        if len(self.hits) >= self._sweep_at:
            self._sweep(event.ts)
        self.hits[ip].append(event.ts)
        while self.hits[ip] and event.ts - self.hits[ip][0] > self.window:
            self.hits[ip].popleft()
        # the previous burst has died down, so a fresh one later counts as a new attack
        if len(self.hits[ip]) < self.threshold:
            self.fired.discard(ip)
        if len(self.hits[ip]) >= self.threshold and ip not in self.fired:
            self.fired.add(ip)
            return Alert(rule="ssh-brute-force", entity= ip, ts= event.ts, count= len(self.hits[ip]), severity= Severity.WARNING)
        return None

    def _sweep(self, now: datetime) -> None:
        # drop IPs with no failures inside the window. Without this, every scanner IP ever
        # seen stays in memory forever. Sweeping only when the table has doubled keeps the
        # cost to O(1) per event on average.
        idle = [ip for ip, ts in self.hits.items() if not ts or now - ts[-1] > self.window]
        for ip in idle:
            del self.hits[ip]
            self.fired.discard(ip)
        self._sweep_at = max(_MIN_SWEEP_AT, 2 * len(self.hits))


def _attacker_ip(message: str) -> str | None:
    # sshd writes "... for <user> from <ip> port <n> ssh2". The username is chosen by the
    # attacker and can itself contain " from <ip>", so use the LAST " from ", which sshd wrote.
    _, sep, tail = message.rpartition(" from ")
    words = tail.split()
    if not sep or not words:
        return None
    return words[0]
