"""SSH brute force detection. YOU write the process() logic."""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from .models import Alert, Event, Severity


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

        if "Failed password" not in event.message or "sshd" not in event.app:
            return None
        words = event.message.split(" ")
        ip_position= words.index("from") + 1
        ip = words[ip_position]
        self.hits[ip].append(event.ts)
        while self.hits[ip] and event.ts - self.hits[ip][0] > self.window:
            self.hits[ip].popleft()
        if len(self.hits[ip]) >= self.threshold and ip not in self.fired:
            self.fired.add(ip)
            return Alert(rule="ssh-brute-force", entity= ip, ts= event.ts, count= len(self.hits[ip]), severity= Severity.WARNING)
        return None