from datetime import datetime, timedelta, timezone

from siem.detection import BruteForceDetector
from siem.models import Event


def _failed_login(ip, ts):
    return Event(
        ts=ts,
        host="webserver",
        app="sshd",
        message=f"Failed password for invalid user admin from {ip} port 4242 ssh2",
        raw="raw line",
    )


def test_fires_after_threshold_within_window():
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    alerts = []
    for i in range(5):
        a = det.process(_failed_login("203.0.113.7", base + timedelta(seconds=i * 10)))
        if a:
            alerts.append(a)
    assert len(alerts) == 1
    assert alerts[0].entity == "203.0.113.7"
    assert alerts[0].count >= 5


def test_no_alert_below_threshold():
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    alerts = [det.process(_failed_login("203.0.113.7", base + timedelta(seconds=i * 10))) for i in range(4)]
    assert all(a is None for a in alerts)


def test_slow_trickle_does_not_fire():
    # 5 failures spread over 10 minutes, so never 5 inside one 2 minute window
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    alerts = [det.process(_failed_login("203.0.113.7", base + timedelta(minutes=2 * i + 1))) for i in range(5)]
    assert all(a is None for a in alerts)


def test_separate_ips_tracked_independently():
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    # 4 from each of two IPs, interleaved, neither reaches 5
    alerts = []
    for i in range(4):
        alerts.append(det.process(_failed_login("10.0.0.1", base + timedelta(seconds=i))))
        alerts.append(det.process(_failed_login("10.0.0.2", base + timedelta(seconds=i))))
    assert all(a is None for a in alerts)


def test_ignores_non_ssh_events():
    det = BruteForceDetector(threshold=1, window_seconds=120)
    ev = Event(ts=datetime.now(timezone.utc), host="h", app="cron", message="job ran", raw="raw")
    assert det.process(ev) is None


def test_fires_once_not_repeatedly():
    # once fired, more failures in the same window must not spam a new alert each time
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    fired = 0
    for i in range(10):
        a = det.process(_failed_login("203.0.113.7", base + timedelta(seconds=i * 5)))
        if a:
            fired += 1
    assert fired == 1


def test_fires_again_when_attacker_returns_after_going_quiet():
    # attack, go quiet for longer than the window, attack again -> two separate alerts
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    later = base + timedelta(minutes=10)
    fired = 0
    for start in (base, later):
        for i in range(5):
            if det.process(_failed_login("203.0.113.7", start + timedelta(seconds=i * 10))):
                fired += 1
    assert fired == 2


def test_long_sustained_attack_fires_once():
    # failures every 10s for 5 minutes never drop below the threshold, so it stays one attack
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    fired = 0
    for i in range(30):
        if det.process(_failed_login("203.0.113.7", base + timedelta(seconds=i * 10))):
            fired += 1
    assert fired == 1


def _ssh_event(message, ts, app="sshd"):
    return Event(ts=ts, host="webserver", app=app, message=message, raw="raw line")


def test_username_cannot_hide_the_real_attacker_ip():
    # the username is attacker-controlled; stuffing a fake " from <ip>" into it must not
    # spread the attempts across fake IPs and dodge the threshold
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    alerts = []
    for i in range(5):
        msg = f"Failed password for invalid user x from 10.9.9.{i} from 45.9.1.8 port 4242 ssh2"
        a = det.process(_ssh_event(msg, base + timedelta(seconds=i)))
        if a:
            alerts.append(a)
    assert len(alerts) == 1
    assert alerts[0].entity == "45.9.1.8"


def test_malformed_failed_password_lines_are_ignored_not_crashing():
    det = BruteForceDetector(threshold=1, window_seconds=120)
    ts = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    assert det.process(_ssh_event("Failed password for root", ts)) is None
    assert det.process(_ssh_event("Failed password for root from", ts)) is None


def test_event_without_app_is_ignored():
    det = BruteForceDetector(threshold=1, window_seconds=120)
    ts = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    msg = "Failed password for root from 10.0.0.1 port 22 ssh2"
    assert det.process(_ssh_event(msg, ts, app=None)) is None


def test_memory_does_not_grow_with_every_ip_ever_seen():
    # a public SSH server sees thousands of scanner IPs a day; only recent ones should be kept
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    for i in range(20_000):
        det.process(_failed_login(f"10.{i // 65536}.{i // 256 % 256}.{i % 256}", base + timedelta(seconds=i)))
    assert len(det.hits) <= 1024
    # and detection still works afterwards
    later = base + timedelta(seconds=20_000)
    fired = sum(1 for i in range(5) if det.process(_failed_login("45.9.1.8", later + timedelta(seconds=i))))
    assert fired == 1
